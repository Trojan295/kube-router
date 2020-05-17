package podegress

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/golang/glog"
	"gitlab.com/trojan295/kube-router/pkg/controllers/routing"
	"gitlab.com/trojan295/kube-router/pkg/healthcheck"
	"gitlab.com/trojan295/kube-router/pkg/options"
	"gitlab.com/trojan295/kube-router/pkg/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type PodEgressController struct {
	nodeHostName    string
	mu              sync.Mutex
	syncPeriod      time.Duration
	healthChan      chan<- *healthcheck.ControllerHeartbeat
	podLister       cache.Indexer
	readyForUpdates bool

	PodEventHandler cache.ResourceEventHandler
}

func (ctrl *PodEgressController) OnPodUpdate(pod *v1.Pod) {
	if !ctrl.readyForUpdates {
		return
	}

	glog.V(3).Infof("received update of pod %v/%v", pod.Namespace, pod.Name)

	if err := ctrl.Sync(); err != nil {
		glog.Errorf("failed to sync pod egress rules: %v", err.Error())
	}
}

func (ctrl *PodEgressController) SyncPod(pod *v1.Pod, routingTables []routeTable, it *iptables.IPTables) error {
	snatIPAddress, present := pod.Annotations[egressIPAnnotation]
	if !present {
		return nil
	}

	glog.V(3).Infof("syncing pod %s/%s", pod.Namespace, pod.Name)

	podIP := pod.Status.PodIP
	fixedPorts := strings.Split(pod.Annotations[egressFixedPortsAnnotation], ",")

	rules := [][]string{
		{"-s", podIP + "/32", "-j", "SNAT", "--to-source", snatIPAddress},
	}

	for _, fixedPort := range fixedPorts {
		var proto, port string

		data := strings.Split(fixedPort, ":")
		if len(data) == 0 {
			continue
		} else if len(data) == 1 {
			proto = "tcp"
			port = data[0]
		} else {
			proto = data[0]
			port = data[1]
		}

		snatAddress := fmt.Sprintf("%s:%s", snatIPAddress, port)
		rules = append(rules, []string{"-s", podIP + "/32", "-p", proto, "-m", proto, "--sport", port, "-j", "SNAT", "--to-source", snatAddress})
	}

	for _, rule := range rules {
		if exists, _ := it.Exists("nat", postroutingSnatChain, rule...); !exists {
			it.Insert("nat", postroutingSnatChain, 1, rule...)
			glog.V(3).Infof("added egress SNAT iptables rule: %v", rule)
		}
	}

	if rt := FindRouteTableForIP(net.ParseIP(snatIPAddress), routingTables); rt != nil {
		mark := fmt.Sprintf("%x/0xff", rt.ID)
		if err := it.AppendUnique("mangle", preroutingMarkChain, "-s", podIP+"/32", "-j", "MARK", "--set-mark", mark); err != nil {
			glog.Errorf("failed to add mark rule for pod %s/%s: %v", pod.Namespace, pod.Name, err.Error())
			return err
		}
	}

	return nil
}

func (ctrl *PodEgressController) Sync() error {
	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()

	healthcheck.SendHeartBeat(ctrl.healthChan, "PEC")
	start := time.Now()
	defer func() {
		endTime := time.Since(start)
		glog.V(1).Infof("pod egress rules sync took %v", endTime)
	}()

	glog.V(3).Infof("performing rules sync")

	routeTables, err := GetRouteTables()
	if err != nil {
		glog.Errorf("cannot get route tables: %v", err.Error())
		return err
	}

	for _, rt := range routeTables {
		if err = EnsureRouteRule(&rt); err != nil {
			glog.Errorf("failed to add fwmark rule for table %v: %v", rt.Name, err.Error())
		}
	}

	iptablesCmd, err := iptables.New()
	if err != nil {
		return err
	}

	egressRuleFilter := []string{
		"-m", "set", "!", "--match-set", routing.PodSubnetsIPSetName, "dst",
		"-m", "set", "!", "--match-set", routing.NodeAddrsIPSetName, "dst",
		"-m", "set", "!", "--match-set", "KUBE-CLUSTER-IP", "dst,dst",
	}

	preroutingRule := append(egressRuleFilter, "-j", preroutingMarkChain)
	if err = iptablesEnsureChain("mangle", preroutingMarkChain, iptablesCmd); err != nil {
		return err
	}
	if err = iptablesCmd.AppendUnique("mangle", "PREROUTING", preroutingRule...); err != nil {
		return err
	}

	postroutingRule := append(egressRuleFilter, "-j", postroutingSnatChain)
	if err = iptablesEnsureChain("nat", postroutingSnatChain, iptablesCmd); err != nil {
		return err
	}
	if err = iptablesEnsureRuleAtPosition("nat", "POSTROUTING", 1, iptablesCmd, postroutingRule...); err != nil {
		return err
	}

	podObjs := ctrl.podLister.List()

	iptablesCmd.ClearChain("mangle", preroutingMarkChain)
	iptablesCmd.ClearChain("nat", postroutingSnatChain)

	for _, podObj := range podObjs {
		pod := podObj.(*v1.Pod)
		if err = ctrl.SyncPod(pod, routeTables, iptablesCmd); err != nil {
			glog.Errorf("failed to sync pod %s/%s: %v", pod.Namespace, pod.Name, err.Error())
		}
	}

	return nil
}

func (ctrl *PodEgressController) newPodEventHandler() cache.ResourceEventHandler {
	triggerUpdate := func(obj interface{}) {
		pod, ok := obj.(*v1.Pod)
		if !ok {
			glog.Error("could not convert pod update object to *v1.Pod")
			return
		}

		ctrl.OnPodUpdate(pod)
	}

	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			triggerUpdate(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			triggerUpdate(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			triggerUpdate(obj)
		},
	}
}

func (ctrl *PodEgressController) Run(healthChan chan<- *healthcheck.ControllerHeartbeat, stopCh <-chan struct{}, wg *sync.WaitGroup) {
	ctrl.healthChan = healthChan

	t := time.NewTicker(ctrl.syncPeriod)
	defer t.Stop()
	defer wg.Done()

	glog.Info("Starting pod egress controller")

	// loop forever till notified to stop on stopCh
	for {
		select {
		case <-stopCh:
			glog.Info("Shutting down pod egress controller")
			return
		default:
		}

		glog.V(1).Info("Performing periodic sync of pod egress rules")
		err := ctrl.Sync()
		if err != nil {
			glog.Errorf("Error during periodic sync of pod egress rules. Error: " + err.Error())
			glog.Errorf("Skipping sending heartbeat from pod egress controller as periodic sync failed.")
		} else {
			healthcheck.SendHeartBeat(healthChan, "PEC")
		}
		ctrl.readyForUpdates = true
		select {
		case <-stopCh:
			glog.Infof("Shutting down pod egress controller")
			return
		case <-t.C:
		}
	}
}

func NewPodEgressController(clientset kubernetes.Interface, config *options.KubeRouterConfig, podInformer cache.SharedIndexInformer) (*PodEgressController, error) {
	ctrl := PodEgressController{}

	ctrl.syncPeriod = time.Minute
	ctrl.podLister = podInformer.GetIndexer()

	node, err := utils.GetNodeObject(clientset, config.HostnameOverride)
	if err != nil {
		return nil, err
	}

	ctrl.nodeHostName = node.Name

	ctrl.PodEventHandler = ctrl.newPodEventHandler()

	return &ctrl, nil
}
