package podegress

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang/glog"
)

type routeTable struct {
	ID     int
	Name   string
	Subnet net.IPNet
}

func FindRouteTableForIP(ip net.IP, rts []routeTable) *routeTable {
	for _, rt := range rts {
		if rt.Subnet.Contains(ip) {
			return &rt
		}
	}
	return nil
}

func EnsureRouteRule(rt *routeTable) error {
	rtID := fmt.Sprintf("%d", rt.ID)
	fwmark := fmt.Sprintf("%x/0xff", rt.ID)

	out, err := exec.Command("ip", "rule", "show", "fwmark", fwmark, "table", rtID).Output()
	if err != nil {
		return err
	}

	if string(out) != "" {
		return nil
	}

	_, err = exec.Command("ip", "rule", "add", "fwmark", fwmark, "table", rtID).Output()
	if err != nil {
		return err
	}

	return nil
}

func GetRouteTables() ([]routeTable, error) {
	tables := make([]routeTable, 0)

	fp, err := os.Open(routingTableFile)
	if err != nil {
		return tables, err
	}
	defer fp.Close()

	r := bufio.NewScanner(fp)
	for r.Scan() {
		line := strings.Trim(r.Text(), " ")
		if strings.HasPrefix(line, "#") {
			continue
		}

		cols := strings.Fields(line)
		name := cols[1]
		ID, err := strconv.Atoi(cols[0])
		if err != nil {
			glog.Error("invalid route table entry in /etc/iproute2/rt_tables")
			continue
		}

		rt := routeTable{
			ID:   ID,
			Name: name,
		}

		if rt.ID == 0 {
			continue
		}

		cidr, err := getCIDRForRouteTable(&rt)
		if err != nil || cidr == nil {
			continue
		}

		rt.Subnet = *cidr

		tables = append(tables, rt)
	}

	return tables, nil
}

func getCIDRForRouteTable(rt *routeTable) (*net.IPNet, error) {
	tableID := fmt.Sprintf("%d", rt.ID)

	out, err := exec.Command("ip", "rule", "show", "table", tableID).Output()
	if err != nil {
		return nil, err
	}

	r := bufio.NewScanner(bytes.NewBuffer(out))

	var cidr *net.IPNet = nil

	pattern := fmt.Sprintf(`\d+:.+from (.+) lookup.+`)
	re := regexp.MustCompile(pattern)

	for r.Scan() {
		line := r.Text()
		result := re.FindStringSubmatch(line)

		if len(result) > 0 {
			_, cidr, _ = net.ParseCIDR(result[1])
			if cidr != nil {
				break
			}
		}
	}

	return cidr, nil
}
