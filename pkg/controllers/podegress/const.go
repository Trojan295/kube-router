package podegress

const (
	preroutingMarkChain  = "CHINCHILLA-PREROUTING-MARK"
	postroutingSnatChain = "CHINCHILLA-POSTROUTING-SNAT"

	egressIPAnnotation         = "egressSNAT.IPAddress"
	egressFixedPortsAnnotation = "egressSNAT.FixedPorts"

	routingTableFile = "/opt/rt_tables"
)
