package discovery

import (
	"slices"

	"dowser/core"
)

type step int

const (
	stepWait step = iota
	stepGET
	stepTLS
)

var (
	orderWaitFirst = []step{stepWait, stepGET, stepTLS}
	orderGETFirst  = []step{stepGET, stepWait, stepTLS}
	orderTLSFirst  = []step{stepTLS, stepWait, stepGET}
)

type portHint struct {
	Proto core.AppProto
	Order []step
}

var portHints = map[int]portHint{
	21:   {core.AppProtoFTP, orderWaitFirst},
	22:   {core.AppProtoSSH, orderWaitFirst},
	23:   {core.AppProtoTelnet, orderWaitFirst},
	25:   {core.AppProtoSMTP, orderWaitFirst},
	80:   {core.AppProtoHTTP, orderGETFirst},
	110:  {core.AppProtoPOP3, orderWaitFirst},
	143:  {core.AppProtoIMAP, orderWaitFirst},
	443:  {core.AppProtoHTTPS, orderTLSFirst},
	587:  {core.AppProtoSMTP, orderWaitFirst},
	873:  {core.AppProtoRsync, orderWaitFirst},
	993:  {core.AppProtoTLS, orderTLSFirst},
	995:  {core.AppProtoTLS, orderTLSFirst},
	2375: {core.AppProtoHTTP, orderGETFirst},
	2376: {core.AppProtoHTTPS, orderTLSFirst},
	3306: {core.AppProtoMySQL, orderWaitFirst},
	5900: {core.AppProtoVNC, orderWaitFirst},
	6379: {core.AppProtoRedis, orderGETFirst},
	6443: {core.AppProtoHTTPS, orderTLSFirst},
	6667: {core.AppProtoIRC, orderGETFirst},
	8000: {core.AppProtoHTTP, orderGETFirst},
	8008: {core.AppProtoHTTP, orderGETFirst},
	8080: {core.AppProtoHTTP, orderGETFirst},
	8443: {core.AppProtoHTTPS, orderTLSFirst},
	8888: {core.AppProtoHTTP, orderGETFirst},
	9200: {core.AppProtoHTTP, orderGETFirst},
}

func hintFor(port int) portHint {
	if h, ok := portHints[port]; ok {
		return h
	}
	return portHint{Order: orderWaitFirst}
}

var nmapTop100 = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
	139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
	646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
	2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
	6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
}

var livenessPorts = []int{22, 80, 443, 445, 3389}

func defaultPorts() []int {
	ports := slices.Clone(nmapTop100)
	for p := range portHints {
		ports = append(ports, p)
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}
