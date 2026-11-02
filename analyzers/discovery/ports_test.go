package discovery

import (
	"fmt"
	"slices"
	"testing"

	"dowser/core"
)

// Feature 01 (discovery): well-known ports map to their protocol and the cheapest first step.
func TestHintFor(t *testing.T) {
	cases := []struct {
		port  int
		proto core.AppProto
		first step
	}{
		{22, core.AppProtoSSH, stepWait},
		{21, core.AppProtoFTP, stepWait},
		{23, core.AppProtoTelnet, stepWait},
		{80, core.AppProtoHTTP, stepGET},
		{8080, core.AppProtoHTTP, stepGET},
		{9200, core.AppProtoHTTP, stepGET},
		{2375, core.AppProtoHTTP, stepGET},
		{6379, core.AppProtoRedis, stepGET},
		{443, core.AppProtoHTTPS, stepTLS},
		{6443, core.AppProtoHTTPS, stepTLS},
		{8443, core.AppProtoHTTPS, stepTLS},
		{31337, "", stepWait},
	}
	for _, tc := range cases {
		h := hintFor(tc.port)
		if h.Proto != tc.proto || h.Order[0] != tc.first {
			t.Errorf("hintFor(%d) = %q first %v, want %q first %v", tc.port, h.Proto, h.Order[0], tc.proto, tc.first)
		}
	}
}

// Feature 01 (discovery): every probe order tries each step exactly once.
func TestHintOrdersAreComplete(t *testing.T) {
	check := func(name string, order []step) {
		sorted := slices.Sorted(slices.Values(order))
		if !slices.Equal(sorted, []step{stepWait, stepGET, stepTLS}) {
			t.Errorf("%s = %v, want each step once", name, order)
		}
	}
	check("default", hintFor(31337).Order)
	for port, h := range portHints {
		check(fmt.Sprintf("port %d", port), h.Order)
	}
}

// Feature 01 (discovery): default ports are nmap's top 100 plus every port the hint table knows, sorted and unique.
func TestDefaultPorts(t *testing.T) {
	if len(nmapTop100) != 100 {
		t.Fatalf("nmapTop100 has %d ports", len(nmapTop100))
	}
	ports := defaultPorts()
	if !slices.IsSorted(ports) || len(slices.Compact(slices.Clone(ports))) != len(ports) {
		t.Fatal("default ports are not sorted and unique")
	}
	for _, p := range nmapTop100 {
		if !slices.Contains(ports, p) {
			t.Errorf("default ports miss top-100 port %d", p)
		}
	}
	for p := range portHints {
		if !slices.Contains(ports, p) {
			t.Errorf("default ports miss hinted port %d", p)
		}
	}
}
