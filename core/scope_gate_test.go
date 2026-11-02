package core

import (
	"net"
	"testing"
)

func mustScope(t *testing.T, cidrs ...string) Scope {
	t.Helper()
	var s Scope
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		s.CIDRs = append(s.CIDRs, *n)
	}
	return s
}

// Feature 01 (discovery): ScopeGate allows only literal IPs that fall inside one of the scope CIDRs.
func TestScopeGateInScope(t *testing.T) {
	gate := NewScopeGate(mustScope(t, "192.168.1.0/24", "10.0.0.5/32", "2001:db8::/64"))

	cases := []struct {
		name   string
		target string
		want   bool
	}{
		{"inside v4", "192.168.1.10", true},
		{"network address", "192.168.1.0", true},
		{"last address", "192.168.1.255", true},
		{"just below network", "192.168.0.255", false},
		{"just above network", "192.168.2.0", false},
		{"single host /32", "10.0.0.5", true},
		{"neighbour of /32", "10.0.0.6", false},
		{"public address", "8.8.8.8", false},
		{"inside v6", "2001:db8::1", true},
		{"outside v6", "2001:db8:0:1::1", false},
		{"v4-mapped v6 inside", "::ffff:192.168.1.10", true},
		{"v4-mapped v6 outside", "::ffff:8.8.8.8", false},
		{"v6 with zone inside", "2001:db8::1%eth0", true},
		{"empty", "", false},
		{"hostname", "example.com", false},
		{"host with port", "192.168.1.10:22", false},
		{"cidr instead of ip", "192.168.1.0/24", false},
		{"garbage", "not an ip", false},
		{"out of range octet", "192.168.1.256", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := gate.InScope(tc.target); got != tc.want {
				t.Errorf("InScope(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

// Feature 01 (discovery): an empty scope lets nothing through.
func TestScopeGateEmptyScope(t *testing.T) {
	gate := NewScopeGate(Scope{})
	for _, target := range []string{"127.0.0.1", "192.168.1.1", "::1"} {
		if gate.InScope(target) {
			t.Errorf("InScope(%q) = true on empty scope", target)
		}
	}
}

// Feature 01 (discovery): mutating the Scope after building the gate does not widen the perimeter.
func TestScopeGateCopiesScope(t *testing.T) {
	s := mustScope(t, "192.168.1.0/24")
	gate := NewScopeGate(s)

	s.CIDRs[0].Mask = net.CIDRMask(0, 32)
	s.CIDRs[0].IP[0] = 8

	if gate.InScope("8.8.8.8") {
		t.Fatal("gate followed a mutation of the original scope")
	}
	if !gate.InScope("192.168.1.10") {
		t.Fatal("gate lost its original perimeter")
	}
}
