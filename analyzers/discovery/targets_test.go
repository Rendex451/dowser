package discovery

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"dowser/core"
)

func scopeOf(t *testing.T, cidrs ...string) core.Scope {
	t.Helper()
	var s core.Scope
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		s.CIDRs = append(s.CIDRs, *n)
	}
	return s
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Feature 01 (discovery): target enumeration expands CIDRs into host addresses with the right edges.
func TestTargets(t *testing.T) {
	cases := []struct {
		name  string
		cidrs []string
		want  []string
	}{
		{"/30 drops network and broadcast", []string{"192.168.1.0/30"}, []string{"192.168.1.1", "192.168.1.2"}},
		{"/31 keeps both addresses", []string{"10.0.0.0/31"}, []string{"10.0.0.0", "10.0.0.1"}},
		{"/32 is a single host", []string{"10.0.0.5/32"}, []string{"10.0.0.5"}},
		{"unaligned cidr is masked", []string{"192.168.1.77/30"}, []string{"192.168.1.77", "192.168.1.78"}},
		{"ipv6 /126 keeps every address", []string{"2001:db8::/126"}, []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}},
		{"ipv6 /128", []string{"2001:db8::10/128"}, []string{"2001:db8::10"}},
		{"overlapping cidrs are deduplicated", []string{"10.0.0.0/30", "10.0.0.2/32"}, []string{"10.0.0.1", "10.0.0.2"}},
		{"several cidrs keep their order", []string{"10.0.0.9/32", "10.0.0.1/32"}, []string{"10.0.0.9", "10.0.0.1"}},
		{"top of address space", []string{"255.255.255.254/31"}, []string{"255.255.255.254", "255.255.255.255"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := targets(scopeOf(t, tc.cidrs...), DefaultMaxTargets)
			if err != nil {
				t.Fatalf("targets: %v", err)
			}
			if g := addrStrings(got); !equalStrings(g, tc.want) {
				t.Errorf("targets = %v, want %v", g, tc.want)
			}
		})
	}
}

// Feature 01 (discovery): a /24 yields 254 hosts.
func TestTargetsSlash24(t *testing.T) {
	got, err := targets(scopeOf(t, "192.168.1.0/24"), DefaultMaxTargets)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 254 || got[0].String() != "192.168.1.1" || got[253].String() != "192.168.1.254" {
		t.Fatalf("got %d hosts from %v to %v", len(got), got[0], got[len(got)-1])
	}
}

// Feature 01 (discovery): an oversized scope is rejected up front instead of being enumerated.
func TestTargetsTooLarge(t *testing.T) {
	cases := [][]string{
		{"2001:db8::/64"},
		{"0.0.0.0/0"},
		{"10.0.0.0/15"},
		{"10.0.0.0/16", "10.1.0.0/31"},
	}
	for _, cidrs := range cases {
		if _, err := targets(scopeOf(t, cidrs...), DefaultMaxTargets); !errors.Is(err, ErrScopeTooLarge) {
			t.Errorf("targets(%v) err = %v, want ErrScopeTooLarge", cidrs, err)
		}
	}
	if got, err := targets(scopeOf(t, "10.0.0.0/16"), DefaultMaxTargets); err != nil || len(got) != 65534 {
		t.Errorf("/16 at the limit: len = %d, err = %v", len(got), err)
	}
}

// Feature 01 (discovery): malformed IPNet values in the scope are reported, not silently skipped.
func TestTargetsInvalidCIDR(t *testing.T) {
	cases := []net.IPNet{
		{IP: net.IP{10, 0, 0, 1}},
		{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(64, 128)},
		{IP: nil, Mask: net.CIDRMask(24, 32)},
	}
	for _, n := range cases {
		if _, err := targets(core.Scope{CIDRs: []net.IPNet{n}}, DefaultMaxTargets); !errors.Is(err, ErrInvalidCIDR) {
			t.Errorf("targets(%v) err = %v, want ErrInvalidCIDR", n, err)
		}
	}
}

// Feature 01 (discovery): an IPv4 network stored in 16-byte form is treated as IPv4.
func TestTargetsSixteenByteIPv4(t *testing.T) {
	n := net.IPNet{IP: net.ParseIP("10.0.0.4").To16(), Mask: net.CIDRMask(31, 32)}
	got, err := targets(core.Scope{CIDRs: []net.IPNet{n}}, DefaultMaxTargets)
	if err != nil {
		t.Fatal(err)
	}
	if g := addrStrings(got); !equalStrings(g, []string{"10.0.0.4", "10.0.0.5"}) {
		t.Fatalf("targets = %v", g)
	}
}

// Feature 01 (discovery): an empty scope has no targets.
func TestTargetsEmpty(t *testing.T) {
	got, err := targets(core.Scope{}, DefaultMaxTargets)
	if err != nil || len(got) != 0 {
		t.Fatalf("targets = %v, %v", got, err)
	}
}
