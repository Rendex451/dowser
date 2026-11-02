package engine

import (
	"context"
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

type fakeResolver struct {
	ips []netip.Addr
	err error
}

func (r fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.ips, r.err
}

type recordingDial struct {
	addrs []string
	fail  map[string]bool
}

func (d *recordingDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	d.addrs = append(d.addrs, addr)
	if d.fail[addr] {
		return nil, errors.New("connection refused")
	}
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func fakeNet(t *testing.T, r resolver, d *recordingDial, cidrs ...string) *guardedNet {
	t.Helper()
	return &guardedNet{
		gate:     core.NewScopeGate(scopeOf(t, cidrs...)),
		resolver: r,
		dial:     d.dial,
	}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

var _ core.Net = (*guardedNet)(nil)

// Feature 01 (discovery): an in-scope address gets a real working TCP connection.
func TestNetDialInScopeConnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("hi"))
		c.Close()
	}()

	n := newGuardedNet(core.NewScopeGate(scopeOf(t, "127.0.0.0/8")))
	conn, err := n.Dial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil || string(buf) != "hi" {
		t.Fatalf("read = %q, %v; want \"hi\"", buf, err)
	}
}

// Feature 01 (discovery): an out-of-scope IP is refused with ErrOutOfScope and no connection is attempted.
func TestNetDialOutOfScopeIP(t *testing.T) {
	d := &recordingDial{}
	n := fakeNet(t, fakeResolver{}, d, "192.168.1.0/24")

	_, err := n.Dial(context.Background(), "tcp", "8.8.8.8:53")
	if !errors.Is(err, core.ErrOutOfScope) {
		t.Fatalf("err = %v, want ErrOutOfScope", err)
	}
	if len(d.addrs) != 0 {
		t.Fatalf("dial attempted: %v", d.addrs)
	}
}

// Feature 01 (discovery): a hostname resolving outside the scope is refused without dialing.
func TestNetDialHostnameResolvesOutside(t *testing.T) {
	d := &recordingDial{}
	n := fakeNet(t, fakeResolver{ips: addrs("93.184.216.34")}, d, "192.168.1.0/24")

	_, err := n.Dial(context.Background(), "tcp", "example.com:80")
	if !errors.Is(err, core.ErrOutOfScope) {
		t.Fatalf("err = %v, want ErrOutOfScope", err)
	}
	if len(d.addrs) != 0 {
		t.Fatalf("dial attempted: %v", d.addrs)
	}
}

// Feature 01 (discovery): a hostname is dialed by its checked IP, never by name, so DNS cannot swap it after the check.
func TestNetDialHostnameUsesCheckedIP(t *testing.T) {
	d := &recordingDial{}
	n := fakeNet(t, fakeResolver{ips: addrs("192.168.1.10")}, d, "192.168.1.0/24")

	conn, err := n.Dial(context.Background(), "tcp", "router.lan:22")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
	if len(d.addrs) != 1 || d.addrs[0] != "192.168.1.10:22" {
		t.Fatalf("dialed %v, want [192.168.1.10:22]", d.addrs)
	}
}

// Feature 01 (discovery): when a hostname resolves to mixed addresses, only in-scope ones are ever dialed.
func TestNetDialHostnameMixedResolution(t *testing.T) {
	d := &recordingDial{fail: map[string]bool{"192.168.1.10:22": true}}
	n := fakeNet(t, fakeResolver{ips: addrs("8.8.8.8", "192.168.1.10", "1.1.1.1", "192.168.1.11")}, d, "192.168.1.0/24")

	conn, err := n.Dial(context.Background(), "tcp", "mixed.lan:22")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
	want := []string{"192.168.1.10:22", "192.168.1.11:22"}
	if len(d.addrs) != len(want) || d.addrs[0] != want[0] || d.addrs[1] != want[1] {
		t.Fatalf("dialed %v, want %v", d.addrs, want)
	}
}

// Feature 01 (discovery): if every in-scope address fails, the dial errors are returned, not ErrOutOfScope.
func TestNetDialAllAllowedFail(t *testing.T) {
	d := &recordingDial{fail: map[string]bool{"192.168.1.10:22": true}}
	n := fakeNet(t, fakeResolver{}, d, "192.168.1.0/24")

	_, err := n.Dial(context.Background(), "tcp", "192.168.1.10:22")
	if err == nil || errors.Is(err, core.ErrOutOfScope) {
		t.Fatalf("err = %v, want a dial error", err)
	}
}

// Feature 01 (discovery): resolver failures are returned and nothing is dialed.
func TestNetDialResolverError(t *testing.T) {
	d := &recordingDial{}
	resolveErr := errors.New("no such host")
	n := fakeNet(t, fakeResolver{err: resolveErr}, d, "192.168.1.0/24")

	_, err := n.Dial(context.Background(), "tcp", "missing.lan:22")
	if !errors.Is(err, resolveErr) {
		t.Fatalf("err = %v, want resolver error", err)
	}
	if len(d.addrs) != 0 {
		t.Fatalf("dial attempted: %v", d.addrs)
	}
}

// Feature 01 (discovery): a family-restricted network ignores resolved addresses of the other family.
func TestNetDialFamilyFiltering(t *testing.T) {
	d := &recordingDial{}
	n := fakeNet(t, fakeResolver{ips: addrs("2001:db8::1", "192.168.1.10")}, d, "192.168.1.0/24", "2001:db8::/64")

	conn, err := n.Dial(context.Background(), "tcp6", "dual.lan:22")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
	if len(d.addrs) != 1 || d.addrs[0] != "[2001:db8::1]:22" {
		t.Fatalf("dialed %v, want only the v6 address", d.addrs)
	}
}

// Feature 01 (discovery): UDP goes through the same perimeter check as TCP.
func TestNetDialUDPChecked(t *testing.T) {
	d := &recordingDial{}
	n := fakeNet(t, fakeResolver{}, d, "192.168.1.0/24")

	if _, err := n.Dial(context.Background(), "udp", "8.8.8.8:161"); !errors.Is(err, core.ErrOutOfScope) {
		t.Fatalf("out-of-scope udp: err = %v, want ErrOutOfScope", err)
	}
	conn, err := n.Dial(context.Background(), "udp", "192.168.1.10:161")
	if err != nil {
		t.Fatalf("in-scope udp: %v", err)
	}
	conn.Close()
}

// Feature 01 (discovery): malformed requests are rejected before any network activity.
func TestNetDialRejectsBadInput(t *testing.T) {
	cases := []struct {
		name      string
		network   string
		addr      string
		wantErrIs error
	}{
		{"unix socket", "unix", "/tmp/sock", ErrUnsupportedNetwork},
		{"ip raw", "ip4:icmp", "192.168.1.10", ErrUnsupportedNetwork},
		{"v6 literal on tcp4", "tcp4", "[2001:db8::1]:22", ErrUnsupportedNetwork},
		{"v4 literal on tcp6", "tcp6", "192.168.1.10:22", ErrUnsupportedNetwork},
		{"missing port", "tcp", "192.168.1.10", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &recordingDial{}
			n := fakeNet(t, fakeResolver{}, d, "192.168.1.0/24", "2001:db8::/64")
			_, err := n.Dial(context.Background(), tc.network, tc.addr)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Fatalf("err = %v, want %v", err, tc.wantErrIs)
			}
			if len(d.addrs) != 0 {
				t.Fatalf("dial attempted: %v", d.addrs)
			}
		})
	}
}

// Feature 01 (discovery): DNS queries go through the gate, so an out-of-scope DNS server is never contacted.
func TestNetResolverDialIsGuarded(t *testing.T) {
	d := &recordingDial{}
	n := newGuardedNet(core.NewScopeGate(scopeOf(t, "192.168.1.0/24")))
	n.dial = d.dial
	r, ok := n.resolver.(*net.Resolver)
	if !ok || !r.PreferGo || r.Dial == nil {
		t.Fatalf("resolver = %#v, want the pure Go resolver with a guarded Dial", n.resolver)
	}

	if _, err := r.Dial(context.Background(), "udp", "8.8.8.8:53"); !errors.Is(err, core.ErrOutOfScope) {
		t.Fatalf("out-of-scope DNS server: err = %v, want ErrOutOfScope", err)
	}
	if len(d.addrs) != 0 {
		t.Fatalf("dialed %v", d.addrs)
	}

	conn, err := r.Dial(context.Background(), "udp", "192.168.1.1:53")
	if err != nil {
		t.Fatalf("in-scope DNS server: %v", err)
	}
	conn.Close()
	if len(d.addrs) != 1 || d.addrs[0] != "192.168.1.1:53" {
		t.Fatalf("dialed %v, want the in-scope DNS server", d.addrs)
	}
}

// Feature 01 (discovery): resolving a hostname with the system DNS server outside the scope fails without any packet leaving.
func TestNetHostnameWithOutOfScopeDNS(t *testing.T) {
	d := &recordingDial{}
	n := newGuardedNet(core.NewScopeGate(core.Scope{}))
	n.dial = d.dial

	if _, err := n.Dial(context.Background(), "tcp", "dowser-test.invalid:80"); err == nil {
		t.Fatal("expected an error")
	}
	if len(d.addrs) != 0 {
		t.Fatalf("dialed %v, want nothing: neither the DNS server nor the target", d.addrs)
	}
}
