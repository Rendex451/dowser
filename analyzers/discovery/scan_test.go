package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"dowser/core"
)

type behaviour int

const (
	silent behaviour = iota
	accept
	refuse
	outOfScope
)

type fakeNet struct {
	mu      sync.Mutex
	rules   map[string]behaviour
	dialled []string
}

func newFakeNet(rules map[string]behaviour) *fakeNet {
	return &fakeNet{rules: rules}
}

func (f *fakeNet) Dial(ctx context.Context, _, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialled = append(f.dialled, addr)
	b := f.rules[addr]
	f.mu.Unlock()

	switch b {
	case accept:
		c, s := net.Pipe()
		s.Close()
		return c, nil
	case refuse:
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &net.OpError{Err: syscall.ECONNREFUSED}}
	case outOfScope:
		return nil, fmt.Errorf("%w: %s", core.ErrOutOfScope, addr)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (f *fakeNet) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dialled)
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

const shortTimeout = 50 * time.Millisecond

// Feature 01 (discovery): a host is alive if any liveness port accepts or actively refuses; silence means dead.
func TestAliveHosts(t *testing.T) {
	n := newFakeNet(map[string]behaviour{
		"10.0.0.1:22":  accept,
		"10.0.0.2:22":  refuse,
		"10.0.0.4:22":  silent,
		"10.0.0.4:443": accept,
	})
	got, err := aliveHosts(context.Background(), n, addrs("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"), []int{22, 443}, shortTimeout, 4)
	if err != nil {
		t.Fatal(err)
	}
	if g := addrStrings(got); !equalStrings(g, []string{"10.0.0.1", "10.0.0.2", "10.0.0.4"}) {
		t.Fatalf("alive = %v, want 10.0.0.1, 10.0.0.2, 10.0.0.4", g)
	}
}

// Feature 01 (discovery): liveness stops probing a host after its first answer.
func TestAliveHostsStopsAtFirstAnswer(t *testing.T) {
	n := newFakeNet(map[string]behaviour{"10.0.0.1:22": accept})
	if _, err := aliveHosts(context.Background(), n, addrs("10.0.0.1"), []int{22, 80, 443}, shortTimeout, 1); err != nil {
		t.Fatal(err)
	}
	if c := n.count(); c != 1 {
		t.Fatalf("dialled %d times, want 1", c)
	}
}

// Feature 01 (discovery): a refusal by the perimeter guard is a bug, not a dead host, and aborts the scan.
func TestAliveHostsOutOfScope(t *testing.T) {
	n := newFakeNet(map[string]behaviour{"10.0.0.1:22": outOfScope})
	_, err := aliveHosts(context.Background(), n, addrs("10.0.0.1"), []int{22}, shortTimeout, 1)
	if !errors.Is(err, core.ErrOutOfScope) {
		t.Fatalf("err = %v, want ErrOutOfScope", err)
	}
}

// Feature 01 (discovery): cancelling the context aborts liveness with the context error.
func TestAliveHostsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := newFakeNet(nil)
	if _, err := aliveHosts(ctx, n, addrs("10.0.0.1", "10.0.0.2"), []int{22}, time.Second, 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// Feature 01 (discovery): liveness checks hosts concurrently, so dead hosts do not add up.
func TestAliveHostsConcurrent(t *testing.T) {
	n := newFakeNet(nil)
	hosts := addrs("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8")
	start := time.Now()
	if _, err := aliveHosts(context.Background(), n, hosts, []int{22}, 100*time.Millisecond, len(hosts)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %v, hosts were not probed concurrently", d)
	}
}

// Feature 01 (discovery): only accepted connections count as open ports; results keep host then port order.
func TestOpenPorts(t *testing.T) {
	n := newFakeNet(map[string]behaviour{
		"10.0.0.1:80":  accept,
		"10.0.0.1:22":  accept,
		"10.0.0.1:443": refuse,
		"10.0.0.2:443": accept,
	})
	got, err := openPorts(context.Background(), n, addrs("10.0.0.1", "10.0.0.2"), []int{22, 80, 443}, shortTimeout, 8)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1:22", "10.0.0.1:80", "10.0.0.2:443"}
	var g []string
	for _, ep := range got {
		g = append(g, ep.String())
	}
	if !equalStrings(g, want) {
		t.Fatalf("open = %v, want %v", g, want)
	}
}

// Feature 01 (discovery): the port scan works against a real local listener.
func TestOpenPortsRealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()

	got, err := openPorts(context.Background(), plainNet{}, addrs("127.0.0.1"), []int{closedPort, openPort}, time.Second, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Port != openPort {
		t.Fatalf("open = %v, want only %d", got, openPort)
	}
}

// Feature 01 (discovery): the port scan aborts on cancellation and on perimeter refusals.
func TestOpenPortsErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openPorts(ctx, newFakeNet(nil), addrs("10.0.0.1"), []int{22, 80}, time.Second, 2); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err = %v, want context.Canceled", err)
	}
	n := newFakeNet(map[string]behaviour{"10.0.0.1:80": outOfScope})
	if _, err := openPorts(context.Background(), n, addrs("10.0.0.1"), []int{80}, shortTimeout, 1); !errors.Is(err, core.ErrOutOfScope) {
		t.Errorf("out of scope: err = %v, want ErrOutOfScope", err)
	}
}

type plainNet struct{}

func (plainNet) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
