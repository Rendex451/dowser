package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"dowser/core"
)

var ErrUnsupportedNetwork = errors.New("unsupported network")

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type guardedNet struct {
	gate     *core.ScopeGate
	resolver resolver
	dial     dialFunc
}

func newGuardedNet(gate *core.ScopeGate) *guardedNet {
	var d net.Dialer
	g := &guardedNet{gate: gate, dial: d.DialContext}
	g.resolver = &net.Resolver{PreferGo: true, Dial: g.Dial}
	return g
}

func (g *guardedNet) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	family, err := ipFamily(network)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	candidates, err := g.candidates(ctx, family, host)
	if err != nil {
		return nil, err
	}

	var allowed []netip.Addr
	for _, ip := range candidates {
		if g.gate.InScope(ip.String()) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: %s", core.ErrOutOfScope, host)
	}

	var errs []error
	for _, ip := range allowed {
		conn, err := g.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (g *guardedNet) candidates(ctx context.Context, family, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !matchesFamily(ip, family) {
			return nil, fmt.Errorf("%w: %s is not %s", ErrUnsupportedNetwork, host, family)
		}
		return []netip.Addr{ip}, nil
	}
	ips, err := g.resolver.LookupNetIP(ctx, family, host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ip := range ips {
		if matchesFamily(ip, family) {
			out = append(out, ip)
		}
	}
	return out, nil
}

func ipFamily(network string) (string, error) {
	switch network {
	case "tcp", "udp":
		return "ip", nil
	case "tcp4", "udp4":
		return "ip4", nil
	case "tcp6", "udp6":
		return "ip6", nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedNetwork, network)
}

func matchesFamily(ip netip.Addr, family string) bool {
	switch family {
	case "ip4":
		return ip.Unmap().Is4()
	case "ip6":
		return ip.Is6() && !ip.Is4In6()
	}
	return true
}
