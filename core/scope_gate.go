package core

import (
	"net"
	"net/netip"
)

type ScopeGate struct {
	nets []net.IPNet
}

func NewScopeGate(s Scope) *ScopeGate {
	nets := make([]net.IPNet, len(s.CIDRs))
	for i, n := range s.CIDRs {
		nets[i] = net.IPNet{
			IP:   append(net.IP(nil), n.IP...),
			Mask: append(net.IPMask(nil), n.Mask...),
		}
	}
	return &ScopeGate{nets: nets}
}

func (g *ScopeGate) InScope(target string) bool {
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return false
	}
	ip := net.IP(addr.WithZone("").Unmap().AsSlice())
	for _, n := range g.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
