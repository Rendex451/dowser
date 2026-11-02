package discovery

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"dowser/core"
)

var (
	ErrScopeTooLarge = errors.New("scope is too large")
	ErrInvalidCIDR   = errors.New("invalid CIDR in scope")
)

func targets(s core.Scope, limit int) ([]netip.Addr, error) {
	prefixes := make([]netip.Prefix, 0, len(s.CIDRs))
	total := 0
	for _, n := range s.CIDRs {
		p, err := toPrefix(n)
		if err != nil {
			return nil, err
		}
		size, ok := hostCount(p, limit-total)
		if !ok {
			return nil, fmt.Errorf("%w: more than %d addresses", ErrScopeTooLarge, limit)
		}
		total += size
		prefixes = append(prefixes, p)
	}

	seen := make(map[netip.Addr]bool, total)
	out := make([]netip.Addr, 0, total)
	for _, p := range prefixes {
		first, last := p.Addr(), lastAddr(p)
		skipEdges := p.Addr().Is4() && p.Bits() <= 30
		for a := first; ; a = a.Next() {
			edge := a == first || a == last
			if !(skipEdges && edge) && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
			if a == last {
				break
			}
		}
	}
	return out, nil
}

func toPrefix(n net.IPNet) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(n.IP)
	ones, bits := n.Mask.Size()
	if !ok || bits == 0 {
		return netip.Prefix{}, fmt.Errorf("%w: %v", ErrInvalidCIDR, n.String())
	}
	if bits == 32 {
		addr = addr.Unmap()
	}
	if addr.BitLen() != bits {
		return netip.Prefix{}, fmt.Errorf("%w: %v", ErrInvalidCIDR, n.String())
	}
	return netip.PrefixFrom(addr, ones).Masked(), nil
}

func hostCount(p netip.Prefix, budget int) (int, bool) {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits >= 62 {
		return 0, false
	}
	size := 1 << hostBits
	return size, size <= budget
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
