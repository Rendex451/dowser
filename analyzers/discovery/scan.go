package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"dowser/core"
)

type endpoint struct {
	Addr netip.Addr
	Port int
}

func (e endpoint) String() string {
	return net.JoinHostPort(e.Addr.String(), strconv.Itoa(e.Port))
}

type dialOutcome int

const (
	dialOpen dialOutcome = iota
	dialRefused
	dialNoAnswer
)

func probeTCP(ctx context.Context, n core.Net, ep endpoint, timeout time.Duration) (dialOutcome, error) {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := n.Dial(dctx, "tcp", ep.String())
	if err == nil {
		conn.Close()
		return dialOpen, nil
	}
	if errors.Is(err, core.ErrOutOfScope) {
		return 0, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return dialRefused, nil
	}
	return dialNoAnswer, nil
}

func aliveHosts(ctx context.Context, n core.Net, hosts []netip.Addr, ports []int, timeout time.Duration, workers int) ([]netip.Addr, error) {
	alive := make([]bool, len(hosts))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	for i, h := range hosts {
		g.Go(func() error {
			for _, p := range ports {
				out, err := probeTCP(gctx, n, endpoint{h, p}, timeout)
				if err != nil {
					return err
				}
				if out != dialNoAnswer {
					alive[i] = true
					return nil
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for i, h := range hosts {
		if alive[i] {
			out = append(out, h)
		}
	}
	return out, nil
}

func openPorts(ctx context.Context, n core.Net, hosts []netip.Addr, ports []int, timeout time.Duration, workers int) ([]endpoint, error) {
	open := make([]bool, len(hosts)*len(ports))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	for hi, h := range hosts {
		for pi, p := range ports {
			g.Go(func() error {
				out, err := probeTCP(gctx, n, endpoint{h, p}, timeout)
				if err != nil {
					return err
				}
				open[hi*len(ports)+pi] = out == dialOpen
				return nil
			})
		}
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var out []endpoint
	for hi, h := range hosts {
		for pi, p := range ports {
			if open[hi*len(ports)+pi] {
				out = append(out, endpoint{h, p})
			}
		}
	}
	return out, nil
}
