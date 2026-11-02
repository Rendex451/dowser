package discovery

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"dowser/core"
)

type Config struct {
	Ports          []int
	Detect         bool
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	Workers        int
	MaxTargets     int
}

const (
	DefaultConnectTimeout = time.Second
	DefaultReadTimeout    = 2 * time.Second
	DefaultWorkers        = 256
	DefaultMaxTargets     = 65536
	readLimit             = 8 << 10
)

type Discovery struct {
	cfg      Config
	liveness []int
}

func New(cfg Config) *Discovery {
	if len(cfg.Ports) == 0 {
		cfg.Ports = defaultPorts()
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultReadTimeout
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.MaxTargets <= 0 {
		cfg.MaxTargets = DefaultMaxTargets
	}
	return &Discovery{cfg: cfg, liveness: livenessPorts}
}

func (d *Discovery) Name() string { return "discovery" }

func (d *Discovery) Stage() core.Stage { return core.StageDiscovery }

func (d *Discovery) Run(ctx context.Context, in core.Input) error {
	hosts, err := targets(in.Scope, d.cfg.MaxTargets)
	if err != nil {
		return err
	}
	alive, err := aliveHosts(ctx, in.Net, hosts, d.liveness, d.cfg.ConnectTimeout, d.cfg.Workers)
	if err != nil {
		return err
	}
	for _, a := range alive {
		if err := in.Sink.AddAsset(ctx, core.Asset{ID: a.String(), Addr: a.String()}); err != nil {
			return err
		}
	}

	eps, err := openPorts(ctx, in.Net, alive, d.cfg.Ports, d.cfg.ConnectTimeout, d.cfg.Workers)
	if err != nil {
		return err
	}
	services := make([]core.Service, len(eps))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(d.cfg.Workers)
	for i, ep := range eps {
		g.Go(func() error {
			svc, err := d.inspect(gctx, in.Net, ep)
			services[i] = svc
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	for _, svc := range services {
		if err := in.Sink.AddService(ctx, svc); err != nil {
			return err
		}
	}
	return nil
}

func (d *Discovery) inspect(ctx context.Context, n core.Net, ep endpoint) (core.Service, error) {
	hint := hintFor(ep.Port)
	order := hint.Order
	if !d.cfg.Detect {
		order = order[:1]
	}
	res, err := identify(ctx, n, ep, order, probeConfig{
		ConnectTimeout: d.cfg.ConnectTimeout,
		ReadTimeout:    d.cfg.ReadTimeout,
		Limit:          readLimit,
	})
	if err != nil {
		return core.Service{}, err
	}

	proto := res.Proto
	switch {
	case !d.cfg.Detect:
		proto = hint.Proto
	case proto == "" && bytes.HasPrefix(res.Raw, []byte("220")) &&
		(hint.Proto == core.AppProtoFTP || hint.Proto == core.AppProtoSMTP):
		proto = hint.Proto
	}
	product, version := parseProduct(res.Raw, res.Product)

	addr := ep.Addr.String()
	return core.Service{
		ID:       fmt.Sprintf("%s:%d/tcp", addr, ep.Port),
		AssetRef: addr,
		Port:     ep.Port,
		Proto:    "tcp",
		AppProto: proto,
		Banner:   bannerText(res.Raw),
		Product:  product,
		Version:  version,
	}, nil
}
