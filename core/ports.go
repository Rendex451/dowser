package core

import (
	"context"
	"errors"
	"net"
)

var ErrOutOfScope = errors.New("target is out of scope")

type Stage int

const (
	StageDiscovery Stage = iota
	StageCorrelation
)

type Input struct {
	Scope Scope
	Net   Net
	View  AssetView
	Sink  Sink
}

type Net interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
}

type Sink interface {
	AddAsset(ctx context.Context, a Asset) error
	AddService(ctx context.Context, s Service) error
	AddFinding(ctx context.Context, f Finding) error
}

type AssetView interface {
	Assets(ctx context.Context) ([]Asset, error)
	Services(ctx context.Context) ([]Service, error)
}
