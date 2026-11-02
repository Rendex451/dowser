package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"dowser/analyzers/discovery"
	"dowser/cli"
	"dowser/core"
	"dowser/engine"
	"dowser/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, build)
	stop()
	os.Exit(code)
}

func build(o cli.ScanOptions) (cli.Scanner, core.AssetView) {
	st := store.NewMemory()
	e := engine.New(st)
	e.Register(discovery.New(discovery.Config{Ports: o.Ports, Detect: o.Detect}))
	return e, st
}
