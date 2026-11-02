package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"

	"dowser/core"
)

var ErrNilSession = errors.New("nil scan session")

type Analyzer interface {
	Name() string
	Stage() core.Stage
	Run(ctx context.Context, in core.Input) error
}

type Store interface {
	core.Sink
	core.AssetView
}

type Engine struct {
	store     Store
	analyzers map[core.Stage][]Analyzer
	now       func() time.Time
}

func New(st Store) *Engine {
	return &Engine{
		store:     st,
		analyzers: make(map[core.Stage][]Analyzer),
		now:       time.Now,
	}
}

func (e *Engine) Register(a Analyzer) {
	e.analyzers[a.Stage()] = append(e.analyzers[a.Stage()], a)
}

func (e *Engine) Run(ctx context.Context, s *core.ScanSession) error {
	if s == nil {
		return ErrNilSession
	}
	s.StartedAt = e.now()

	in := core.Input{
		Scope: s.Scope,
		Net:   newGuardedNet(core.NewScopeGate(s.Scope)),
		View:  e.store,
		Sink:  e.store,
	}

	stages := make([]core.Stage, 0, len(e.analyzers))
	for st := range e.analyzers {
		stages = append(stages, st)
	}
	slices.Sort(stages)

	for _, st := range stages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.runStage(ctx, e.analyzers[st], in); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) runStage(ctx context.Context, analyzers []Analyzer, in core.Input) error {
	g, gctx := errgroup.WithContext(ctx)
	for _, a := range analyzers {
		g.Go(func() error {
			if err := a.Run(gctx, in); err != nil {
				return fmt.Errorf("analyzer %s: %w", a.Name(), err)
			}
			return nil
		})
	}
	return g.Wait()
}
