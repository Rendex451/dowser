package store

import (
	"context"
	"slices"
	"sync"

	"dowser/core"
)

type Memory struct {
	mu       sync.RWMutex
	assets   ordered[core.Asset]
	services ordered[core.Service]
	findings []core.Finding
}

func NewMemory() *Memory {
	return &Memory{
		assets:   newOrdered[core.Asset](),
		services: newOrdered[core.Service](),
	}
}

func (m *Memory) AddAsset(ctx context.Context, a core.Asset) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets.put(a.ID, a)
	return nil
}

func (m *Memory) AddService(ctx context.Context, s core.Service) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services.put(s.ID, s)
	return nil
}

func (m *Memory) AddFinding(ctx context.Context, f core.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f.References = slices.Clone(f.References)
	f.Evidence.Raw = slices.Clone(f.Evidence.Raw)
	m.findings = append(m.findings, f)
	return nil
}

func (m *Memory) Assets(ctx context.Context) ([]core.Asset, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.assets.list(), nil
}

func (m *Memory) Services(ctx context.Context) ([]core.Service, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.services.list(), nil
}

func (m *Memory) Findings(ctx context.Context) ([]core.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]core.Finding, len(m.findings))
	for i, f := range m.findings {
		f.References = slices.Clone(f.References)
		f.Evidence.Raw = slices.Clone(f.Evidence.Raw)
		out[i] = f
	}
	return out, nil
}

type ordered[T any] struct {
	index map[string]int
	items []T
}

func newOrdered[T any]() ordered[T] {
	return ordered[T]{index: make(map[string]int)}
}

func (o *ordered[T]) put(id string, v T) {
	if i, ok := o.index[id]; ok {
		o.items[i] = v
		return
	}
	o.index[id] = len(o.items)
	o.items = append(o.items, v)
}

func (o *ordered[T]) list() []T {
	return slices.Clone(o.items)
}
