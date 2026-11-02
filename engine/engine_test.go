package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dowser/core"
	"dowser/store"
)

type fakeAnalyzer struct {
	name  string
	stage core.Stage
	run   func(ctx context.Context, in core.Input) error
}

func (f *fakeAnalyzer) Name() string      { return f.name }
func (f *fakeAnalyzer) Stage() core.Stage { return f.stage }
func (f *fakeAnalyzer) Run(ctx context.Context, in core.Input) error {
	if f.run == nil {
		return nil
	}
	return f.run(ctx, in)
}

var _ Analyzer = (*fakeAnalyzer)(nil)

func newTestEngine(t *testing.T, cidrs ...string) (*Engine, *store.Memory, *core.ScanSession) {
	t.Helper()
	scope := scopeOf(t, cidrs...)
	st := store.NewMemory()
	return New(st), st, &core.ScanSession{ID: "s1", Scope: scope}
}

// Feature 01 (discovery): correlation sees what discovery wrote, regardless of registration order.
func TestEngineStagesRunInOrder(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")

	var seen []core.Asset
	e.Register(&fakeAnalyzer{name: "corr", stage: core.StageCorrelation, run: func(ctx context.Context, in core.Input) error {
		var err error
		seen, err = in.View.Assets(ctx)
		return err
	}})
	e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(ctx context.Context, in core.Input) error {
		return in.Sink.AddAsset(ctx, core.Asset{ID: "192.168.1.10", Addr: "192.168.1.10"})
	}})

	if err := e.Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(seen) != 1 || seen[0].ID != "192.168.1.10" {
		t.Fatalf("correlation saw %v, want the discovered asset", seen)
	}
}

// Feature 01 (discovery): the next stage starts only after every analyzer of the previous stage has finished.
func TestEngineStageBarrier(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")

	var discDone atomic.Int32
	for _, d := range []time.Duration{0, 30 * time.Millisecond, 60 * time.Millisecond} {
		e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(context.Context, core.Input) error {
			time.Sleep(d)
			discDone.Add(1)
			return nil
		}})
	}
	var doneAtCorr int32
	e.Register(&fakeAnalyzer{name: "corr", stage: core.StageCorrelation, run: func(context.Context, core.Input) error {
		doneAtCorr = discDone.Load()
		return nil
	}})

	if err := e.Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if doneAtCorr != 3 {
		t.Fatalf("correlation started after %d of 3 discovery analyzers", doneAtCorr)
	}
}

// Feature 01 (discovery): analyzers within one stage run concurrently.
func TestEngineStageIsConcurrent(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")

	const n = 3
	var started sync.WaitGroup
	started.Add(n)
	for range n {
		e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(ctx context.Context, _ core.Input) error {
			started.Done()
			waited := make(chan struct{})
			go func() { started.Wait(); close(waited) }()
			select {
			case <-waited:
				return nil
			case <-time.After(time.Second):
				return errors.New("siblings did not start concurrently")
			}
		}})
	}

	if err := e.Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// Feature 01 (discovery): an analyzer error is returned wrapped with its name and stops later stages.
func TestEngineErrorStopsLaterStages(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")

	boom := errors.New("boom")
	e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(context.Context, core.Input) error {
		return boom
	}})
	var corrRan atomic.Bool
	e.Register(&fakeAnalyzer{name: "corr", stage: core.StageCorrelation, run: func(context.Context, core.Input) error {
		corrRan.Store(true)
		return nil
	}})

	err := e.Run(context.Background(), s)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if want := "analyzer disc: boom"; err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	if corrRan.Load() {
		t.Fatal("correlation ran after a discovery failure")
	}
}

type failingStore struct {
	*store.Memory
	err error
}

func (f failingStore) AddAsset(context.Context, core.Asset) error { return f.err }

// Feature 01 (discovery): a store write failure returned by an analyzer aborts the scan before later stages.
func TestEngineStoreWriteFailureStopsScan(t *testing.T) {
	scope := scopeOf(t, "192.168.1.0/24")
	diskFull := errors.New("disk full")
	e := New(failingStore{Memory: store.NewMemory(), err: diskFull})

	e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(ctx context.Context, in core.Input) error {
		return in.Sink.AddAsset(ctx, core.Asset{ID: "192.168.1.10"})
	}})
	var corrRan atomic.Bool
	e.Register(&fakeAnalyzer{name: "corr", stage: core.StageCorrelation, run: func(context.Context, core.Input) error {
		corrRan.Store(true)
		return nil
	}})

	if err := e.Run(context.Background(), &core.ScanSession{Scope: scope}); !errors.Is(err, diskFull) {
		t.Fatalf("err = %v, want the store error", err)
	}
	if corrRan.Load() {
		t.Fatal("correlation ran on incomplete data")
	}
}

// Feature 01 (discovery): an analyzer error cancels the context of its siblings in the same stage.
func TestEngineErrorCancelsSiblings(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")

	e.Register(&fakeAnalyzer{name: "failing", stage: core.StageDiscovery, run: func(context.Context, core.Input) error {
		return errors.New("boom")
	}})
	var siblingCanceled atomic.Bool
	e.Register(&fakeAnalyzer{name: "slow", stage: core.StageDiscovery, run: func(ctx context.Context, _ core.Input) error {
		select {
		case <-ctx.Done():
			siblingCanceled.Store(true)
			return ctx.Err()
		case <-time.After(time.Second):
			return nil
		}
	}})

	if err := e.Run(context.Background(), s); err == nil {
		t.Fatal("expected error")
	}
	if !siblingCanceled.Load() {
		t.Fatal("sibling was not canceled")
	}
}

// Feature 01 (discovery): an already canceled context runs nothing and returns the context error.
func TestEngineCanceledBeforeRun(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")

	var ran atomic.Bool
	e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(context.Context, core.Input) error {
		ran.Store(true)
		return nil
	}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Run(ctx, s); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if ran.Load() {
		t.Fatal("analyzer ran on a canceled context")
	}
}

// Feature 01 (discovery): canceling during a stage reaches the analyzers and prevents later stages.
func TestEngineCanceledDuringStage(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")

	ctx, cancel := context.WithCancel(context.Background())
	e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(actx context.Context, _ core.Input) error {
		cancel()
		<-actx.Done()
		return nil
	}})
	var corrRan atomic.Bool
	e.Register(&fakeAnalyzer{name: "corr", stage: core.StageCorrelation, run: func(context.Context, core.Input) error {
		corrRan.Store(true)
		return nil
	}})

	if err := e.Run(ctx, s); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if corrRan.Load() {
		t.Fatal("correlation ran after cancellation")
	}
}

// Feature 01 (discovery): analyzers get the session scope, the shared store and a perimeter-guarded Net.
func TestEngineInput(t *testing.T) {
	e, st, s := newTestEngine(t, "192.168.1.0/24")

	var in core.Input
	e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(_ context.Context, got core.Input) error {
		in = got
		return nil
	}})
	if err := e.Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(in.Scope.CIDRs) != 1 || in.Scope.CIDRs[0].String() != "192.168.1.0/24" {
		t.Errorf("Scope = %v, want session scope", in.Scope.CIDRs)
	}
	if in.View != core.AssetView(st) || in.Sink != core.Sink(st) {
		t.Error("View/Sink are not the engine store")
	}
	if in.Net == nil {
		t.Fatal("Net is nil")
	}
	if _, err := in.Net.Dial(context.Background(), "tcp", "8.8.8.8:53"); !errors.Is(err, core.ErrOutOfScope) {
		t.Errorf("Net.Dial out of scope: err = %v, want ErrOutOfScope", err)
	}
}

// Feature 01 (discovery): Net enforces the scope of the session being run, so the perimeter has a single source.
func TestEngineNetFollowsSessionScope(t *testing.T) {
	e, _, _ := newTestEngine(t, "192.168.1.0/24")

	var n core.Net
	e.Register(&fakeAnalyzer{name: "disc", stage: core.StageDiscovery, run: func(_ context.Context, in core.Input) error {
		n = in.Net
		return nil
	}})

	if err := e.Run(context.Background(), &core.ScanSession{Scope: scopeOf(t, "10.0.0.0/8")}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := n.Dial(context.Background(), "tcp", "192.168.1.10:22"); !errors.Is(err, core.ErrOutOfScope) {
		t.Errorf("address outside the session scope: err = %v, want ErrOutOfScope", err)
	}
	if !n.(*guardedNet).gate.InScope("10.1.2.3") {
		t.Error("address inside the session scope is not allowed")
	}
}

// Feature 01 (discovery): Run stamps the session start time.
func TestEngineSetsStartedAt(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")
	fixed := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return fixed }

	if err := e.Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !s.StartedAt.Equal(fixed) {
		t.Fatalf("StartedAt = %v, want %v", s.StartedAt, fixed)
	}
}

// Feature 01 (discovery): an engine without analyzers completes successfully.
func TestEngineNoAnalyzers(t *testing.T) {
	e, _, s := newTestEngine(t, "192.168.1.0/24")
	if err := e.Run(context.Background(), s); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// Feature 01 (discovery): a nil session is rejected.
func TestEngineNilSession(t *testing.T) {
	e, _, _ := newTestEngine(t, "192.168.1.0/24")
	if err := e.Run(context.Background(), nil); !errors.Is(err, ErrNilSession) {
		t.Fatalf("err = %v, want ErrNilSession", err)
	}
}
