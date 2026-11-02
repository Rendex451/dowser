package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"dowser/core"
)

var (
	_ core.Sink      = (*Memory)(nil)
	_ core.AssetView = (*Memory)(nil)
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func get[T any](t *testing.T, f func(context.Context) ([]T, error)) []T {
	t.Helper()
	v, err := f(context.Background())
	must(t, err)
	return v
}

// Feature 01 (discovery): an empty store returns empty results without errors.
func TestMemoryEmpty(t *testing.T) {
	m := NewMemory()
	if n := len(get(t, m.Assets)); n != 0 {
		t.Errorf("Assets() len = %d, want 0", n)
	}
	if n := len(get(t, m.Services)); n != 0 {
		t.Errorf("Services() len = %d, want 0", n)
	}
	if n := len(get(t, m.Findings)); n != 0 {
		t.Errorf("Findings() len = %d, want 0", n)
	}
}

// Feature 01 (discovery): assets and services come back in insertion order.
func TestMemoryKeepsInsertionOrder(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	for _, addr := range []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"} {
		must(t, m.AddAsset(ctx, core.Asset{ID: addr, Addr: addr}))
	}
	got := get(t, m.Assets)
	want := []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"}
	if len(got) != len(want) {
		t.Fatalf("Assets() len = %d, want %d", len(got), len(want))
	}
	for i, a := range got {
		if a.ID != want[i] {
			t.Errorf("Assets()[%d].ID = %q, want %q", i, a.ID, want[i])
		}
	}
}

// Feature 01 (discovery): re-adding an asset with the same ID replaces it in place instead of duplicating.
func TestMemoryAssetDeduplicatedByID(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	must(t, m.AddAsset(ctx, core.Asset{ID: "10.0.0.1", Addr: "old"}))
	must(t, m.AddAsset(ctx, core.Asset{ID: "10.0.0.2", Addr: "10.0.0.2"}))
	must(t, m.AddAsset(ctx, core.Asset{ID: "10.0.0.1", Addr: "new"}))

	got := get(t, m.Assets)
	if len(got) != 2 {
		t.Fatalf("Assets() len = %d, want 2", len(got))
	}
	if got[0].ID != "10.0.0.1" || got[0].Addr != "new" {
		t.Errorf("Assets()[0] = %+v, want replaced asset at original position", got[0])
	}
}

// Feature 01 (discovery): a later service with the same ID (e.g. after banner grabbing) replaces the earlier one.
func TestMemoryServiceDeduplicatedByID(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	id := "10.0.0.1:22/tcp"
	must(t, m.AddService(ctx, core.Service{ID: id, AssetRef: "10.0.0.1", Port: 22, Proto: "tcp"}))
	must(t, m.AddService(ctx, core.Service{ID: id, AssetRef: "10.0.0.1", Port: 22, Proto: "tcp", Banner: "SSH-2.0-OpenSSH_7.4"}))

	got := get(t, m.Services)
	if len(got) != 1 {
		t.Fatalf("Services() len = %d, want 1", len(got))
	}
	if got[0].Banner != "SSH-2.0-OpenSSH_7.4" {
		t.Errorf("Banner = %q, want the later value", got[0].Banner)
	}
}

// Feature 01 (discovery): findings are kept as a list, duplicates included.
func TestMemoryFindingsAppended(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	must(t, m.AddFinding(ctx, core.Finding{ID: "f1", Title: "a"}))
	must(t, m.AddFinding(ctx, core.Finding{ID: "f1", Title: "b"}))

	got := get(t, m.Findings)
	if len(got) != 2 || got[0].Title != "a" || got[1].Title != "b" {
		t.Fatalf("Findings() = %+v, want both findings in order", got)
	}
}

// Feature 01 (discovery): returned slices are snapshots; mutating them does not change the store.
func TestMemoryReturnsCopies(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	must(t, m.AddAsset(ctx, core.Asset{ID: "a", Addr: "10.0.0.1"}))
	must(t, m.AddService(ctx, core.Service{ID: "s", Port: 22}))
	must(t, m.AddFinding(ctx, core.Finding{ID: "f", References: []string{"CVE-1"}, Evidence: core.Evidence{Raw: []byte("raw")}}))

	get(t, m.Assets)[0].Addr = "changed"
	get(t, m.Services)[0].Port = 0
	f := get(t, m.Findings)
	f[0].References[0] = "changed"
	f[0].Evidence.Raw[0] = 'X'

	if get(t, m.Assets)[0].Addr != "10.0.0.1" {
		t.Error("asset changed through returned slice")
	}
	if get(t, m.Services)[0].Port != 22 {
		t.Error("service changed through returned slice")
	}
	got := get(t, m.Findings)[0]
	if got.References[0] != "CVE-1" || string(got.Evidence.Raw) != "raw" {
		t.Error("finding changed through returned slice")
	}
}

// Feature 01 (discovery): mutating a finding's slices after AddFinding does not change the stored copy.
func TestMemoryAddFindingCopiesInput(t *testing.T) {
	m := NewMemory()
	refs := []string{"CVE-1"}
	raw := []byte("raw")
	must(t, m.AddFinding(context.Background(), core.Finding{ID: "f", References: refs, Evidence: core.Evidence{Raw: raw}}))

	refs[0] = "changed"
	raw[0] = 'X'

	got := get(t, m.Findings)[0]
	if got.References[0] != "CVE-1" || string(got.Evidence.Raw) != "raw" {
		t.Error("stored finding follows caller's slices")
	}
}

// Feature 01 (discovery): every method honours a canceled context — writes are rejected and nothing is stored.
func TestMemoryCanceledContext(t *testing.T) {
	m := NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	writes := map[string]error{
		"AddAsset":   m.AddAsset(ctx, core.Asset{ID: "a"}),
		"AddService": m.AddService(ctx, core.Service{ID: "s"}),
		"AddFinding": m.AddFinding(ctx, core.Finding{ID: "f"}),
	}
	for name, err := range writes {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: err = %v, want context.Canceled", name, err)
		}
	}

	if _, err := m.Assets(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Assets: err = %v, want context.Canceled", err)
	}
	if _, err := m.Services(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Services: err = %v, want context.Canceled", err)
	}
	if _, err := m.Findings(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Findings: err = %v, want context.Canceled", err)
	}

	if len(get(t, m.Assets))+len(get(t, m.Services))+len(get(t, m.Findings)) != 0 {
		t.Error("rejected writes were stored")
	}
}

// Feature 01 (discovery): concurrent writers and readers are safe (run with -race) and lose nothing.
func TestMemoryConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	const writers, perWriter = 16, 100

	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter*6)
	for w := range writers {
		wg.Go(func() {
			for i := range perWriter {
				id := fmt.Sprintf("%d-%d", w, i)
				errs <- m.AddAsset(ctx, core.Asset{ID: id})
				errs <- m.AddService(ctx, core.Service{ID: id})
				errs <- m.AddFinding(ctx, core.Finding{ID: id})
			}
		})
		wg.Go(func() {
			for range perWriter {
				_, err := m.Assets(ctx)
				errs <- err
				_, err = m.Services(ctx)
				errs <- err
				_, err = m.Findings(ctx)
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}

	want := writers * perWriter
	if n := len(get(t, m.Assets)); n != want {
		t.Errorf("Assets() len = %d, want %d", n, want)
	}
	if n := len(get(t, m.Services)); n != want {
		t.Errorf("Services() len = %d, want %d", n, want)
	}
	if n := len(get(t, m.Findings)); n != want {
		t.Errorf("Findings() len = %d, want %d", n, want)
	}
}
