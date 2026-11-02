package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"dowser/core"
	"dowser/store"
)

type redirectNet struct{ to string }

func (r redirectNet) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, r.to)
}

type lab struct {
	ssh, http, mute, closed int
}

func startLab(t *testing.T) lab {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return lab{
		ssh:    startStub(t, talker("SSH-2.0-OpenSSH_9.6\r\n")).endpoint().Port,
		http:   startStub(t, httpResponder(nginxOK, false)).endpoint().Port,
		mute:   startStub(t, mute).endpoint().Port,
		closed: closed,
	}
}

func newTestDiscovery(l lab, detect bool) *Discovery {
	d := New(Config{
		Ports:       []int{l.ssh, l.http, l.mute, l.closed},
		Detect:      detect,
		ReadTimeout: 300 * time.Millisecond,
	})
	d.liveness = []int{l.ssh}
	return d
}

func runDiscovery(t *testing.T, d *Discovery, n core.Net, cidrs ...string) *store.Memory {
	t.Helper()
	st := store.NewMemory()
	in := core.Input{Scope: scopeOf(t, cidrs...), Net: n, View: st, Sink: st}
	if err := d.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return st
}

func servicesByPort(t *testing.T, st *store.Memory) map[int]core.Service {
	t.Helper()
	svcs, err := st.Services(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[int]core.Service, len(svcs))
	for _, s := range svcs {
		out[s.Port] = s
	}
	return out
}

// Feature 01 (discovery): the analyzer declares itself as the discovery stage.
func TestDiscoveryIdentity(t *testing.T) {
	d := New(Config{})
	if d.Name() != "discovery" || d.Stage() != core.StageDiscovery {
		t.Fatalf("Name/Stage = %q/%v", d.Name(), d.Stage())
	}
}

// Feature 01 (discovery): an empty config gets the agreed defaults.
func TestDiscoveryDefaults(t *testing.T) {
	cfg := New(Config{}).cfg
	if !slices.Equal(cfg.Ports, defaultPorts()) || cfg.Detect ||
		cfg.ConnectTimeout != time.Second || cfg.ReadTimeout != 2*time.Second ||
		cfg.Workers != 256 || cfg.MaxTargets != 65536 {
		t.Fatalf("defaults = %+v", cfg)
	}
}

// Feature 01 (discovery): detect mode finds the host, its open ports and identifies services by content.
func TestDiscoveryDetectMode(t *testing.T) {
	l := startLab(t)
	st := runDiscovery(t, newTestDiscovery(l, true), plainNet{}, "127.0.0.1/32")

	assets, _ := st.Assets(context.Background())
	if len(assets) != 1 || assets[0].ID != "127.0.0.1" || assets[0].Addr != "127.0.0.1" {
		t.Fatalf("assets = %+v", assets)
	}

	svcs := servicesByPort(t, st)
	if len(svcs) != 3 {
		t.Fatalf("services = %+v, want ssh, http and mute", svcs)
	}
	if _, ok := svcs[l.closed]; ok {
		t.Error("closed port reported as a service")
	}

	ssh := svcs[l.ssh]
	want := core.Service{
		ID: fmt.Sprintf("127.0.0.1:%d/tcp", l.ssh), AssetRef: "127.0.0.1", Port: l.ssh, Proto: "tcp",
		AppProto: core.AppProtoSSH, Banner: "SSH-2.0-OpenSSH_9.6", Product: "OpenSSH", Version: "9.6",
	}
	if ssh != want {
		t.Errorf("ssh = %+v, want %+v", ssh, want)
	}
	if h := svcs[l.http]; h.AppProto != core.AppProtoHTTP || h.Product != "nginx" || h.Version != "1.27.5" {
		t.Errorf("http = %+v", h)
	}
	if m := svcs[l.mute]; m.AppProto != "" || m.Product != "" {
		t.Errorf("mute = %+v, want unidentified", m)
	}
}

// Feature 01 (discovery): fast mode takes the protocol from the port table only and runs a single probe step.
func TestDiscoveryFastMode(t *testing.T) {
	l := startLab(t)
	st := runDiscovery(t, newTestDiscovery(l, false), plainNet{}, "127.0.0.1/32")

	svcs := servicesByPort(t, st)
	if len(svcs) != 3 {
		t.Fatalf("services = %+v", svcs)
	}
	for port, s := range svcs {
		if s.AppProto != "" {
			t.Errorf("port %d: AppProto = %q, want empty for a port outside the table", port, s.AppProto)
		}
	}
	if s := svcs[l.ssh]; s.Product != "OpenSSH" {
		t.Errorf("ssh banner from the single wait step: %+v", s)
	}
	if s := svcs[l.http]; s.Product != "" {
		t.Errorf("silent http got a product without the GET step: %+v", s)
	}
}

// Feature 01 (discovery): fast mode labels a well-known port by the table even when the content says otherwise.
func TestDiscoveryFastModeUsesTable(t *testing.T) {
	s := startStub(t, talker("SSH-2.0-OpenSSH_9.6\r\n"))
	d := New(Config{ReadTimeout: 300 * time.Millisecond})
	svc, err := d.inspect(context.Background(), redirectNet{s.ln.Addr().String()}, endpoint{netip.MustParseAddr("127.0.0.1"), 80})
	if err != nil {
		t.Fatal(err)
	}
	if svc.AppProto != core.AppProtoHTTP {
		t.Fatalf("AppProto = %q, want http from the port table", svc.AppProto)
	}
}

// Feature 01 (discovery): an ambiguous "220" greeting is resolved by the port hint in detect mode.
func TestDiscoveryAmbiguous220UsesHint(t *testing.T) {
	s := startStub(t, talker("220 Welcome\r\n"))
	d := New(Config{Detect: true, ReadTimeout: 300 * time.Millisecond})
	n := redirectNet{s.ln.Addr().String()}
	for port, want := range map[int]core.AppProto{21: core.AppProtoFTP, 25: core.AppProtoSMTP, 31337: ""} {
		svc, err := d.inspect(context.Background(), n, endpoint{netip.MustParseAddr("127.0.0.1"), port})
		if err != nil {
			t.Fatal(err)
		}
		if svc.AppProto != want {
			t.Errorf("port %d: AppProto = %q, want %q", port, svc.AppProto, want)
		}
	}
}

// Feature 01 (discovery): a dead scope yields no assets and no services.
func TestDiscoveryNothingAlive(t *testing.T) {
	d := New(Config{Ports: []int{22}, ConnectTimeout: 50 * time.Millisecond})
	st := runDiscovery(t, d, newFakeNet(nil), "10.0.0.0/30")
	assets, _ := st.Assets(context.Background())
	svcs, _ := st.Services(context.Background())
	if len(assets) != 0 || len(svcs) != 0 {
		t.Fatalf("assets = %v, services = %v", assets, svcs)
	}
}

type failingSink struct {
	*store.Memory
	failAsset, failService bool
}

var errSink = errors.New("disk full")

func (f failingSink) AddAsset(ctx context.Context, a core.Asset) error {
	if f.failAsset {
		return errSink
	}
	return f.Memory.AddAsset(ctx, a)
}

func (f failingSink) AddService(ctx context.Context, s core.Service) error {
	if f.failService {
		return errSink
	}
	return f.Memory.AddService(ctx, s)
}

// Feature 01 (discovery): a store failure aborts Run with the store error.
func TestDiscoverySinkErrors(t *testing.T) {
	l := startLab(t)
	for _, sink := range []failingSink{
		{Memory: store.NewMemory(), failAsset: true},
		{Memory: store.NewMemory(), failService: true},
	} {
		in := core.Input{Scope: scopeOf(t, "127.0.0.1/32"), Net: plainNet{}, View: sink, Sink: sink}
		if err := newTestDiscovery(l, true).Run(context.Background(), in); !errors.Is(err, errSink) {
			t.Errorf("err = %v, want the sink error", err)
		}
	}
}

// Feature 01 (discovery): scope and perimeter errors stop Run before any result is written.
func TestDiscoveryRunErrors(t *testing.T) {
	d := New(Config{Ports: []int{22}, ConnectTimeout: 50 * time.Millisecond})
	st := store.NewMemory()

	in := core.Input{Scope: scopeOf(t, "2001:db8::/64"), Net: plainNet{}, View: st, Sink: st}
	if err := d.Run(context.Background(), in); !errors.Is(err, ErrScopeTooLarge) {
		t.Errorf("too large: err = %v", err)
	}

	in = core.Input{Scope: scopeOf(t, "10.0.0.1/32"), Net: newFakeNet(map[string]behaviour{"10.0.0.1:22": outOfScope}), View: st, Sink: st}
	if err := d.Run(context.Background(), in); !errors.Is(err, core.ErrOutOfScope) {
		t.Errorf("out of scope: err = %v", err)
	}

	assets, _ := st.Assets(context.Background())
	if len(assets) != 0 {
		t.Errorf("assets written despite errors: %v", assets)
	}
}

// Feature 01 (discovery): a perimeter refusal during the port scan or the probes aborts Run.
func TestDiscoveryOutOfScopeLater(t *testing.T) {
	d := New(Config{Ports: []int{80}, ConnectTimeout: 50 * time.Millisecond})
	d.liveness = []int{22}
	st := store.NewMemory()
	n := newFakeNet(map[string]behaviour{"10.0.0.1:22": refuse, "10.0.0.1:80": outOfScope})
	in := core.Input{Scope: scopeOf(t, "10.0.0.1/32"), Net: n, View: st, Sink: st}
	if err := d.Run(context.Background(), in); !errors.Is(err, core.ErrOutOfScope) {
		t.Fatalf("err = %v, want ErrOutOfScope", err)
	}
}
