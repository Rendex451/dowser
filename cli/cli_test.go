package cli

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"dowser/core"
	"dowser/store"
)

func cidrs(o ScanOptions) []string {
	out := make([]string, len(o.Scope.CIDRs))
	for i, n := range o.Scope.CIDRs {
		out[i] = n.String()
	}
	return out
}

// Feature 01 (discovery): scan flags are parsed into scope, ports and detect mode.
func TestParseScan(t *testing.T) {
	o, err := ParseScan([]string{"--scope", "192.168.1.0/24", "--scope", "10.0.0.5", "--scope", "2001:db8::1", "--ports", "443,22,8000-8002,22", "--detect"})
	if err != nil {
		t.Fatal(err)
	}
	if got := cidrs(o); !slices.Equal(got, []string{"192.168.1.0/24", "10.0.0.5/32", "2001:db8::1/128"}) {
		t.Errorf("scope = %v", got)
	}
	if !slices.Equal(o.Ports, []int{22, 443, 8000, 8001, 8002}) {
		t.Errorf("ports = %v", o.Ports)
	}
	if !o.Detect {
		t.Error("detect not set")
	}
}

// Feature 01 (discovery): without --ports and --detect the analyzer defaults apply.
func TestParseScanDefaults(t *testing.T) {
	o, err := ParseScan([]string{"--scope", "10.0.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Ports != nil || o.Detect {
		t.Errorf("opts = %+v, want default ports and fast mode", o)
	}
}

// Feature 01 (discovery): a host address inside a CIDR is masked to the network, an IPv4-mapped address becomes IPv4.
func TestParseScanNormalisesScope(t *testing.T) {
	o, err := ParseScan([]string{"--scope", "192.168.1.77/24", "--scope", "::ffff:10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := cidrs(o); !slices.Equal(got, []string{"192.168.1.0/24", "10.0.0.1/32"}) {
		t.Errorf("scope = %v", got)
	}
}

// Feature 01 (discovery): bad scan arguments are usage errors.
func TestParseScanErrors(t *testing.T) {
	cases := map[string][]string{
		"no scope":            {"--ports", "22"},
		"bad cidr":            {"--scope", "192.168.1.0/33"},
		"hostname scope":      {"--scope", "example.com"},
		"port zero":           {"--scope", "10.0.0.1", "--ports", "0"},
		"port too big":        {"--scope", "10.0.0.1", "--ports", "65536"},
		"reversed range":      {"--scope", "10.0.0.1", "--ports", "100-10"},
		"garbage port":        {"--scope", "10.0.0.1", "--ports", "ssh"},
		"broken range end":    {"--scope", "10.0.0.1", "--ports", "10-x"},
		"empty port item":     {"--scope", "10.0.0.1", "--ports", "22,"},
		"unknown flag":        {"--scope", "10.0.0.1", "--fast"},
		"positional argument": {"--scope", "10.0.0.1", "extra"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseScan(args); !errors.Is(err, ErrUsage) {
				t.Errorf("err = %v, want ErrUsage", err)
			}
		})
	}
}

func filledStore(t *testing.T) *store.Memory {
	t.Helper()
	ctx := context.Background()
	st := store.NewMemory()
	for _, a := range []string{"10.0.0.10", "10.0.0.2", "10.0.0.3"} {
		if err := st.AddAsset(ctx, core.Asset{ID: a, Addr: a}); err != nil {
			t.Fatal(err)
		}
	}
	svcs := []core.Service{
		{ID: "10.0.0.2:80/tcp", AssetRef: "10.0.0.2", Port: 80, Proto: "tcp", AppProto: core.AppProtoHTTP, Product: "nginx", Version: "1.27.5"},
		{ID: "10.0.0.2:22/tcp", AssetRef: "10.0.0.2", Port: 22, Proto: "tcp", AppProto: core.AppProtoSSH, Product: "OpenSSH", Version: "9.6"},
		{ID: "10.0.0.10:2121/tcp", AssetRef: "10.0.0.10", Port: 2121, Proto: "tcp"},
	}
	for _, s := range svcs {
		if err := st.AddService(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// Feature 01 (discovery): the inventory table is sorted by address and port, unknown values shown as "-".
func TestPrintInventory(t *testing.T) {
	var buf bytes.Buffer
	if err := PrintInventory(context.Background(), &buf, filledStore(t)); err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"ADDRESS    PORT      PROTOCOL  PRODUCT  VERSION",
		"10.0.0.2   22/tcp    ssh       OpenSSH  9.6",
		"10.0.0.2   80/tcp    http      nginx    1.27.5",
		"10.0.0.3   -         -         -        -",
		"10.0.0.10  2121/tcp  -         -        -",
		"",
	}, "\n")
	if buf.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

type failingView struct {
	assetsErr, servicesErr error
}

func (f failingView) Assets(context.Context) ([]core.Asset, error)     { return nil, f.assetsErr }
func (f failingView) Services(context.Context) ([]core.Service, error) { return nil, f.servicesErr }

// Feature 01 (discovery): read errors from the store are returned, not printed as an empty table.
func TestPrintInventoryErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, v := range []failingView{{assetsErr: boom}, {servicesErr: boom}} {
		if err := PrintInventory(context.Background(), &bytes.Buffer{}, v); !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
	}
}

type fakeScanner struct {
	session *core.ScanSession
	err     error
}

func (f *fakeScanner) Run(_ context.Context, s *core.ScanSession) error {
	f.session = s
	return f.err
}

// Feature 01 (discovery): Run wires options into the scanner, runs a session and prints the inventory.
func TestRunScan(t *testing.T) {
	sc := &fakeScanner{}
	var got ScanOptions
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"scan", "--scope", "10.0.0.0/24", "--detect"}, &out, &errOut,
		func(o ScanOptions) (Scanner, core.AssetView) { got = o; return sc, filledStore(t) })

	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errOut.String())
	}
	if !got.Detect || cidrs(got)[0] != "10.0.0.0/24" {
		t.Errorf("options = %+v", got)
	}
	if sc.session == nil || len(sc.session.ID) != 16 || sc.session.Scope.CIDRs[0].String() != "10.0.0.0/24" {
		t.Errorf("session = %+v", sc.session)
	}
	if !strings.Contains(out.String(), "OpenSSH") {
		t.Errorf("stdout = %q", out.String())
	}
}

// Feature 01 (discovery): usage problems exit with 2, scan and print failures with 1.
func TestRunExitCodes(t *testing.T) {
	build := func(sc Scanner, v core.AssetView) Build {
		return func(ScanOptions) (Scanner, core.AssetView) { return sc, v }
	}
	cases := []struct {
		name  string
		args  []string
		build Build
		want  int
	}{
		{"no command", nil, nil, 2},
		{"unknown command", []string{"report"}, nil, 2},
		{"bad flags", []string{"scan"}, nil, 2},
		{"scan fails", []string{"scan", "--scope", "10.0.0.1"}, build(&fakeScanner{err: errors.New("disk full")}, store.NewMemory()), 1},
		{"print fails", []string{"scan", "--scope", "10.0.0.1"}, build(&fakeScanner{}, failingView{assetsErr: errors.New("boom")}), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), tc.args, &out, &errOut, tc.build); code != tc.want {
				t.Fatalf("exit = %d, want %d (stderr: %s)", code, tc.want, errOut.String())
			}
			if errOut.Len() == 0 {
				t.Error("nothing written to stderr")
			}
		})
	}
}
