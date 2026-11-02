package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"dowser/core"
)

type ScanOptions struct {
	Scope  core.Scope
	Ports  []int
	Detect bool
}

type Scanner interface {
	Run(ctx context.Context, s *core.ScanSession) error
}

type Build func(ScanOptions) (Scanner, core.AssetView)

var ErrUsage = errors.New("usage error")

const usage = `usage: dowser scan --scope CIDR [--scope CIDR ...] [--ports LIST] [--detect]

  --scope   network or address to audit, repeatable (192.168.1.0/24, 10.0.0.5)
  --ports   ports to scan: 22,80,8000-8100 (default: nmap top-100 + known services)
  --detect  identify protocols by response content instead of port number
`

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, build Build) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	opts, err := ParseScan(args[1:])
	if err != nil {
		fmt.Fprintf(stderr, "dowser: %v\n\n%s", err, usage)
		return 2
	}

	scanner, view := build(opts)
	session := &core.ScanSession{ID: newSessionID(), Scope: opts.Scope}
	if err := scanner.Run(ctx, session); err != nil {
		fmt.Fprintf(stderr, "dowser: scan failed: %v\n", err)
		return 1
	}
	if err := PrintInventory(ctx, stdout, view); err != nil {
		fmt.Fprintf(stderr, "dowser: %v\n", err)
		return 1
	}
	return 0
}

func ParseScan(args []string) (ScanOptions, error) {
	var (
		opts   ScanOptions
		scopes scopeFlag
		ports  string
	)
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&scopes, "scope", "")
	fs.StringVar(&ports, "ports", "", "")
	fs.BoolVar(&opts.Detect, "detect", false, "")
	if err := fs.Parse(args); err != nil {
		return ScanOptions{}, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return ScanOptions{}, fmt.Errorf("%w: unexpected argument %q", ErrUsage, fs.Arg(0))
	}
	if len(scopes) == 0 {
		return ScanOptions{}, fmt.Errorf("%w: at least one --scope is required", ErrUsage)
	}
	opts.Scope = core.Scope{CIDRs: scopes}
	if ports != "" {
		p, err := parsePorts(ports)
		if err != nil {
			return ScanOptions{}, err
		}
		opts.Ports = p
	}
	return opts, nil
}

type scopeFlag []net.IPNet

func (s *scopeFlag) String() string { return "" }

func (s *scopeFlag) Set(v string) error {
	if !strings.Contains(v, "/") {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return fmt.Errorf("invalid scope %q: not an address or CIDR", v)
		}
		v = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String()
	}
	_, n, err := net.ParseCIDR(v)
	if err != nil {
		return fmt.Errorf("invalid scope %q: not an address or CIDR", v)
	}
	*s = append(*s, *n)
	return nil
}

func parsePorts(v string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(v, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		from, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		to := from
		if isRange {
			if to, err = parsePort(hi); err != nil {
				return nil, err
			}
			if to < from {
				return nil, fmt.Errorf("%w: invalid port range %q", ErrUsage, part)
			}
		}
		for p := from; p <= to; p++ {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("%w: invalid port %q", ErrUsage, s)
	}
	return p, nil
}

func PrintInventory(ctx context.Context, w io.Writer, view core.AssetView) error {
	assets, err := view.Assets(ctx)
	if err != nil {
		return err
	}
	services, err := view.Services(ctx)
	if err != nil {
		return err
	}

	byAsset := make(map[string][]core.Service)
	for _, s := range services {
		byAsset[s.AssetRef] = append(byAsset[s.AssetRef], s)
	}
	slices.SortFunc(assets, func(a, b core.Asset) int { return compareAddr(a.Addr, b.Addr) })

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS\tPORT\tPROTOCOL\tPRODUCT\tVERSION")
	for _, a := range assets {
		svcs := byAsset[a.ID]
		if len(svcs) == 0 {
			fmt.Fprintf(tw, "%s\t-\t-\t-\t-\n", a.Addr)
			continue
		}
		slices.SortFunc(svcs, func(x, y core.Service) int { return x.Port - y.Port })
		for _, s := range svcs {
			fmt.Fprintf(tw, "%s\t%d/%s\t%s\t%s\t%s\n", a.Addr, s.Port, s.Proto, dash(string(s.AppProto)), dash(s.Product), dash(s.Version))
		}
	}
	return tw.Flush()
}

func compareAddr(a, b string) int {
	x, errX := netip.ParseAddr(a)
	y, errY := netip.ParseAddr(b)
	if errX != nil || errY != nil {
		return strings.Compare(a, b)
	}
	return x.Compare(y)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
