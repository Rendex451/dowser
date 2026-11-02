package discovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"dowser/core"
)

type stub struct {
	ln      net.Listener
	accepts atomic.Int32
}

func startStub(t *testing.T, handle func(net.Conn)) *stub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveStub(t, ln, handle)
}

func serveStub(t *testing.T, ln net.Listener, handle func(net.Conn)) *stub {
	t.Helper()
	s := &stub{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepts.Add(1)
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return s
}

func (s *stub) endpoint() endpoint {
	ap := netip.MustParseAddrPort(s.ln.Addr().String())
	return endpoint{Addr: ap.Addr(), Port: int(ap.Port())}
}

func talker(greeting string) func(net.Conn) {
	return func(c net.Conn) {
		c.Write([]byte(greeting))
		io.Copy(io.Discard, c)
	}
}

func httpResponder(resp string, keepOpen bool) func(net.Conn) {
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		c.Write([]byte(resp))
		if keepOpen {
			io.Copy(io.Discard, c)
		}
	}
}

func mute(c net.Conn) { io.Copy(io.Discard, c) }

func testProbeConfig() probeConfig {
	return probeConfig{ConnectTimeout: time.Second, ReadTimeout: 300 * time.Millisecond, Limit: readLimit}
}

func tlsListener(t *testing.T) net.Listener {
	t.Helper()
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	certs := srv.TLS.Certificates
	srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certs})
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

const nginxOK = "HTTP/1.1 200 OK\r\nServer: nginx/1.27.5\r\nContent-Length: 2\r\n\r\nok"

// Feature 01 (discovery): a service that speaks first is identified on the wait step without waiting for the timeout.
func TestIdentifyTalker(t *testing.T) {
	s := startStub(t, talker("SSH-2.0-OpenSSH_9.6\r\n"))
	start := time.Now()
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderWaitFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoSSH || string(res.Raw) != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("res = %+v", res)
	}
	if d := time.Since(start); d >= testProbeConfig().ReadTimeout {
		t.Fatalf("took %v, the read waited for the timeout", d)
	}
}

// Feature 01 (discovery): a silent HTTP server is identified by GET on the same connection after the wait step.
func TestIdentifySilentHTTPReusesConnection(t *testing.T) {
	s := startStub(t, httpResponder(nginxOK, false))
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderWaitFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoHTTP {
		t.Fatalf("proto = %q, want http", res.Proto)
	}
	if n := s.accepts.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1", n)
	}
}

// Feature 01 (discovery): a kept-alive HTTP response is complete by Content-Length, not by the read timeout.
func TestIdentifyHTTPKeepAliveCompletes(t *testing.T) {
	s := startStub(t, httpResponder(nginxOK, true))
	start := time.Now()
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderGETFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoHTTP || time.Since(start) >= testProbeConfig().ReadTimeout {
		t.Fatalf("proto = %q after %v", res.Proto, time.Since(start))
	}
}

// Feature 01 (discovery): a non-HTTP answer to GET that keeps the connection open is identified immediately.
func TestIdentifyRedisLike(t *testing.T) {
	s := startStub(t, httpResponder("-ERR wrong number of arguments for 'get' command\r\n", true))
	start := time.Now()
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderGETFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoRedis || time.Since(start) >= testProbeConfig().ReadTimeout {
		t.Fatalf("proto = %q after %v", res.Proto, time.Since(start))
	}
}

// Feature 01 (discovery): with GET first, a service that speaks first is still recognised from what it sent.
func TestIdentifyGETFirstOnTalker(t *testing.T) {
	s := startStub(t, talker("SSH-2.0-OpenSSH_9.6\r\n"))
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderGETFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoSSH {
		t.Fatalf("proto = %q, want ssh", res.Proto)
	}
}

// Feature 01 (discovery): a mute service stays unidentified after every step and nothing hangs past the timeouts.
func TestIdentifyMute(t *testing.T) {
	s := startStub(t, mute)
	start := time.Now()
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderWaitFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != "" || len(res.Raw) != 0 {
		t.Fatalf("res = %+v, want unidentified", res)
	}
	if d := time.Since(start); d > 4*testProbeConfig().ReadTimeout {
		t.Fatalf("took %v", d)
	}
}

// Feature 01 (discovery): an unknown talker keeps its raw banner even though the protocol is not identified.
func TestIdentifyUnknownTalkerKeepsBanner(t *testing.T) {
	s := startStub(t, func(c net.Conn) { c.Write([]byte("hello stranger\n")) })
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderWaitFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != "" || string(res.Raw) != "hello stranger\n" {
		t.Fatalf("res = %+v", res)
	}
}

// Feature 01 (discovery): a server that closes right away is reopened for the next step instead of reusing a dead connection.
func TestIdentifyReopensAfterClose(t *testing.T) {
	var first atomic.Bool
	s := startStub(t, func(c net.Conn) {
		if first.CompareAndSwap(false, true) {
			return
		}
		httpResponder(nginxOK, false)(c)
	})
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderWaitFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoHTTP || s.accepts.Load() != 2 {
		t.Fatalf("proto = %q, connections = %d", res.Proto, s.accepts.Load())
	}
}

// Feature 01 (discovery): an HTTPS server is identified as https with the product from the inner HTTP response.
func TestIdentifyHTTPS(t *testing.T) {
	s := serveStub(t, tlsListener(t), httpResponder(nginxOK, false))
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderTLSFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoHTTPS {
		t.Fatalf("proto = %q, want https", res.Proto)
	}
	if p, v := parseProduct(res.Raw, res.Product); p != "nginx" || v != "1.27.5" {
		t.Fatalf("product = %q %q", p, v)
	}
}

// Feature 01 (discovery): HTTPS on a non-standard port is found by the full order even though plain GET gets an error page.
func TestIdentifyHTTPSOnUnknownPort(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.27.5")
	}))
	defer srv.Close()
	ap := netip.MustParseAddrPort(srv.Listener.Addr().String())
	res, err := identify(context.Background(), plainNet{}, endpoint{ap.Addr(), int(ap.Port())}, orderWaitFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoHTTPS {
		t.Fatalf("proto = %q, want https", res.Proto)
	}
}

// Feature 01 (discovery): TLS carrying something other than HTTP is reported as tls.
func TestIdentifyTLSNotHTTP(t *testing.T) {
	s := serveStub(t, tlsListener(t), func(c net.Conn) {
		c.Write([]byte("* OK IMAP ready\r\n"))
		io.Copy(io.Discard, c)
	})
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderTLSFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoTLS {
		t.Fatalf("proto = %q, want tls", res.Proto)
	}
}

// Feature 01 (discovery): a TLS probe against a plain service fails quietly and the next steps still run.
func TestIdentifyTLSFirstOnPlain(t *testing.T) {
	s := startStub(t, talker("SSH-2.0-OpenSSH_9.6\r\n"))
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), orderTLSFirst, testProbeConfig())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proto != core.AppProtoSSH {
		t.Fatalf("proto = %q, want ssh", res.Proto)
	}
}

// Feature 01 (discovery): a perimeter refusal and a canceled context are errors, not "unidentified".
func TestIdentifyErrors(t *testing.T) {
	ep := endpoint{netip.MustParseAddr("10.0.0.1"), 22}
	n := newFakeNet(map[string]behaviour{"10.0.0.1:22": outOfScope})
	if _, err := identify(context.Background(), n, ep, orderWaitFirst, testProbeConfig()); !errors.Is(err, core.ErrOutOfScope) {
		t.Errorf("out of scope: err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := identify(ctx, newFakeNet(nil), ep, orderTLSFirst, testProbeConfig()); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err = %v", err)
	}
}

// Feature 01 (discovery): a refused connection inside a probe step means "no answer", the probe moves on.
func TestIdentifyRefused(t *testing.T) {
	ep := endpoint{netip.MustParseAddr("10.0.0.1"), 22}
	n := newFakeNet(map[string]behaviour{"10.0.0.1:22": refuse})
	res, err := identify(context.Background(), n, ep, orderWaitFirst, testProbeConfig())
	if err != nil || res.Proto != "" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
}

// Feature 01 (discovery): reading stops at the size limit.
func TestIdentifyReadLimit(t *testing.T) {
	big := make([]byte, 64<<10)
	for i := range big {
		big[i] = 'x'
	}
	s := startStub(t, func(c net.Conn) { c.Write(big); io.Copy(io.Discard, c) })
	cfg := testProbeConfig()
	cfg.Limit = 1000
	res, err := identify(context.Background(), plainNet{}, s.endpoint(), []step{stepWait}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Raw) != 1000 {
		t.Fatalf("read %d bytes, want 1000", len(res.Raw))
	}
}
