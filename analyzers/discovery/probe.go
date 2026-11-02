package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"

	"dowser/core"
)

var getRequest = []byte("GET / HTTP/1.0\r\n\r\n")

type probeConfig struct {
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	Limit          int
}

type probeResult struct {
	Proto   core.AppProto
	Product string
	Raw     []byte
}

type prober struct {
	net   core.Net
	ep    endpoint
	cfg   probeConfig
	plain net.Conn
}

func identify(ctx context.Context, n core.Net, ep endpoint, order []step, cfg probeConfig) (probeResult, error) {
	p := &prober{net: n, ep: ep, cfg: cfg}
	defer p.closePlain()

	var last []byte
	for _, st := range order {
		var (
			res probeResult
			err error
		)
		switch st {
		case stepWait:
			res, err = p.wait(ctx)
		case stepGET:
			res, err = p.get(ctx)
		case stepTLS:
			res, err = p.tls(ctx)
		}
		if err != nil {
			return probeResult{}, err
		}
		if res.Proto != "" {
			return res, nil
		}
		if len(res.Raw) > 0 {
			last = res.Raw
		}
	}
	return probeResult{Raw: last}, nil
}

func (p *prober) wait(ctx context.Context) (probeResult, error) {
	conn, err := p.plainConn(ctx)
	if err != nil || conn == nil {
		return probeResult{}, err
	}
	return p.read(conn), nil
}

func (p *prober) get(ctx context.Context) (probeResult, error) {
	conn, err := p.plainConn(ctx)
	if err != nil || conn == nil {
		return probeResult{}, err
	}
	conn.SetWriteDeadline(time.Now().Add(p.cfg.ReadTimeout))
	if _, err := conn.Write(getRequest); err != nil {
		p.closePlain()
		return probeResult{}, nil
	}
	res := p.read(conn)
	if res.Proto == core.AppProtoHTTP && plainHTTPToTLS(res.Raw) {
		return probeResult{Raw: res.Raw}, nil
	}
	return res, nil
}

func (p *prober) tls(ctx context.Context) (probeResult, error) {
	raw, err := p.dial(ctx)
	if err != nil || raw == nil {
		return probeResult{}, err
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	hctx, cancel := context.WithTimeout(ctx, p.cfg.ReadTimeout)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return probeResult{}, ctxErr
		}
		return probeResult{}, nil
	}

	conn.SetWriteDeadline(time.Now().Add(p.cfg.ReadTimeout))
	if _, err := conn.Write(getRequest); err != nil {
		return probeResult{Proto: core.AppProtoTLS}, nil
	}
	inner := p.read(conn)
	if inner.Proto == core.AppProtoHTTP {
		return probeResult{Proto: core.AppProtoHTTPS, Product: inner.Product, Raw: inner.Raw}, nil
	}
	return probeResult{Proto: core.AppProtoTLS, Raw: inner.Raw}, nil
}

func (p *prober) plainConn(ctx context.Context) (net.Conn, error) {
	if p.plain != nil {
		return p.plain, nil
	}
	conn, err := p.dial(ctx)
	p.plain = conn
	return conn, err
}

func (p *prober) closePlain() {
	if p.plain != nil {
		p.plain.Close()
		p.plain = nil
	}
}

func (p *prober) dial(ctx context.Context) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout)
	defer cancel()
	conn, err := p.net.Dial(dctx, "tcp", p.ep.String())
	if err == nil {
		return conn, nil
	}
	if errors.Is(err, core.ErrOutOfScope) {
		return nil, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	return nil, nil
}

func (p *prober) read(conn net.Conn) probeResult {
	conn.SetReadDeadline(time.Now().Add(p.cfg.ReadTimeout))
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 1024)
	for len(buf) < p.cfg.Limit {
		n, err := conn.Read(chunk[:min(len(chunk), p.cfg.Limit-len(buf))])
		buf = append(buf, chunk[:n]...)
		if err != nil {
			if !isTimeout(err) && conn == p.plain {
				p.closePlain()
			}
			break
		}
		if complete(buf) {
			break
		}
	}
	m := matchResponse(buf)
	return probeResult{Proto: m.Proto, Product: m.Product, Raw: buf}
}

func complete(b []byte) bool {
	m := matchResponse(b)
	switch {
	case m.Proto == core.AppProtoHTTP:
		return httpComplete(b)
	case m.Proto != "":
		return true
	}
	return bytes.HasSuffix(b, []byte("\n"))
}

func httpComplete(b []byte) bool {
	head, body, ok := bytes.Cut(b, []byte("\r\n\r\n"))
	if !ok {
		return false
	}
	cl := header(string(head), "Content-Length")
	if cl == "" {
		return false
	}
	n, err := strconv.Atoi(cl)
	return err == nil && len(body) >= n
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
