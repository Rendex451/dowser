package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"dowser/cli"
)

// Feature 01 (discovery): the composed binary scans a real local service end to end in both detect and fast modes.
func TestScanEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
				io.Copy(io.Discard, c)
			}()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	for _, mode := range []struct {
		args  []string
		proto string
	}{
		{[]string{"--detect"}, "ssh"},
		{nil, "-"},
	} {
		var out, errOut bytes.Buffer
		args := append([]string{"scan", "--scope", "127.0.0.1", "--ports", fmt.Sprint(port)}, mode.args...)
		if code := runCLI(args, &out, &errOut); code != 0 {
			t.Fatalf("%v: exit = %d, stderr = %s", args, code, errOut.String())
		}
		want := fmt.Sprintf("%d/tcp", port)
		line := ""
		for _, l := range strings.Split(out.String(), "\n") {
			if strings.Contains(l, want) {
				line = l
			}
		}
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "127.0.0.1" || fields[2] != mode.proto || fields[3] != "OpenSSH" || fields[4] != "9.6" {
			t.Errorf("%v: row = %q in\n%s", args, line, out.String())
		}
	}
}

func runCLI(args []string, out, errOut *bytes.Buffer) int {
	return cli.Run(context.Background(), args, out, errOut, build)
}
