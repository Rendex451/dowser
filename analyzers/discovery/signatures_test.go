package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"dowser/core"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if len(b) == 0 {
		t.Fatalf("fixture %s is empty", name)
	}
	return b
}

// Feature 01 (discovery): greetings recorded from real services are recognised by their first bytes.
func TestMatchGreetingRealServices(t *testing.T) {
	cases := map[string]core.AppProto{
		"openssh-9.greeting":       core.AppProtoSSH,
		"vsftpd-3.greeting":        core.AppProtoFTP,
		"mailpit.greeting":         core.AppProtoSMTP,
		"dovecot-pop3.greeting":    core.AppProtoPOP3,
		"dovecot-imap.greeting":    core.AppProtoIMAP,
		"busybox-telnetd.greeting": core.AppProtoTelnet,
		"mariadb-11.greeting":      core.AppProtoMySQL,
		"x11vnc.greeting":          core.AppProtoVNC,
		"rsyncd.greeting":          core.AppProtoRsync,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			if got := matchGreeting(fixture(t, name)).Proto; got != want {
				t.Errorf("matchGreeting = %q, want %q", got, want)
			}
		})
	}
}

// Feature 01 (discovery): greeting signatures without a recorded fixture, taken from widely deployed servers.
func TestMatchGreetingSamples(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want core.AppProto
	}{
		{"proftpd", "220 ProFTPD 1.3.5 Server (Debian) [::ffff:10.0.0.1]\r\n", core.AppProtoFTP},
		{"vsftpd versioned", "220 (vsFTPd 2.3.4)\r\n", core.AppProtoFTP},
		{"multiline ftp", "220-FileZilla Server 1.8.0\r\n220 Please visit\r\n", core.AppProtoFTP},
		{"postfix", "220 mail.lab.lan ESMTP Postfix (Ubuntu)\r\n", core.AppProtoSMTP},
		{"exim", "220 mx.lab.lan ESMTP Exim 4.96 Mon, 02 Nov 2026\r\n", core.AppProtoSMTP},
		{"ambiguous 220", "220 Welcome\r\n", ""},
		{"imap preauth", "* PREAUTH IMAP4rev1 server logged in\r\n", core.AppProtoIMAP},
		{"irc numeric reply", ":irc.lab.lan 451 * :You have not registered\r\n", core.AppProtoIRC},
		{"mysql host not allowed", "\x45\x00\x00\x00\xff\x6a\x04Host '10.0.0.9' is not allowed to connect to this MySQL server", core.AppProtoMySQL},
		{"plain 200", "200 OK\r\n", ""},
		{"telnet without negotiation", "\xff\x01", ""},
		{"random text", "hello\n", ""},
		{"empty", "", ""},
		{"binary noise", "\x05\x00\x00\x00\x0a\x01\x02", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchGreeting([]byte(tc.in)).Proto; got != tc.want {
				t.Errorf("matchGreeting(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Feature 01 (discovery): responses of real services to our GET are recognised, including product hints.
func TestMatchResponseRealServices(t *testing.T) {
	cases := []struct {
		fixture string
		proto   core.AppProto
		product string
	}{
		{"nginx-1.27.get", core.AppProtoHTTP, ""},
		{"mailpit-ui.get", core.AppProtoHTTP, ""},
		{"elasticsearch-8.get", core.AppProtoHTTP, "Elasticsearch"},
		{"k3s-apiserver.tls-get", core.AppProtoHTTP, "Kubernetes"},
		{"redis-7.get", core.AppProtoRedis, "Redis"},
		{"ergo-irc.get", core.AppProtoIRC, ""},
		{"openssh-9.get", core.AppProtoSSH, ""},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			m := matchResponse(fixture(t, tc.fixture))
			if m.Proto != tc.proto || m.Product != tc.product {
				t.Errorf("matchResponse = %q/%q, want %q/%q", m.Proto, m.Product, tc.proto, tc.product)
			}
		})
	}
}

// Feature 01 (discovery): error pages of TLS servers hit with plain HTTP are recognised so the probe goes on to TLS.
func TestPlainHTTPToTLS(t *testing.T) {
	cases := map[string]bool{
		"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n":              true,
		"HTTP/1.1 400 Bad Request\r\n\r\n<center>The plain HTTP request was sent to HTTPS port</center>": true,
		"HTTP/1.1 400 Bad Request\r\n\r\nYou're speaking plain HTTP to an SSL-enabled server port.":      true,
		"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nok":                                                     false,
	}
	for in, want := range cases {
		if got := plainHTTPToTLS([]byte(in)); got != want {
			t.Errorf("plainHTTPToTLS(%q) = %v, want %v", in, got, want)
		}
	}
}

// Feature 01 (discovery): HTTP product hints that real fixtures do not cover.
func TestMatchResponseSamples(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		proto   core.AppProto
		product string
	}{
		{"old elasticsearch tagline", "HTTP/1.1 200 OK\r\n\r\n{\"tagline\" : \"You Know, for Search\"}", core.AppProtoHTTP, "Elasticsearch"},
		{"redis protected mode", "-DENIED Redis is running in protected mode\r\n", core.AppProtoRedis, "Redis"},
		{"redis noauth", "-NOAUTH Authentication required.\r\n", core.AppProtoRedis, "Redis"},
		{"lowercase dash is not redis", "-err nope\r\n", "", ""},
		{"nothing", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := matchResponse([]byte(tc.in))
			if m.Proto != tc.proto || m.Product != tc.product {
				t.Errorf("matchResponse = %q/%q, want %q/%q", m.Proto, m.Product, tc.proto, tc.product)
			}
		})
	}
}
