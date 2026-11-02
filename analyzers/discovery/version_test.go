package discovery

import "testing"

// Feature 01 (discovery): product and version are parsed from responses recorded from real services.
func TestParseProductRealServices(t *testing.T) {
	cases := []struct {
		fixture string
		hint    string
		product string
		version string
	}{
		{"openssh-9.greeting", "", "OpenSSH", "10.3"},
		{"openssh-9.get", "", "OpenSSH", "10.3"},
		{"nginx-1.27.get", "", "nginx", "1.27.5"},
		{"elasticsearch-8.get", "Elasticsearch", "Elasticsearch", "8.15.3"},
		{"k3s-apiserver.tls-get", "Kubernetes", "Kubernetes", ""},
		{"mariadb-11.greeting", "", "MariaDB", "11.8.9"},
		{"mailpit.greeting", "", "Mailpit", ""},
		{"dovecot-pop3.greeting", "", "Dovecot", ""},
		{"dovecot-imap.greeting", "", "Dovecot", ""},
		{"redis-7.get", "Redis", "Redis", ""},
		{"vsftpd-3.greeting", "", "", ""},
		{"mailpit-ui.get", "", "", ""},
		{"busybox-telnetd.greeting", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			p, v := parseProduct(fixture(t, tc.fixture), tc.hint)
			if p != tc.product || v != tc.version {
				t.Errorf("parseProduct = %q %q, want %q %q", p, v, tc.product, tc.version)
			}
		})
	}
}

// Feature 01 (discovery): product and version from banner shapes without a recorded fixture; hidden versions stay empty.
func TestParseProductSamples(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		product string
		version string
	}{
		{"openssh distro suffix", "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n", "OpenSSH", "7.4p1"},
		{"dropbear", "SSH-2.0-dropbear_2022.83\r\n", "dropbear", "2022.83"},
		{"ssh without version", "SSH-2.0-Go\r\n", "Go", ""},
		{"vsftpd", "220 (vsFTPd 2.3.4)\r\n", "vsFTPd", "2.3.4"},
		{"proftpd", "220 ProFTPD 1.3.5 Server (Debian)\r\n", "ProFTPD", "1.3.5"},
		{"filezilla", "220-FileZilla Server 1.8.0\r\n", "FileZilla Server", "1.8.0"},
		{"pure-ftpd", "220---------- Welcome to Pure-FTPd [privsep] ----------\r\n", "Pure-FTPd", ""},
		{"exim", "220 mx ESMTP Exim 4.96 Mon, 02 Nov 2026\r\n", "Exim", "4.96"},
		{"postfix", "220 mail ESMTP Postfix (Ubuntu)\r\n", "Postfix", ""},
		{"apache", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian)\r\n\r\n", "Apache", "2.4.62"},
		{"server without version", "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", "nginx", ""},
		{"no server header", "HTTP/1.1 200 OK\r\n\r\n", "", ""},
		{"mysql", "\x0a\x00\x00\x00\x0a8.0.39\x00\x01", "MySQL", "8.0.39"},
		{"mariadb compat prefix", "\x1a\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB-0+deb12u1\x00", "MariaDB", "10.11.6"},
		{"unknown", "hello\n", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, v := parseProduct([]byte(tc.in), "")
			if p != tc.product || v != tc.version {
				t.Errorf("parseProduct(%q) = %q %q, want %q %q", tc.in, p, v, tc.product, tc.version)
			}
		})
	}
}

// Feature 01 (discovery): a product hint without an HTTP body to parse is returned as is.
func TestParseProductHintOnly(t *testing.T) {
	if p, v := parseProduct([]byte("HTTP/1.1 200 OK\r\n\r\n"), "Elasticsearch"); p != "Elasticsearch" || v != "" {
		t.Errorf("got %q %q", p, v)
	}
}

// Feature 01 (discovery): the stored banner is the first line, printable, with binary bytes escaped and length capped.
func TestBannerText(t *testing.T) {
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'a'
	}
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"ssh", fixture(t, "openssh-9.greeting"), "SSH-2.0-OpenSSH_10.3"},
		{"http status line", fixture(t, "nginx-1.27.get"), "HTTP/1.1 200 OK"},
		{"mysql shows version", fixture(t, "mariadb-11.greeting"), "11.8.9-MariaDB-ubu2404"},
		{"telnet escaped", []byte("\xff\xfd\x01ok\n"), `\xff\xfd\x01ok`},
		{"utf8 kept", []byte("220 Привет\r\n"), "220 Привет"},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bannerText(tc.in); got != tc.want {
				t.Errorf("bannerText = %q, want %q", got, tc.want)
			}
		})
	}
	if got := bannerText(long); len(got) != bannerMax {
		t.Errorf("long banner length = %d, want %d", len(got), bannerMax)
	}
}
