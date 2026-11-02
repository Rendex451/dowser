package discovery

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	reSSH       = regexp.MustCompile(`^SSH-[\d.]+-(\S+)`)
	reESVersion = regexp.MustCompile(`"number"\s*:\s*"([^"]+)"`)
	reServer    = regexp.MustCompile(`^([^/\s]+)(?:/(\S+))?`)
)

var textBanners = []struct {
	re      *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`vsFTPd (\S+?)\)`), "vsFTPd"},
	{regexp.MustCompile(`ProFTPD (\d\S*)`), "ProFTPD"},
	{regexp.MustCompile(`FileZilla Server (\d\S*)`), "FileZilla Server"},
	{regexp.MustCompile(`Pure-FTPd()`), "Pure-FTPd"},
	{regexp.MustCompile(`ESMTP Exim (\d\S*)`), "Exim"},
	{regexp.MustCompile(`ESMTP Postfix()`), "Postfix"},
	{regexp.MustCompile(`Mailpit()`), "Mailpit"},
	{regexp.MustCompile(`Dovecot()`), "Dovecot"},
}

func parseProduct(raw []byte, hint string) (product, version string) {
	s := string(raw)
	switch {
	case strings.HasPrefix(s, "SSH-"):
		return parseSSH(s)
	case strings.HasPrefix(s, "HTTP/1."):
		return parseHTTP(s, hint)
	case isMySQL(raw) && raw[4] == 0x0a:
		return parseMySQL(raw)
	}
	if hint != "" {
		return hint, ""
	}
	line := firstLine(s)
	for _, b := range textBanners {
		if m := b.re.FindStringSubmatch(line); m != nil {
			return b.product, m[1]
		}
	}
	return "", ""
}

func parseSSH(s string) (string, string) {
	m := reSSH.FindStringSubmatch(firstLine(s))
	if m == nil {
		return "", ""
	}
	product, version, _ := strings.Cut(m[1], "_")
	return product, version
}

func parseHTTP(s, hint string) (string, string) {
	head, body, _ := strings.Cut(s, "\r\n\r\n")
	switch hint {
	case "Elasticsearch":
		if m := reESVersion.FindStringSubmatch(body); m != nil {
			return hint, m[1]
		}
		return hint, ""
	case "":
	default:
		return hint, ""
	}
	m := reServer.FindStringSubmatch(header(head, "Server"))
	if m == nil {
		return "", ""
	}
	return m[1], m[2]
}

func parseMySQL(raw []byte) (string, string) {
	end := bytes.IndexByte(raw[5:], 0)
	v := strings.TrimPrefix(string(raw[5:5+end]), "5.5.5-")
	product := "MySQL"
	if strings.Contains(v, "MariaDB") {
		product = "MariaDB"
	}
	version, _, _ := strings.Cut(v, "-")
	return product, version
}

const bannerMax = 200

func bannerText(raw []byte) string {
	if isMySQL(raw) && raw[4] == 0x0a {
		end := bytes.IndexByte(raw[5:], 0)
		return string(raw[5 : 5+end])
	}
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	line = bytes.TrimRight(line, "\r")
	var sb strings.Builder
	for len(line) > 0 && sb.Len() < bannerMax {
		r, size := utf8.DecodeRune(line)
		if r == utf8.RuneError || r < 0x20 || r == 0x7f {
			fmt.Fprintf(&sb, `\x%02x`, line[0])
			line = line[1:]
			continue
		}
		sb.WriteRune(r)
		line = line[size:]
	}
	return sb.String()
}
