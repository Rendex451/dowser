package discovery

import (
	"bytes"
	"regexp"
	"strings"

	"dowser/core"
)

type match struct {
	Proto   core.AppProto
	Product string
}

var (
	reVNC       = regexp.MustCompile(`^RFB \d{3}\.\d{3}\n`)
	reIRC       = regexp.MustCompile(`^:\S+ \d{3} `)
	reRESPError = regexp.MustCompile(`^-[A-Z]+ `)
)

func matchGreeting(b []byte) match {
	s := string(b)
	lower := strings.ToLower(firstLine(s))
	switch {
	case strings.HasPrefix(s, "SSH-"):
		return match{Proto: core.AppProtoSSH}
	case isTelnet(b):
		return match{Proto: core.AppProtoTelnet}
	case reVNC.MatchString(s):
		return match{Proto: core.AppProtoVNC}
	case strings.HasPrefix(s, "@RSYNCD:"):
		return match{Proto: core.AppProtoRsync}
	case isMySQL(b):
		return match{Proto: core.AppProtoMySQL}
	case strings.HasPrefix(s, "+OK"):
		return match{Proto: core.AppProtoPOP3}
	case strings.HasPrefix(s, "* OK"), strings.HasPrefix(s, "* PREAUTH"):
		return match{Proto: core.AppProtoIMAP}
	case strings.HasPrefix(s, "220"):
		return match220(lower)
	case reIRC.MatchString(s):
		return match{Proto: core.AppProtoIRC}
	}
	return match{}
}

func match220(lower string) match {
	smtp := strings.Contains(lower, "smtp")
	ftp := strings.Contains(lower, "ftp") || strings.Contains(lower, "filezilla")
	switch {
	case smtp && !ftp:
		return match{Proto: core.AppProtoSMTP}
	case ftp && !smtp:
		return match{Proto: core.AppProtoFTP}
	}
	return match{}
}

func isTelnet(b []byte) bool {
	return len(b) >= 2 && b[0] == 0xFF && b[1] >= 0xFB && b[1] <= 0xFE
}

func isMySQL(b []byte) bool {
	if len(b) < 6 || b[3] != 0 {
		return false
	}
	payload := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	if payload == 0 || payload > 1<<16 {
		return false
	}
	switch b[4] {
	case 0x0a:
		end := bytes.IndexByte(b[5:], 0)
		return end > 0 && isPrintable(b[5:5+end])
	case 0xff:
		msg := strings.ToLower(string(b[7:]))
		return strings.Contains(msg, "mysql") || strings.Contains(msg, "mariadb")
	}
	return false
}

func matchResponse(b []byte) match {
	s := string(b)
	switch {
	case strings.HasPrefix(s, "HTTP/1."):
		return match{Proto: core.AppProtoHTTP, Product: httpProduct(s)}
	case reRESPError.MatchString(s):
		return match{Proto: core.AppProtoRedis, Product: "Redis"}
	}
	return matchGreeting(b)
}

var plainToTLSMarkers = []string{
	"http request to an https server",
	"plain http request was sent to https port",
	"speaking plain http to an ssl-enabled server",
}

func plainHTTPToTLS(b []byte) bool {
	lower := strings.ToLower(string(b))
	for _, m := range plainToTLSMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func httpProduct(s string) string {
	head, body, _ := strings.Cut(s, "\r\n\r\n")
	if strings.EqualFold(header(head, "X-Elastic-Product"), "Elasticsearch") ||
		strings.Contains(body, `"tagline" : "You Know, for Search"`) {
		return "Elasticsearch"
	}
	if strings.Contains(body, `"kind":"Status"`) && strings.Contains(body, `"apiVersion"`) {
		return "Kubernetes"
	}
	return ""
}

func header(head, name string) string {
	for _, line := range strings.Split(head, "\r\n")[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimRight(line, "\r")
}

func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
