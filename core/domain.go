package core

import (
	"net"
	"time"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type Category string

const (
	CategoryVuln      Category = "vuln"
	CategoryCleartext Category = "cleartext"
	CategoryExposure  Category = "exposure"
)

type AppProto string

const (
	AppProtoSSH    AppProto = "ssh"
	AppProtoFTP    AppProto = "ftp"
	AppProtoSMTP   AppProto = "smtp"
	AppProtoPOP3   AppProto = "pop3"
	AppProtoIMAP   AppProto = "imap"
	AppProtoTelnet AppProto = "telnet"
	AppProtoMySQL  AppProto = "mysql"
	AppProtoVNC    AppProto = "vnc"
	AppProtoRsync  AppProto = "rsync"
	AppProtoIRC    AppProto = "irc"
	AppProtoHTTP   AppProto = "http"
	AppProtoHTTPS  AppProto = "https"
	AppProtoTLS    AppProto = "tls"
	AppProtoRedis  AppProto = "redis"
)

type Asset struct {
	ID   string
	Addr string
}

type Service struct {
	ID       string
	AssetRef string
	Port     int
	Proto    string
	AppProto AppProto
	Banner   string
	Product  string
	Version  string
}

type Finding struct {
	ID         string
	SessionID  string
	Analyzer   string
	AssetRef   string
	ServiceRef string
	Title      string
	Severity   Severity
	Category   Category
	References []string
	Evidence   Evidence
	Timestamp  time.Time
}

type Evidence struct {
	Raw  []byte
	Note string
}

type Scope struct {
	CIDRs []net.IPNet
}

type ScanSession struct {
	ID        string
	Scope     Scope
	StartedAt time.Time
}
