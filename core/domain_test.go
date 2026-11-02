package core

import (
	"strings"
	"testing"
)

// Feature 01 (discovery): severities are ordered from least to most severe so they can be compared and sorted.
func TestSeverityOrder(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Fatalf("severity %d is not below %d", order[i-1], order[i])
		}
	}
}

// Feature 01 (discovery): discovery stage runs before correlation, the engine relies on this ordering.
func TestStageOrder(t *testing.T) {
	if StageDiscovery >= StageCorrelation {
		t.Fatalf("StageDiscovery (%d) must be below StageCorrelation (%d)", StageDiscovery, StageCorrelation)
	}
}

// Feature 01 (discovery): app protocol values are stable, unique lowercase strings, they end up in the JSON report as is.
func TestAppProtoValues(t *testing.T) {
	all := []AppProto{
		AppProtoSSH, AppProtoFTP, AppProtoSMTP, AppProtoPOP3, AppProtoIMAP, AppProtoTelnet,
		AppProtoMySQL, AppProtoVNC, AppProtoRsync, AppProtoIRC, AppProtoHTTP,
		AppProtoHTTPS, AppProtoTLS, AppProtoRedis,
	}
	seen := make(map[AppProto]bool, len(all))
	for _, p := range all {
		if p == "" || string(p) != strings.ToLower(string(p)) {
			t.Errorf("app protocol %q must be a non-empty lowercase string", p)
		}
		if seen[p] {
			t.Errorf("app protocol %q is duplicated", p)
		}
		seen[p] = true
	}
}

// Feature 01 (discovery): category values are stable strings, they end up in the JSON report as is.
func TestCategoryValues(t *testing.T) {
	cases := map[Category]string{
		CategoryVuln:      "vuln",
		CategoryCleartext: "cleartext",
		CategoryExposure:  "exposure",
	}
	for c, want := range cases {
		if string(c) != want {
			t.Errorf("category = %q, want %q", c, want)
		}
	}
}
