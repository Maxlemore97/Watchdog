package osv

import (
	"strings"
	"testing"
)

// Reference scores from the FIRST CVSS v3.1 calculator.
func TestCVSS3BaseScore(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
	}
	for vec, want := range cases {
		got, ok := cvssScore(vec)
		if !ok || got != want {
			t.Errorf("cvssScore(%s) = %v,%v want %v", vec, got, ok, want)
		}
	}
	for _, bad := range []string{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:X", "garbage"} {
		if _, ok := cvssScore(bad); ok {
			t.Errorf("cvssScore(%q) should not score", bad)
		}
	}
}

// Before: severity[].score holds a vector, ParseFloat failed, every
// such record fell back to "unknown = high" regardless of its score.
func TestSeverityRankOf_UsesCVSSVector(t *testing.T) {
	low := map[string]any{"id": "GHSA-low", "severity": []any{
		map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
	}}
	crit := map[string]any{"id": "GHSA-crit", "severity": []any{
		map[string]any{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}}
	if got := SeverityLabel(SeverityRankOf(low)); got != "low" {
		t.Errorf("low vector ranked %s", got)
	}
	if got := SeverityLabel(SeverityRankOf(crit)); got != "critical" {
		t.Errorf("critical vector ranked %s", got)
	}
}

// Malicious-package advisories carry no severity; they must rank
// critical and survive any WATCHDOG_MIN_SEVERITY floor.
func TestMaliciousAdvisoriesAlwaysKept(t *testing.T) {
	t.Setenv("WATCHDOG_MIN_SEVERITY", "critical")
	mal := map[string]any{"id": "MAL-2025-12345"}
	aliased := map[string]any{"id": "GHSA-xxxx", "aliases": []any{"MAL-2025-777"}}
	origin := map[string]any{"id": "OSV-1", "database_specific": map[string]any{"malicious-packages-origins": []any{}}}
	lowCVE := map[string]any{"id": "GHSA-low", "database_specific": map[string]any{"severity": "low"}}

	got := FilterBySeverity([]map[string]any{lowCVE, mal, aliased, origin})
	if len(got) != 3 {
		t.Fatalf("FilterBySeverity kept %d, want the 3 malicious records", len(got))
	}
	sum := Summarize([]map[string]any{lowCVE, mal})
	if !strings.HasPrefix(sum, "MAL-2025-12345[MALICIOUS PACKAGE]") {
		t.Errorf("Summarize = %q, malicious advisory should lead", sum)
	}
}
