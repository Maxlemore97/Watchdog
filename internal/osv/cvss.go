package osv

import (
	"math"
	"strconv"
	"strings"
)

// IsMalicious reports whether an OSV record is a malicious-package
// advisory (OpenSSF malicious-packages feed: MAL-YYYY-N ids, also
// carried as aliases). These usually have no CVSS severity at all, yet
// they are the most severe finding there is: the package *is* the
// attack (Shai-Hulud, Nx/s1ngularity, postmark-mcp).
func IsMalicious(vuln map[string]any) bool {
	if id, _ := vuln["id"].(string); strings.HasPrefix(id, "MAL-") {
		return true
	}
	if aliases, ok := vuln["aliases"].([]any); ok {
		for _, a := range aliases {
			if s, _ := a.(string); strings.HasPrefix(s, "MAL-") {
				return true
			}
		}
	}
	if dbs, ok := vuln["database_specific"].(map[string]any); ok {
		if _, ok := dbs["malicious-packages-origins"]; ok {
			return true
		}
	}
	return false
}

// cvssScore returns the base score for an OSV severity score string:
// a plain number, or a CVSS v3.x vector ("CVSS:3.1/AV:N/AC:L/…"). OSV
// stores vectors, not numbers, in severity[].score. ok=false for
// formats it cannot score (CVSS v4 needs the full macro-vector lookup
// table; v2 is obsolete in OSV) — the caller treats those as unknown.
func cvssScore(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}
	if strings.HasPrefix(s, "CVSS:3.") {
		return cvss3BaseScore(s)
	}
	return 0, false
}

// cvss3BaseScore implements the CVSS v3.1 base-score equations
// (https://www.first.org/cvss/v3.1/specification-document §7.1). v3.0
// vectors use the same metrics; the rounding difference is at most 0.1.
func cvss3BaseScore(vector string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	val := map[string]float64{}
	for k, table := range weights {
		w, ok := table[m[k]]
		if !ok {
			return 0, false
		}
		val[k] = w
	}
	changed := m["S"] == "C"
	if m["S"] != "C" && m["S"] != "U" {
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, false
	}
	iss := 1 - (1-val["C"])*(1-val["I"])*(1-val["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * val["AV"] * val["AC"] * pr * val["UI"]
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp(math.Min(impact+exploitability, 10)), true
}

// roundUp is the CVSS v3.1 Roundup: smallest one-decimal number >= x,
// computed on integers to avoid floating-point artefacts.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
