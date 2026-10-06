// Package registryage asks the package registry when a package and a
// version were first published. Two agent-specific risks hinge on it:
//
//   - slopsquatting: models hallucinate plausible package names and
//     attackers register them; such packages are days old. A name that
//     does not exist at all is a hallucination the agent should not
//     retry with a "close" spelling.
//   - fresh malicious releases: worm-style compromises (Shai-Hulud)
//     publish poisoned versions of popular packages and are pulled
//     within hours to days; a release-age cooldown sidesteps most of
//     them (the same idea as npm min-release-age / pnpm
//     minimumReleaseAge).
//
// Supported: npm, PyPI, crates.io. Other ecosystems return Unknown.
// Lookups fail open (Unknown): this is a heuristic on top of OSV and
// the analyzer, not a gate that should break installs when a registry
// is slow.
package registryage

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/types"
	"github.com/Maxlemore97/watchdog/internal/urlenc"
)

// Info is what the registry knows about a package.
type Info struct {
	Known          bool      // registry answered (found or not found)
	Exists         bool      // package exists
	FirstPublished time.Time // zero when unknown
	VersionTime    time.Time // zero when unknown or version not given
}

// Endpoints are vars so tests can point them at httptest servers.
var (
	NPMRegistry   = "https://registry.npmjs.org/"
	PyPIRegistry  = "https://pypi.org/pypi/"
	CratesAPI     = "https://crates.io/api/v1/crates/"
	httpTimeout   = 8 * time.Second
	maxBodyBytes  = int64(8 << 20)
	userAgentName = "watchdog-registryage (+https://github.com/Maxlemore97/Watchdog)"
	now           = time.Now
)

// Lookup queries the registry for p. Setting both
// WATCHDOG_MIN_RELEASE_AGE_HOURS and WATCHDOG_MIN_PACKAGE_AGE_DAYS to
// 0 turns registry lookups off entirely (including the existence
// check).
func Lookup(p types.Package) Info {
	if minReleaseAge() == 0 && minPackageAge() == 0 {
		return Info{}
	}
	switch p.Ecosystem {
	case "npm":
		return lookupNPM(p)
	case "PyPI":
		return lookupPyPI(p)
	case "crates.io":
		return lookupCrates(p)
	}
	return Info{}
}

// getJSON returns (found, ok): found=false on 404, ok=false on any
// other failure.
func getJSON(url string, out any) (found, ok bool) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("User-Agent", userAgentName)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return false, true
	default:
		return false, false
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(out); err != nil {
		return false, false
	}
	return true, true
}

func lookupNPM(p types.Package) Info {
	var doc struct {
		Time map[string]string `json:"time"`
	}
	// The full packument carries the per-version publish times. Very
	// large packuments exceed maxBodyBytes and fail open — those are
	// long-established packages anyway.
	found, ok := getJSON(NPMRegistry+urlenc.Escape(p.Name, "@"), &doc)
	if !ok {
		return Info{}
	}
	if !found {
		return Info{Known: true}
	}
	info := Info{Known: true, Exists: true, FirstPublished: parseTime(doc.Time["created"])}
	if p.Version != "" {
		info.VersionTime = parseTime(doc.Time[p.Version])
	}
	return info
}

func lookupPyPI(p types.Package) Info {
	var doc struct {
		Releases map[string][]struct {
			Upload string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	found, ok := getJSON(PyPIRegistry+urlenc.Escape(p.Name, "")+"/json", &doc)
	if !ok {
		return Info{}
	}
	if !found {
		return Info{Known: true}
	}
	info := Info{Known: true, Exists: true}
	for ver, files := range doc.Releases {
		for _, f := range files {
			t := parseTime(f.Upload)
			if t.IsZero() {
				continue
			}
			if info.FirstPublished.IsZero() || t.Before(info.FirstPublished) {
				info.FirstPublished = t
			}
			if ver == p.Version && (info.VersionTime.IsZero() || t.Before(info.VersionTime)) {
				info.VersionTime = t
			}
		}
	}
	return info
}

func lookupCrates(p types.Package) Info {
	var doc struct {
		Crate struct {
			Created string `json:"created_at"`
		} `json:"crate"`
		Versions []struct {
			Num     string `json:"num"`
			Created string `json:"created_at"`
		} `json:"versions"`
	}
	found, ok := getJSON(CratesAPI+urlenc.Escape(p.Name, ""), &doc)
	if !ok {
		return Info{}
	}
	if !found {
		return Info{Known: true}
	}
	info := Info{Known: true, Exists: true, FirstPublished: parseTime(doc.Crate.Created)}
	for _, v := range doc.Versions {
		if v.Num == p.Version {
			info.VersionTime = parseTime(v.Created)
		}
	}
	return info
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Policy thresholds; read from the environment (validated by
// internal/config). 0 disables a check.
func minReleaseAge() time.Duration {
	return time.Duration(envInt("WATCHDOG_MIN_RELEASE_AGE_HOURS", 24)) * time.Hour
}

func minPackageAge() time.Duration {
	return time.Duration(envInt("WATCHDOG_MIN_PACKAGE_AGE_DAYS", 7)) * 24 * time.Hour
}

func envInt(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return def
	}
	return v
}

// Verdict turns Info into "ask" with a reason, or "" when nothing is
// suspicious (or nothing is known).
func Verdict(p types.Package, info Info) (string, string) {
	if !info.Known {
		return "", ""
	}
	if !info.Exists {
		return "ask", fmt.Sprintf("%s:%s does not exist on the registry — likely a hallucinated name; verify the package instead of trying similar spellings", p.Ecosystem, p.Name)
	}
	t := now()
	if d := minPackageAge(); d > 0 && !info.FirstPublished.IsZero() && t.Sub(info.FirstPublished) < d {
		return "ask", fmt.Sprintf("%s:%s was first published %s ago — new packages are the main vehicle for slopsquatting; confirm it is the intended package", p.Ecosystem, p.Name, humanAge(t.Sub(info.FirstPublished)))
	}
	if d := minReleaseAge(); d > 0 && !info.VersionTime.IsZero() && t.Sub(info.VersionTime) < d {
		return "ask", fmt.Sprintf("%s:%s@%s was released %s ago — inside the %s cooldown in which compromised releases are usually caught; pin an older version or wait", p.Ecosystem, p.Name, p.Version, humanAge(t.Sub(info.VersionTime)), humanAge(d))
	}
	return "", ""
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
