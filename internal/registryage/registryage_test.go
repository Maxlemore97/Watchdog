package registryage

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Maxlemore97/watchdog/internal/types"
)

func TestLookup_Registries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/npm/@scope%2Fpkg", "/npm/@scope/pkg":
			_, _ = w.Write([]byte(`{"time":{"created":"2020-01-01T00:00:00.000Z","1.0.0":"2026-10-06T10:00:00.000Z"}}`))
		case "/pypi/requests/json":
			_, _ = w.Write([]byte(`{"releases":{"2.0":[{"upload_time_iso_8601":"2014-05-01T00:00:00.000000Z"}],"1.0":[{"upload_time_iso_8601":"2012-12-17T00:00:00.000000Z"}]}}`))
		case "/crates/serde":
			_, _ = w.Write([]byte(`{"crate":{"created_at":"2014-12-05T20:20:39.487502Z"},"versions":[{"num":"1.0.0","created_at":"2017-04-20T00:00:00Z"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	NPMRegistry, PyPIRegistry, CratesAPI = srv.URL+"/npm/", srv.URL+"/pypi/", srv.URL+"/crates/"
	t.Cleanup(func() {
		NPMRegistry, PyPIRegistry, CratesAPI = "https://registry.npmjs.org/", "https://pypi.org/pypi/", "https://crates.io/api/v1/crates/"
	})

	npm := Lookup(types.Package{Ecosystem: "npm", Name: "@scope/pkg", Version: "1.0.0"})
	if !npm.Exists || npm.FirstPublished.Year() != 2020 || npm.VersionTime.Day() != 6 {
		t.Errorf("npm: %+v", npm)
	}
	py := Lookup(types.Package{Ecosystem: "PyPI", Name: "requests", Version: "2.0"})
	if !py.Exists || py.FirstPublished.Year() != 2012 || py.VersionTime.Year() != 2014 {
		t.Errorf("pypi: %+v", py)
	}
	cr := Lookup(types.Package{Ecosystem: "crates.io", Name: "serde", Version: "1.0.0"})
	if !cr.Exists || cr.FirstPublished.Year() != 2014 || cr.VersionTime.Year() != 2017 {
		t.Errorf("crates: %+v", cr)
	}
	missing := Lookup(types.Package{Ecosystem: "npm", Name: "reqeusts-helper-ai"})
	if !missing.Known || missing.Exists {
		t.Errorf("missing: %+v", missing)
	}
	if other := Lookup(types.Package{Ecosystem: "RubyGems", Name: "rails"}); other.Known {
		t.Errorf("unsupported ecosystem should be unknown: %+v", other)
	}
}

func TestVerdict(t *testing.T) {
	fixed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = time.Now })
	p := types.Package{Ecosystem: "npm", Name: "x", Version: "1.0.0"}
	cases := []struct {
		info Info
		want string
	}{
		{Info{}, ""}, // lookup failed: fail open
		{Info{Known: true}, "does not exist"},
		{Info{Known: true, Exists: true, FirstPublished: fixed.Add(-48 * time.Hour)}, "first published 2 days ago"},
		{Info{Known: true, Exists: true, FirstPublished: fixed.AddDate(-3, 0, 0), VersionTime: fixed.Add(-5 * time.Hour)}, "released 5 h ago"},
		{Info{Known: true, Exists: true, FirstPublished: fixed.AddDate(-3, 0, 0), VersionTime: fixed.AddDate(0, 0, -3)}, ""},
	}
	for _, tc := range cases {
		v, reason := Verdict(p, tc.info)
		if tc.want == "" {
			if v != "" {
				t.Errorf("%+v: got %q %q, want none", tc.info, v, reason)
			}
			continue
		}
		if v != "ask" || !strings.Contains(reason, tc.want) {
			t.Errorf("%+v: got %q %q, want ask %q", tc.info, v, reason, tc.want)
		}
	}
}

func TestLookup_DisabledMakesNoRequest(t *testing.T) {
	t.Setenv("WATCHDOG_MIN_RELEASE_AGE_HOURS", "0")
	t.Setenv("WATCHDOG_MIN_PACKAGE_AGE_DAYS", "0")
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	orig := NPMRegistry
	NPMRegistry = srv.URL + "/"
	defer func() { NPMRegistry = orig }()
	if info := Lookup(types.Package{Ecosystem: "npm", Name: "x"}); info.Known || called {
		t.Errorf("disabled lookup: info=%+v called=%v", info, called)
	}
}
