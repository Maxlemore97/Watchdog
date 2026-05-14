package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightInstall_EmptyCommandAllow(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	r := PreflightInstall("", "osv")
	if r.Verdict != "allow" {
		t.Errorf("empty command verdict = %q", r.Verdict)
	}
}

func TestPreflightInstall_NonInstallAllow(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	r := PreflightInstall("ls -la", "osv")
	if r.Verdict != "allow" {
		t.Errorf("non-install verdict = %q", r.Verdict)
	}
}

func TestPreflightInstall_InvalidModeFallsBack(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	r := PreflightInstall("", "banana")
	if r.Mode != "both" {
		t.Errorf("invalid mode = %q, want both", r.Mode)
	}
}

func TestScanPackage_NilAnalyzerReturnsAskFallback(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	t.Setenv("PATH", "") // no LLM CLI
	t.Setenv("WATCHDOG_RESOLVE_LATEST", "0")
	v := ScanPackage("npm", "some-fake-pkg-xyz", "1.0.0")
	if v["verdict"] != "ask" {
		t.Errorf("verdict = %v", v["verdict"])
	}
}

func TestAuditPlugin_ClassifiesGitURL(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	t.Setenv("PATH", "") // no git, no LLM
	v := AuditPlugin("https://example.invalid/repo.git")
	if v["verdict"] == nil {
		t.Errorf("missing verdict: %v", v)
	}
}

func TestAuditPluginLocal_ReturnsAskOnMissingDir(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	v := AuditPluginLocal("nope", "/nonexistent/x9q")
	if v["verdict"] != "ask" {
		t.Errorf("verdict = %v", v)
	}
}

func TestListVettedPlugins_ReturnsLedger(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	l := ListVettedPlugins()
	if l.Version != 1 || l.Entries == nil {
		t.Errorf("got %v", l)
	}
}

func TestOSVQuery_LiveServerHappyPath(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[{"id":"GHSA-x","database_specific":{"severity":"high"}}]}`))
	}))
	defer srv.Close()
	t.Setenv("WATCHDOG_OSV_ENDPOINT", srv.URL)

	r := OSVQuery("npm", "lodash", "4.0.0")
	if r.Error != "" {
		t.Errorf("unexpected error: %q", r.Error)
	}
	if len(r.Vulns) != 1 {
		t.Errorf("vulns = %v", r.Vulns)
	}
	if r.Threshold == "" {
		t.Errorf("missing threshold")
	}
}

func TestOSVQuery_OfflineReturnsError(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // closed → connection refused
	t.Setenv("WATCHDOG_OSV_ENDPOINT", srv.URL)

	r := OSVQuery("npm", "lodash", "4.0.0")
	if r.Error == "" {
		t.Errorf("offline should populate Error")
	}
	if len(r.Vulns) != 0 {
		t.Errorf("offline vulns should be empty: %v", r.Vulns)
	}
}

// JSON marshaling shape is the MCP contract — pin it so a future
// refactor of the handler types doesn't silently break clients.
func TestOSVQueryResult_JSONShape(t *testing.T) {
	r := OSVQueryResult{
		Vulns:     []map[string]any{{"id": "X"}},
		Filtered:  []map[string]any{},
		Threshold: "low",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"vulns", "filtered", "threshold"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing %q in JSON: %s", key, data)
		}
	}
	// `error` should be omitted when empty per `omitempty` tag.
	if _, ok := parsed["error"]; ok {
		t.Errorf("error field present when empty: %s", data)
	}
}

func TestOSVQueryResult_ErrorFieldIncluded(t *testing.T) {
	r := OSVQueryResult{Error: "boom", Threshold: "low"}
	data, _ := json.Marshal(r)
	var parsed map[string]any
	_ = json.Unmarshal(data, &parsed)
	if parsed["error"] != "boom" {
		t.Errorf("error not surfaced: %s", data)
	}
}

// Smoke check that the ledger path used by ListVettedPlugins respects
// the cache-dir env. Regression guard if someone hardcodes a path.
func TestListVettedPlugins_UsesCacheDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	_ = ListVettedPlugins() // creates empty
	// Save a synthetic ledger so we can load it back via the handler.
	path := filepath.Join(dir, "vetted_plugins.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"entries":{"x":{"name":"x","content_hash":"h"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ListVettedPlugins()
	if got.Entries["x"].ContentHash != "h" {
		t.Errorf("ledger not read from cache dir: %v", got)
	}
}
