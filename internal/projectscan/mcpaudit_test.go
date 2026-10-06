package projectscan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOSV answers every query with no vulns, except for packages named
// in malicious, which get a MAL advisory.
func fakeOSV(t *testing.T, malicious ...string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			Package struct{ Name string } `json:"package"`
		}
		_ = json.Unmarshal(body, &q)
		for _, m := range malicious {
			if q.Package.Name == m {
				_, _ = w.Write([]byte(`{"vulns":[{"id":"MAL-2026-1"}]}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("WATCHDOG_OSV_ENDPOINT", srv.URL)
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	t.Setenv("WATCHDOG_RESOLVE_LATEST", "0")
	t.Setenv("WATCHDOG_MIN_RELEASE_AGE_HOURS", "0")
	t.Setenv("WATCHDOG_MIN_PACKAGE_AGE_DAYS", "0")
	t.Setenv("WATCHDOG_LOG", filepath.Join(t.TempDir(), "events.jsonl"))
}

func TestAuditMCP(t *testing.T) {
	fakeOSV(t, "evil-mcp")
	dir := t.TempDir()
	desktop := filepath.Join(dir, "claude_desktop_config.json")
	codex := filepath.Join(dir, "config.toml")
	_ = os.WriteFile(desktop, []byte(`{"mcpServers":{
		"watchdog":{"command":"/x/watchdog-mcp"},
		"good":{"command":"npx","args":["-y","good-mcp@1.0.0"]},
		"bad":{"command":"npx","args":["-y","evil-mcp@2.0.0"]}}}`), 0o600)
	_ = os.WriteFile(codex, []byte("[mcp_servers.floating]\ncommand = \"uvx\"\nargs = [\"floating-mcp\"]\n"), 0o600)

	res := AuditMCP(MCPAuditOpts{Configs: []string{desktop, codex, filepath.Join(dir, "missing.json")}})
	if res.Verdict != "deny" {
		t.Errorf("verdict %q, want deny (malicious package)", res.Verdict)
	}
	if len(res.Configs) != 2 {
		t.Errorf("configs %v, want the two existing files", res.Configs)
	}
	got := map[string]MCPServerReport{}
	for _, s := range res.Servers {
		got[s.Name] = s
	}
	if _, ok := got["watchdog"]; ok {
		t.Error("watchdog's own entry should be skipped")
	}
	if got["good"].Verdict != "allow" {
		t.Errorf("good: %+v", got["good"])
	}
	if got["bad"].Verdict != "deny" || got["bad"].Preflight == nil || !strings.Contains(got["bad"].Preflight.Reason, "MALICIOUS") {
		t.Errorf("bad: %+v", got["bad"])
	}
	if got["floating"].Verdict != "ask" || len(got["floating"].Findings) == 0 {
		t.Errorf("floating (unpinned uvx): %+v", got["floating"])
	}
}
