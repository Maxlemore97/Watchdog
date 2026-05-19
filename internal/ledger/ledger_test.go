package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func makePlugin(t *testing.T, root, name, version string, withSkill bool) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(dir, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"name": name, "version": version}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(dir, ".claude-plugin", "plugin.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks", "demo.sh"), []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "commands"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "commands", "demo.md"), []byte("# demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if withSkill {
		if err := os.MkdirAll(filepath.Join(dir, "skills"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "skills", "demo.md"),
			[]byte("---\nname: demo\nallowed-tools: Bash\n---\nhelpful demo\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// ---------- discovery -------------------------------------------

func TestDiscover_FindsManifestedPlugins(t *testing.T) {
	tmp := t.TempDir()
	makePlugin(t, tmp, "alpha", "0.1", false)
	makePlugin(t, tmp, "beta", "0.1", false)
	if err := os.MkdirAll(filepath.Join(tmp, "not-a-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	found := Discover([]string{tmp})
	names := []string{}
	for _, p := range found {
		names = append(names, p.Name)
	}
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Errorf("got %v", names)
	}
}

func TestDiscover_SkipsSelf(t *testing.T) {
	tmp := t.TempDir()
	makePlugin(t, tmp, "watchdog", "0.1", false)
	makePlugin(t, tmp, "other", "0.1", false)
	found := Discover([]string{tmp})
	if len(found) != 1 || found[0].Name != "other" {
		t.Errorf("self not skipped: %v", found)
	}
}

func TestDiscover_ReadsInstalledPluginsJSON(t *testing.T) {
	tmp := t.TempDir()
	cache := filepath.Join(tmp, "cache", "mkt", "alpha", "0.1")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	makePlugin(t, filepath.Dir(cache), "0.1", "0.1", false)
	// rewrite the plugin manifest with the real name expected by the test
	manifest := map[string]any{"name": "alpha", "version": "0.1"}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(cache, ".claude-plugin", "plugin.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cache, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "hooks", "demo.sh"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	installed := map[string]any{
		"version": 2,
		"plugins": map[string]any{
			"alpha@mkt": []any{
				map[string]any{"scope": "user", "installPath": cache, "version": "0.1"},
			},
		},
	}
	doc, _ := json.Marshal(installed)
	if err := os.WriteFile(filepath.Join(tmp, "installed_plugins.json"), doc, 0o644); err != nil {
		t.Fatal(err)
	}

	// Add a decoy child that would have matched the immediate-child walk
	// — it must be ignored once installed_plugins.json is present.
	makePlugin(t, tmp, "decoy", "0.1", false)

	found := Discover([]string{tmp})
	if len(found) != 1 || found[0].Name != "alpha" || found[0].Path != cache {
		t.Errorf("expected alpha at %s, got %#v", cache, found)
	}
}

func TestDiscover_InstalledPluginsJSON_SkipsStaleAndSelf(t *testing.T) {
	tmp := t.TempDir()
	live := filepath.Join(tmp, "cache", "mkt", "other", "0.1")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"name": "other", "version": "0.1"}
	data, _ := json.Marshal(manifest)
	if err := os.MkdirAll(filepath.Join(live, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, ".claude-plugin", "plugin.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	wd := filepath.Join(tmp, "cache", "mkt", "watchdog", "0.1")
	if err := os.MkdirAll(filepath.Join(wd, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	wdManifest, _ := json.Marshal(map[string]any{"name": "watchdog", "version": "0.1"})
	if err := os.WriteFile(filepath.Join(wd, ".claude-plugin", "plugin.json"), wdManifest, 0o644); err != nil {
		t.Fatal(err)
	}

	installed := map[string]any{
		"plugins": map[string]any{
			"other@mkt":    []any{map[string]any{"installPath": live}},
			"watchdog@mkt": []any{map[string]any{"installPath": wd}},
			"stale@mkt":    []any{map[string]any{"installPath": filepath.Join(tmp, "cache", "mkt", "stale", "0.1")}},
		},
	}
	doc, _ := json.Marshal(installed)
	if err := os.WriteFile(filepath.Join(tmp, "installed_plugins.json"), doc, 0o644); err != nil {
		t.Fatal(err)
	}

	found := Discover([]string{tmp})
	if len(found) != 1 || found[0].Name != "other" {
		t.Errorf("expected only 'other'; got %#v", found)
	}
}

// ---------- content hash ----------------------------------------

func TestContentHash_StableForIdenticalFiles(t *testing.T) {
	tmp := t.TempDir()
	p := makePlugin(t, tmp, "alpha", "0.1", false)
	if ContentHash(p) != ContentHash(p) {
		t.Error("hash not stable")
	}
}

func TestContentHash_ChangesWhenFileChanges(t *testing.T) {
	tmp := t.TempDir()
	p := makePlugin(t, tmp, "alpha", "0.1", false)
	h1 := ContentHash(p)
	if err := os.WriteFile(filepath.Join(p, "hooks", "demo.sh"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2 := ContentHash(p)
	if h1 == h2 {
		t.Error("hash didn't change after file edit")
	}
}

func TestContentHash_IgnoresUnrelatedFiles(t *testing.T) {
	tmp := t.TempDir()
	p := makePlugin(t, tmp, "alpha", "0.1", false)
	h1 := ContentHash(p)
	if err := os.WriteFile(filepath.Join(p, "README.md"), []byte("docs"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2 := ContentHash(p)
	if h1 != h2 {
		t.Error("README.md should not change hash")
	}
}

func TestContentHash_ChangesWhenSkillAdded(t *testing.T) {
	tmp := t.TempDir()
	p := makePlugin(t, tmp, "alpha", "0.1", false)
	h1 := ContentHash(p)
	if err := os.MkdirAll(filepath.Join(p, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "skills", "evil.md"),
		[]byte("malicious"), 0o644); err != nil {
		t.Fatal(err)
	}
	h2 := ContentHash(p)
	if h1 == h2 {
		t.Error("new skill should change hash")
	}
}

// ---------- ReadManifest symlink reject ------------------------

func TestReadManifest_RejectsSymlink(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "real")
	if err := os.WriteFile(target, []byte(`{"name":"leak"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(tmp, ".claude-plugin", "plugin.json")); err != nil {
		t.Fatal(err)
	}
	if got := ReadManifest(tmp); len(got) != 0 {
		t.Errorf("symlinked manifest leaked: %v", got)
	}
}

func TestReadManifest_RealFile(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".claude-plugin", "plugin.json"),
		[]byte(`{"name":"real","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ReadManifest(tmp)
	if got["name"] != "real" || got["version"] != "1" {
		t.Errorf("got %v", got)
	}
}

// ---------- ledger I/O ------------------------------------------

func TestLoadSave_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	l := Ledger{
		Version: 1,
		Entries: map[string]LedgerEntry{
			"a": {Name: "a", ContentHash: "x"},
		},
	}
	Save(l)
	loaded := Load()
	if loaded.Entries["a"].ContentHash != "x" {
		t.Errorf("roundtrip failed: %v", loaded)
	}
}

func TestLoad_MissingReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	l := Load()
	if l.Version != 1 || len(l.Entries) != 0 {
		t.Errorf("got %v", l)
	}
}

func TestLoad_CorruptReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "vetted_plugins.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := Load()
	if len(l.Entries) != 0 {
		t.Errorf("corrupt should yield empty: %v", l)
	}
}

func TestConcurrentSave_NoTornFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", dir)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			Save(Ledger{
				Version: 1,
				Entries: map[string]LedgerEntry{"p": {Name: "p", ContentHash: "h"}},
			})
		}(i)
	}
	wg.Wait()
	l := Load()
	if l.Version != 1 {
		t.Errorf("torn write: %v", l)
	}
}

// ---------- Scan ------------------------------------------------

func TestScan_SkipsUnchanged(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	makePlugin(t, tmp, "alpha", "0.1", false)
	plugins := Discover([]string{tmp})
	calls := []string{}
	fake := func(name, path, hash string) map[string]any {
		calls = append(calls, name)
		return map[string]any{"verdict": "allow", "reason": "ok"}
	}
	l := Ledger{Version: 1, Entries: map[string]LedgerEntry{}}
	findings, dirty, skipped := Scan(plugins, &l, fake, 0)
	if len(findings) != 1 || !dirty || skipped != 0 {
		t.Errorf("first scan: %d findings, dirty=%v, skipped=%d", len(findings), dirty, skipped)
	}
	findings2, dirty2, _ := Scan(plugins, &l, fake, 0)
	if len(findings2) != 0 || dirty2 {
		t.Errorf("second scan should noop: %d findings, dirty=%v", len(findings2), dirty2)
	}
	if len(calls) != 1 {
		t.Errorf("analyzer called %d times, want 1", len(calls))
	}
}

func TestScan_RespectsMaxScansEnv(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	t.Setenv("WATCHDOG_SESSION_MAX_SCANS", "2")
	for i := 0; i < 5; i++ {
		makePlugin(t, tmp, "p"+string(rune('0'+i)), "0.1", false)
	}
	plugins := Discover([]string{tmp})
	fake := func(_, _, _ string) map[string]any {
		return map[string]any{"verdict": "allow"}
	}
	l := Ledger{Version: 1, Entries: map[string]LedgerEntry{}}
	findings, _, skipped := Scan(plugins, &l, fake, 0)
	if len(findings) != 2 || skipped != 3 {
		t.Errorf("findings=%d skipped=%d", len(findings), skipped)
	}
}

// TestWithLock_ConcurrentSave_NoLostUpdates verifies that wrapping
// Load → modify → Save in WithLock prevents the classic lost-update
// race: N goroutines each add a unique entry; the final ledger must
// contain all N entries (no concurrent writer's modifications
// clobbered by a sibling's Save).
func TestWithLock_ConcurrentSave_NoLostUpdates(t *testing.T) {
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	const N = 16
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			WithLock(func() {
				l := Load()
				name := "plugin-" + string(rune('a'+i))
				l.Entries[name] = LedgerEntry{
					Name:        name,
					ContentHash: "hash-" + name,
					Verdict:     "allow",
				}
				Save(l)
			})
		}(i)
	}
	wg.Wait()

	final := Load()
	if len(final.Entries) != N {
		t.Errorf("lost updates: got %d entries, want %d", len(final.Entries), N)
		for k := range final.Entries {
			t.Logf("  present: %s", k)
		}
	}
}

func TestScan_RecordsVerdictFields(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("WATCHDOG_CACHE_DIR", t.TempDir())
	makePlugin(t, tmp, "alpha", "1.2.3", false)
	plugins := Discover([]string{tmp})
	fake := func(_, _, _ string) map[string]any {
		return map[string]any{"verdict": "deny", "risk": "high", "reason": "scary"}
	}
	l := Ledger{Version: 1, Entries: map[string]LedgerEntry{}}
	Scan(plugins, &l, fake, 0)
	entry := l.Entries["alpha"]
	if entry.Verdict != "deny" || entry.Risk != "high" || entry.Reason != "scary" ||
		entry.ManifestVersion != "1.2.3" || entry.ContentHash == "" {
		t.Errorf("entry not recorded: %+v", entry)
	}
}
