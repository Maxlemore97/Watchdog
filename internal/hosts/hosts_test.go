package hosts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// fakeHost lets us drive the mcpServersHost logic with a controllable
// config path in tests, without depending on the real OS-specific
// path for Claude Desktop or Cursor.
func fakeHost(t *testing.T, name string) *mcpServersHost {
	t.Helper()
	dir := t.TempDir()
	// Pre-create the config dir so Exists() returns true.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &mcpServersHost{
		name:       name,
		configPath: filepath.Join(dir, "config.json"),
	}
}

func TestExists_TrueWhenConfigDirPresent(t *testing.T) {
	h := fakeHost(t, "fake")
	if !h.Exists() {
		t.Errorf("Exists should be true when parent dir exists")
	}
}

func TestExists_FalseWhenNoDir(t *testing.T) {
	h := &mcpServersHost{
		name:       "fake",
		configPath: "/nonexistent/path/config.json",
	}
	if h.Exists() {
		t.Errorf("Exists should be false for missing parent dir")
	}
}

func TestRegister_CreatesConfigFile(t *testing.T) {
	h := fakeHost(t, "fake")
	if h.IsRegistered() {
		t.Fatal("registered before any Register call")
	}
	if err := h.Register("/usr/local/bin/watchdog-mcp"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !h.IsRegistered() {
		t.Error("IsRegistered=false after Register")
	}

	data, err := os.ReadFile(h.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	entry, _ := servers["watchdog"].(map[string]any)
	if entry["command"] != "/usr/local/bin/watchdog-mcp" {
		t.Errorf("command = %v", entry["command"])
	}
}

func TestRegister_PreservesOtherEntries(t *testing.T) {
	h := fakeHost(t, "fake")
	pre := map[string]any{
		"mcpServers": map[string]any{
			"other-server": map[string]any{"command": "/usr/local/bin/other"},
		},
		"unrelated": "data",
	}
	data, _ := json.Marshal(pre)
	if err := os.WriteFile(h.ConfigPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := h.Register("/usr/local/bin/watchdog-mcp"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	data, _ = os.ReadFile(h.ConfigPath())
	var cfg map[string]any
	_ = json.Unmarshal(data, &cfg)
	servers := cfg["mcpServers"].(map[string]any)
	if _, ok := servers["other-server"]; !ok {
		t.Error("Register clobbered other-server entry")
	}
	if _, ok := servers["watchdog"]; !ok {
		t.Error("Register did not add watchdog entry")
	}
	if cfg["unrelated"] != "data" {
		t.Errorf("unrelated key lost: %v", cfg["unrelated"])
	}
}

func TestRegister_Idempotent(t *testing.T) {
	h := fakeHost(t, "fake")
	exec := "/usr/local/bin/watchdog-mcp"
	if err := h.Register(exec); err != nil {
		t.Fatal(err)
	}
	// Second call should overwrite the entry, not duplicate or fail.
	if err := h.Register(exec); err != nil {
		t.Fatalf("second Register: %v", err)
	}
	data, _ := os.ReadFile(h.ConfigPath())
	var cfg map[string]any
	_ = json.Unmarshal(data, &cfg)
	servers := cfg["mcpServers"].(map[string]any)
	if len(servers) != 1 {
		t.Errorf("servers count = %d, want 1: %v", len(servers), servers)
	}
}

func TestUnregister_RemovesEntryAndKeepsOthers(t *testing.T) {
	h := fakeHost(t, "fake")
	pre := map[string]any{
		"mcpServers": map[string]any{
			"other-server": map[string]any{"command": "/x"},
			"watchdog":     map[string]any{"command": "/y"},
		},
	}
	data, _ := json.Marshal(pre)
	if err := os.WriteFile(h.ConfigPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := h.Unregister(); err != nil {
		t.Fatal(err)
	}
	if h.IsRegistered() {
		t.Error("still registered after Unregister")
	}

	data, _ = os.ReadFile(h.ConfigPath())
	var cfg map[string]any
	_ = json.Unmarshal(data, &cfg)
	servers := cfg["mcpServers"].(map[string]any)
	if _, ok := servers["other-server"]; !ok {
		t.Error("Unregister clobbered other-server")
	}
	if _, ok := servers["watchdog"]; ok {
		t.Error("watchdog entry not removed")
	}
}

func TestUnregister_NoopWhenFileMissing(t *testing.T) {
	h := fakeHost(t, "fake")
	// No file on disk.
	if err := h.Unregister(); err != nil {
		t.Errorf("Unregister on missing file = %v, want nil", err)
	}
}

func TestUnregister_NoopWhenEntryAbsent(t *testing.T) {
	h := fakeHost(t, "fake")
	pre := map[string]any{
		"mcpServers": map[string]any{
			"only-other": map[string]any{"command": "/x"},
		},
	}
	data, _ := json.Marshal(pre)
	if err := os.WriteFile(h.ConfigPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.Unregister(); err != nil {
		t.Errorf("Unregister with no entry = %v", err)
	}
	// Other entry still there.
	data, _ = os.ReadFile(h.ConfigPath())
	var cfg map[string]any
	_ = json.Unmarshal(data, &cfg)
	servers := cfg["mcpServers"].(map[string]any)
	if _, ok := servers["only-other"]; !ok {
		t.Error("Unregister wiped unrelated entries")
	}
}

func TestRegister_AtomicNoTempLeftOver(t *testing.T) {
	h := fakeHost(t, "fake")
	if err := h.Register("/usr/local/bin/watchdog-mcp"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(h.ConfigPath()))
	var tmps []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			tmps = append(tmps, e.Name())
		}
	}
	if len(tmps) != 0 {
		t.Errorf("leftover .tmp files: %v", tmps)
	}
}

func TestByName(t *testing.T) {
	if h := ByName("claude-desktop"); h == nil || h.Name() != "claude-desktop" {
		t.Errorf("ByName(claude-desktop) = %v", h)
	}
	if h := ByName("cursor"); h == nil || h.Name() != "cursor" {
		t.Errorf("ByName(cursor) = %v", h)
	}
	if h := ByName("not-a-host"); h != nil {
		t.Errorf("ByName(garbage) = %v, want nil", h)
	}
}

func TestAll_ListsKnownHosts(t *testing.T) {
	got := All()
	names := []string{}
	for _, h := range got {
		names = append(names, h.Name())
	}
	want := []string{"claude-desktop", "cursor"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("All names = %v, want %v", names, want)
	}
}
