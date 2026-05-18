package hosts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeZed builds a Zed-like schemaHost over a temp config so we can
// exercise the context_servers + nested-command-shape branches
// without depending on the OS-specific Zed config path.
func fakeZed(t *testing.T) *schemaHost {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &schemaHost{
		name:       "zed",
		configPath: filepath.Join(dir, "settings.json"),
		serverKey:  "context_servers",
		format:     formatJSON,
		entryShape: zedEntry,
	}
}

func TestZed_RegisterEmitsContextServersWithNestedCommand(t *testing.T) {
	h := fakeZed(t)
	if err := h.Register("/abs/path/to/watchdog-mcp"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	data, err := os.ReadFile(h.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	servers, ok := cfg["context_servers"].(map[string]any)
	if !ok {
		t.Fatalf("context_servers missing or wrong type: %v", cfg)
	}
	entry, ok := servers["watchdog"].(map[string]any)
	if !ok {
		t.Fatalf("watchdog entry missing or wrong shape: %v", servers)
	}
	if entry["source"] != "custom" {
		t.Errorf("source = %v, want custom", entry["source"])
	}
	command, ok := entry["command"].(map[string]any)
	if !ok {
		t.Fatalf("command nested object missing: %v", entry)
	}
	if command["path"] != "/abs/path/to/watchdog-mcp" {
		t.Errorf("command.path = %v", command["path"])
	}
}

func TestZed_PreservesOtherContextServers(t *testing.T) {
	h := fakeZed(t)
	pre := map[string]any{
		"context_servers": map[string]any{
			"other": map[string]any{"command": map[string]any{"path": "/x"}},
		},
		"theme": "dark",
	}
	data, _ := json.Marshal(pre)
	if err := os.WriteFile(h.ConfigPath(), data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := h.Register("/abs/watchdog-mcp"); err != nil {
		t.Fatal(err)
	}

	data, _ = os.ReadFile(h.ConfigPath())
	var cfg map[string]any
	_ = json.Unmarshal(data, &cfg)
	servers := cfg["context_servers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Error("Register clobbered other context_servers entry")
	}
	if _, ok := servers["watchdog"]; !ok {
		t.Error("watchdog entry not added")
	}
	if cfg["theme"] != "dark" {
		t.Errorf("unrelated theme key lost: %v", cfg["theme"])
	}
}

func TestZed_UnregisterLeavesOthersAlone(t *testing.T) {
	h := fakeZed(t)
	_ = h.Register("/abs/watchdog-mcp")
	// Add a sibling entry, then unregister watchdog.
	data, _ := os.ReadFile(h.ConfigPath())
	var cfg map[string]any
	_ = json.Unmarshal(data, &cfg)
	cfg["context_servers"].(map[string]any)["sibling"] = map[string]any{
		"command": map[string]any{"path": "/y"},
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(h.ConfigPath(), out, 0o644)

	if err := h.Unregister(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(h.ConfigPath())
	_ = json.Unmarshal(data, &cfg)
	servers := cfg["context_servers"].(map[string]any)
	if _, ok := servers["watchdog"]; ok {
		t.Error("watchdog still present after Unregister")
	}
	if _, ok := servers["sibling"]; !ok {
		t.Error("sibling entry lost")
	}
}
