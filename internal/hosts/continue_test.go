package hosts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// fakeContinue builds a Continue-like schemaHost backed by a temp
// config file in the requested format.
func fakeContinue(t *testing.T, basename string) *schemaHost {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, basename)
	return &schemaHost{
		name:       "continue",
		configPath: path,
		serverKey:  "mcpServers",
		format:     formatForPath(path),
		entryShape: standardMCPEntry,
	}
}

func TestContinue_YAMLRoundTrip(t *testing.T) {
	h := fakeContinue(t, "config.yaml")
	// Seed with a pre-existing mcpServers entry and an unrelated key.
	pre := "models:\n  - name: claude\nmcpServers:\n  other:\n    command: /usr/bin/other\n"
	if err := os.WriteFile(h.ConfigPath(), []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := h.Register("/abs/watchdog-mcp"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	data, err := os.ReadFile(h.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	// Output must remain valid YAML.
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("post-register YAML invalid: %v\nraw: %s", err, data)
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		t.Fatalf("mcpServers missing after register: %v", cfg)
	}
	if _, ok := servers["watchdog"]; !ok {
		t.Errorf("watchdog entry missing: %v", servers)
	}
	if _, ok := servers["other"]; !ok {
		t.Errorf("Register clobbered other entry: %v", servers)
	}
	if _, ok := cfg["models"]; !ok {
		t.Errorf("unrelated key 'models' lost: %v", cfg)
	}
}

func TestContinue_JSONFallbackWhenNoYAML(t *testing.T) {
	// Confirm the format is JSON when given a .json file.
	h := fakeContinue(t, "config.json")
	if h.format != formatJSON {
		t.Errorf("format = %v, want JSON", h.format)
	}
	if err := h.Register("/abs/watchdog-mcp"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.ConfigPath())
	// JSON path should produce valid JSON with 2-space indent + trailing newline.
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("JSON output missing trailing newline")
	}
	if !strings.Contains(string(data), "\"mcpServers\"") {
		t.Errorf("JSON output missing mcpServers key:\n%s", data)
	}
}

func TestPickContinueConfig_PrefersYAMLWhenPresent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome) // os.UserHomeDir() reads this on Windows
	base := filepath.Join(tmpHome, ".continue")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create both — yaml should win.
	if err := os.WriteFile(filepath.Join(base, "config.yaml"), []byte("mcpServers:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, format := pickContinueConfig()
	if !strings.HasSuffix(path, "config.yaml") {
		t.Errorf("path = %q, want config.yaml", path)
	}
	if format != formatYAML {
		t.Errorf("format = %v, want YAML", format)
	}
}

func TestPickContinueConfig_DefaultsToJSONWhenNothingPresent(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome) // os.UserHomeDir() reads this on Windows
	path, format := pickContinueConfig()
	if !strings.HasSuffix(path, "config.json") {
		t.Errorf("path = %q, want config.json", path)
	}
	if format != formatJSON {
		t.Errorf("format = %v, want JSON", format)
	}
}
