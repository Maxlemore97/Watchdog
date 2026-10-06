package hosts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestCodex_RegisterKeepsUserTOML(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CODEX_HOME", dir)
	cfgPath := filepath.Join(dir, "config.toml")
	original := "# my settings\nmodel = \"o4\"\n\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"-y\", \"docs@1.0.0\"]\n"
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewCodex()
	if h.IsRegistered() {
		t.Fatal("registered before Register")
	}
	exe := `C:\Program Files\watchdog "x"\watchdog-mcp.exe`
	if err := h.Register(exe); err != nil {
		t.Fatal(err)
	}
	if err := h.Register(exe); err != nil { // idempotent
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cfgPath)
	text := string(data)
	if !strings.HasPrefix(text, "# my settings\nmodel = \"o4\"") || !strings.Contains(text, "[mcp_servers.docs]") {
		t.Errorf("user content not preserved:\n%s", text)
	}
	if strings.Count(text, codexTable) != 1 {
		t.Errorf("watchdog table should appear once:\n%s", text)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string `toml:"command"`
		} `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(text, &cfg); err != nil {
		t.Fatalf("result is not valid TOML: %v\n%s", err, text)
	}
	if cfg.MCPServers[EntryName].Command != exe {
		t.Errorf("command = %q, want %q", cfg.MCPServers[EntryName].Command, exe)
	}
	if !h.IsRegistered() {
		t.Error("IsRegistered false after Register")
	}
	if err := h.Unregister(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(cfgPath)
	if strings.Contains(string(data), EntryName) || !strings.Contains(string(data), "[mcp_servers.docs]") {
		t.Errorf("Unregister removed too much or too little:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(cfgPath); st.Mode().Perm() != 0o600 {
			t.Errorf("config mode changed to %v", st.Mode().Perm())
		}
	}
}

func TestVSCode_EntryShape(t *testing.T) {
	dir := t.TempDir()
	h := &schemaHost{name: "vscode", configPath: filepath.Join(dir, "mcp.json"), serverKey: "servers", entryShape: vscodeEntry}
	if err := h.Register("/opt/wd/watchdog-mcp"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(h.configPath)
	var cfg map[string]map[string]map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	e := cfg["servers"][EntryName]
	if e["type"] != "stdio" || e["command"] != "/opt/wd/watchdog-mcp" {
		t.Errorf("entry = %v", e)
	}
}

// Register must not widen a user's private config (API keys in env).
func TestRegister_PreservesFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "claude_desktop_config.json")
	if err := os.WriteFile(p, []byte(`{"mcpServers":{"x":{"command":"y","env":{"KEY":"secret"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &schemaHost{name: "t", configPath: p, serverKey: "mcpServers"}
	if err := h.Register("/bin/watchdog-mcp"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode after Register = %v, want 0600", st.Mode().Perm())
	}
}
