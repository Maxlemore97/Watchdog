package hosts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// NewCodex returns a Host for OpenAI's Codex CLI. Its config is TOML
// ($CODEX_HOME/config.toml, default ~/.codex/config.toml) with one
// table per server: [mcp_servers.<name>].
//
// Unlike the JSON hosts, the file is edited as text: re-encoding TOML
// would drop the user's comments and ordering, so Register appends a
// table and Unregister removes exactly that table.
func NewCodex() Host {
	return &codexHost{configPath: codexConfigPath()}
}

type codexHost struct{ configPath string }

func codexConfigPath() string {
	if v := os.Getenv("CODEX_HOME"); v != "" {
		return filepath.Join(v, "config.toml")
	}
	return homeJoin(".codex", "config.toml")
}

const codexTable = "[mcp_servers." + EntryName + "]"

func (h *codexHost) Name() string       { return "codex" }
func (h *codexHost) ConfigPath() string { return h.configPath }

func (h *codexHost) Exists() bool {
	st, err := os.Stat(filepath.Dir(h.configPath))
	return err == nil && st.IsDir()
}

func (h *codexHost) IsRegistered() bool {
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		return false
	}
	var cfg struct {
		MCPServers map[string]any `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return false
	}
	_, ok := cfg.MCPServers[EntryName]
	return ok
}

func (h *codexHost) Register(execPath string) error {
	if execPath == "" {
		return errors.New("hosts: empty execPath")
	}
	data, err := os.ReadFile(h.configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Refuse to edit a file that does not parse: appending to broken
	// TOML would only make it worse.
	if len(data) > 0 {
		var probe map[string]any
		if _, err := toml.Decode(string(data), &probe); err != nil {
			return err
		}
	}
	text := removeCodexTable(string(data))
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if text != "" {
		text += "\n"
	}
	text += codexTable + "\ncommand = " + tomlQuote(execPath) + "\nargs = []\n"
	if err := os.MkdirAll(filepath.Dir(h.configPath), 0o700); err != nil {
		return err
	}
	return writeAtomic(h.configPath, []byte(text))
}

func (h *codexHost) Unregister() error {
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	text := removeCodexTable(string(data))
	if text == string(data) {
		return nil
	}
	return writeAtomic(h.configPath, []byte(text))
}

// tomlQuote renders s as a TOML basic string. strconv.Quote is not
// enough: its \\x escapes are not valid TOML.
func tomlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteString(fmt.Sprintf("\\u%04X", r))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// removeCodexTable drops the [mcp_servers.watchdog] table and its
// sub-tables ([mcp_servers.watchdog.env], …), up to the next
// unrelated table header.
func removeCodexTable(text string) string {
	lines := strings.SplitAfter(text, "\n")
	var out []string
	skipping := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			skipping = t == codexTable || strings.HasPrefix(t, "[mcp_servers."+EntryName+".")
		}
		if !skipping {
			out = append(out, l)
		}
	}
	return strings.TrimRight(strings.Join(out, ""), "\n") + func() string {
		if len(out) > 0 {
			return "\n"
		}
		return ""
	}()
}
