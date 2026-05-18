package hosts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// EntryName is the key under the host's server map we own. Stable so
// unregister can find it.
const EntryName = "watchdog"

// configFormat selects on-disk encoding. Most hosts are JSON; Continue's
// newer setups use YAML. Both round-trip through map[string]any.
type configFormat int

const (
	formatJSON configFormat = iota
	formatYAML
)

// entryBuilder returns the value to store under the host's server map
// at key=EntryName. Different hosts demand different shapes — Claude
// Desktop / Cursor / Cline want {command, args}; Zed wants
// {source, command:{path, args}}.
type entryBuilder func(execPath string) any

// standardMCPEntry is the canonical {command, args} shape used by
// every host that follows the mcpServers convention.
func standardMCPEntry(execPath string) any {
	return map[string]any{
		"command": execPath,
		"args":    []string{},
	}
}

// schemaHost implements Host for any single-key on-disk config —
// {<serverKey>: {<EntryName>: <entry>}}. Hosts differ only by
// configPath, serverKey, format, and entry shape.
type schemaHost struct {
	name       string
	configPath string
	serverKey  string
	format     configFormat
	entryShape entryBuilder
}

func (h *schemaHost) Name() string       { return h.name }
func (h *schemaHost) ConfigPath() string { return h.configPath }

// Exists treats the config-file's parent directory as the install
// signal — the dir is created by the host app on first launch. A
// missing config file inside an existing dir is OK; Register will
// create the file.
func (h *schemaHost) Exists() bool {
	dir := filepath.Dir(h.configPath)
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

// IsRegistered reports whether the watchdog entry already lives in
// the config's server map. Safe to call when the file doesn't exist
// (returns false).
func (h *schemaHost) IsRegistered() bool {
	servers, err := h.loadServers()
	if err != nil {
		return false
	}
	_, ok := servers[EntryName]
	return ok
}

// Register adds (or replaces) the watchdog entry under serverKey and
// writes the config atomically. Creates the config file if missing.
//
// execPath should be an absolute path to the watchdog-mcp binary, so
// registration survives PATH changes. Caller is responsible for
// supplying it (the cmd layer resolves via exec.LookPath).
func (h *schemaHost) Register(execPath string) error {
	if execPath == "" {
		return errors.New("hosts: empty execPath")
	}
	cfg, err := h.loadConfig()
	if err != nil {
		// File missing → start from an empty config; saveConfig will
		// create the file. Any other error is propagated.
		if !os.IsNotExist(err) {
			return err
		}
		cfg = map[string]any{}
	}
	servers, _ := cfg[h.serverKey].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	build := h.entryShape
	if build == nil {
		build = standardMCPEntry
	}
	servers[EntryName] = build(execPath)
	cfg[h.serverKey] = servers
	return h.saveConfig(cfg)
}

// Unregister removes the watchdog entry from serverKey. Idempotent.
func (h *schemaHost) Unregister() error {
	cfg, err := h.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	servers, _ := cfg[h.serverKey].(map[string]any)
	if servers == nil {
		return nil
	}
	if _, ok := servers[EntryName]; !ok {
		return nil
	}
	delete(servers, EntryName)
	cfg[h.serverKey] = servers
	return h.saveConfig(cfg)
}

func (h *schemaHost) loadServers() (map[string]any, error) {
	cfg, err := h.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	servers, _ := cfg[h.serverKey].(map[string]any)
	if servers == nil {
		return map[string]any{}, nil
	}
	return servers, nil
}

// loadConfig reads and decodes the config file in whichever format
// the host uses. Returns os.IsNotExist on missing file so callers
// can distinguish.
func (h *schemaHost) loadConfig() (map[string]any, error) {
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		return nil, err
	}
	cfg, err := decodeConfig(data, h.format)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

// saveConfig atomically writes cfg to h.configPath via temp + rename.
// Creates the parent dir if missing.
func (h *schemaHost) saveConfig(cfg map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(h.configPath), 0o755); err != nil {
		return err
	}
	data, err := encodeConfig(cfg, h.format)
	if err != nil {
		return err
	}
	tmp := h.configPath + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, h.configPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// decodeConfig parses raw bytes into a generic map. YAML's decoder
// emits map[interface{}]interface{} for nested maps; we recursively
// normalize to map[string]any so the rest of the package can treat
// every host uniformly.
func decodeConfig(data []byte, fmt configFormat) (map[string]any, error) {
	switch fmt {
	case formatYAML:
		var raw any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		v := normalizeYAML(raw)
		m, _ := v.(map[string]any)
		return m, nil
	default:
		var cfg map[string]any
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
}

// encodeConfig serializes cfg in whichever format the host uses. JSON
// gets a 2-space indent + trailing newline; YAML gets yaml.v3's
// default 4-space block style.
func encodeConfig(cfg map[string]any, fmt configFormat) ([]byte, error) {
	switch fmt {
	case formatYAML:
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		return data, nil
	default:
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	}
}

// normalizeYAML walks the YAML decoder's output and converts every
// map[interface{}]interface{} into map[string]any so JSON-style
// downstream code works without per-type branching.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			out[ks] = normalizeYAML(val)
		}
		return out
	case map[string]any:
		for k, val := range x {
			x[k] = normalizeYAML(val)
		}
		return x
	case []any:
		for i, item := range x {
			x[i] = normalizeYAML(item)
		}
		return x
	}
	return v
}

// formatForPath chooses an encoder based on filename extension. Used
// by hosts whose config can be either JSON or YAML (Continue).
func formatForPath(path string) configFormat {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".yaml" || ext == ".yml" {
		return formatYAML
	}
	return formatJSON
}
