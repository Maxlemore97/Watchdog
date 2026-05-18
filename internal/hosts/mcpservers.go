package hosts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

// EntryName is the key under `mcpServers` we own. Stable so
// unregister can find it.
const EntryName = "watchdog"

// mcpServersHost is the shared implementation for hosts whose config
// has the JSON shape:
//
//	{ "mcpServers": { "<name>": { "command": "...", "args": [...] } } }
//
// Used by Claude Desktop, Cursor, and any future host that adopts
// the same schema.
type mcpServersHost struct {
	name       string
	configPath string
}

func (h *mcpServersHost) Name() string       { return h.name }
func (h *mcpServersHost) ConfigPath() string { return h.configPath }

// Exists treats the config-file's parent directory as the install
// signal — the dir is created by the host app on first launch. A
// missing config file inside an existing dir is OK; Register will
// create the file.
func (h *mcpServersHost) Exists() bool {
	dir := filepath.Dir(h.configPath)
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

// IsRegistered reports whether the watchdog entry already lives in
// the config's `mcpServers` map. Safe to call when the file doesn't
// exist (returns false).
func (h *mcpServersHost) IsRegistered() bool {
	servers, err := h.loadServers()
	if err != nil {
		return false
	}
	_, ok := servers[EntryName]
	return ok
}

// Register adds (or replaces) the watchdog entry in mcpServers and
// writes the config atomically. Creates the config file if missing.
//
// execPath should be an absolute path to the watchdog-mcp binary,
// so registration survives PATH changes. Caller is responsible for
// supplying it (the cmd layer resolves via exec.LookPath).
func (h *mcpServersHost) Register(execPath string) error {
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
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers[EntryName] = map[string]any{
		"command": execPath,
		"args":    []string{},
	}
	cfg["mcpServers"] = servers
	return h.saveConfig(cfg)
}

// Unregister removes the watchdog entry from mcpServers. If the
// config doesn't exist, or the entry isn't present, returns nil (op
// is idempotent).
func (h *mcpServersHost) Unregister() error {
	cfg, err := h.loadConfig()
	if err != nil {
		// File doesn't exist → nothing to unregister.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		return nil
	}
	if _, ok := servers[EntryName]; !ok {
		return nil
	}
	delete(servers, EntryName)
	cfg["mcpServers"] = servers
	return h.saveConfig(cfg)
}

// loadServers returns just the mcpServers map; useful for read-only
// inspection. Returns empty map and nil error when the file doesn't
// exist (read-only callers shouldn't care).
func (h *mcpServersHost) loadServers() (map[string]any, error) {
	cfg, err := h.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	servers, _ := cfg["mcpServers"].(map[string]any)
	if servers == nil {
		return map[string]any{}, nil
	}
	return servers, nil
}

// loadConfig reads the JSON config file. Returns os.IsNotExist when
// the file is missing so callers can distinguish.
func (h *mcpServersHost) loadConfig() (map[string]any, error) {
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

// saveConfig atomically writes cfg to h.configPath via temp + rename.
// Creates the parent dir if missing. Preserves 0o644 perms.
func (h *mcpServersHost) saveConfig(cfg map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(h.configPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// Trailing newline matches host-app conventions.
	data = append(data, '\n')
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
