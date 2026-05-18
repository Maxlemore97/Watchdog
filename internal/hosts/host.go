// Package hosts registers watchdog-mcp as an MCP server in the
// config files of detected MCP-aware hosts (Claude Desktop, Cursor,
// …). This is what turns "we have an MCP server" into "the user's
// agents are actually wired to it."
//
// Why a separate package: each host owns a config-file schema. Some
// share `mcpServers` (Claude Desktop, Cursor); others use different
// keys (Zed → `context_servers`, Continue → its own format). Keeping
// them behind one interface lets `watchdog-shim register/unregister`
// treat them uniformly and the doctor report on each.
//
// Threat-model note: registering with a host is user-visible state.
// The installer does NOT auto-register; the user runs
// `watchdog-shim register` explicitly. Atomic writes preserve other
// `mcpServers` entries so we never clobber a user's existing MCP
// setup.
package hosts

// Host is one MCP-aware application whose config we can read and
// modify.
type Host interface {
	// Name is a human-readable identifier used in CLI output and
	// audit logs. Lowercase, hyphen-separated (e.g., "claude-desktop").
	Name() string
	// ConfigPath returns the absolute path to the host's config file.
	// The file may not exist yet; we resolve the path even when not
	// installed so the doctor can tell the user where it would land.
	ConfigPath() string
	// Exists reports whether the host appears to be installed on
	// this machine. Used by Detect; implementations decide what
	// "installed" means (config-dir presence is the usual signal).
	Exists() bool
	// IsRegistered reports whether watchdog-mcp is already listed in
	// this host's config.
	IsRegistered() bool
	// Register adds watchdog-mcp to this host's config. Atomic;
	// idempotent. Preserves other entries.
	Register(execPath string) error
	// Unregister removes watchdog-mcp from this host's config.
	// Atomic; idempotent. Leaves other entries intact.
	Unregister() error
}

// All returns every host adapter the binary knows about, in display
// order. Detect filters this list to those present on disk.
func All() []Host {
	return []Host{
		NewClaudeDesktop(),
		NewCursor(),
	}
}

// Detect returns the subset of All() whose Exists() reports true.
// Order is preserved from All so the doctor output is stable.
func Detect() []Host {
	var out []Host
	for _, h := range All() {
		if h.Exists() {
			out = append(out, h)
		}
	}
	return out
}

// ByName looks up a host by its Name(). Returns nil if no match.
func ByName(name string) Host {
	for _, h := range All() {
		if h.Name() == name {
			return h
		}
	}
	return nil
}
