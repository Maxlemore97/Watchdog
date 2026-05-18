package hosts

import (
	"os"
	"path/filepath"
)

// NewCursor returns a Host for the Cursor editor's MCP config.
// Cursor's global MCP config is at ~/.cursor/mcp.json on all OSes;
// schema is `mcpServers`.
func NewCursor() Host {
	return &mcpServersHost{
		name:       "cursor",
		configPath: cursorConfigPath(),
	}
}

func cursorConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cursor", "mcp.json")
}
