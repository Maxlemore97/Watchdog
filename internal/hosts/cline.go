package hosts

import (
	"os"
	"path/filepath"
	"runtime"
)

// NewCline returns a Host for the Cline VS Code extension. Cline
// stores its MCP server config in the extension's globalStorage area
// inside VS Code's user-data directory. Schema is the standard
// `mcpServers` JSON.
//
// Per-OS path:
//
//	macOS:   ~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
//	Linux:   $XDG_CONFIG_HOME/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
//	         (defaults to ~/.config/Code/…)
//	Windows: %APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json
func NewCline() Host {
	return &schemaHost{
		name:       "cline",
		configPath: clineConfigPath(),
		serverKey:  "mcpServers",
		format:     formatJSON,
		entryShape: standardMCPEntry,
	}
}

func clineConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	rel := filepath.Join(
		"Code", "User", "globalStorage",
		"saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json",
	)
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", rel)
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, rel)
	default:
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		return filepath.Join(xdg, rel)
	}
}
