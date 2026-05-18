package hosts

import (
	"os"
	"path/filepath"
	"runtime"
)

// NewClaudeDesktop returns a Host for Anthropic's Claude Desktop app.
// Config location per OS:
//
//	macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json
//	Linux:   $XDG_CONFIG_HOME/Claude/claude_desktop_config.json
//	         (defaults to ~/.config/Claude/…)
//	Windows: %APPDATA%/Claude/claude_desktop_config.json
//
// The schema is `mcpServers` so this delegates to mcpServersHost.
func NewClaudeDesktop() Host {
	return &mcpServersHost{
		name:       "claude-desktop",
		configPath: claudeDesktopConfigPath(),
	}
}

func claudeDesktopConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Claude", "claude_desktop_config.json")
	default: // linux + others
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		return filepath.Join(xdg, "Claude", "claude_desktop_config.json")
	}
}
