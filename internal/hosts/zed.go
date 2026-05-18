package hosts

import (
	"os"
	"path/filepath"
	"runtime"
)

// NewZed returns a Host for the Zed editor. Zed differs from the
// other MCP-aware hosts in two ways:
//
//  1. The server map is named `context_servers`, not `mcpServers`.
//  2. Each entry uses {source:"custom", command:{path, args}} —
//     not the flat {command, args} shape.
//
// Zed config path:
//
//	macOS/Linux: $XDG_CONFIG_HOME/zed/settings.json (defaults to ~/.config/zed/…)
//	Windows:     %APPDATA%/Zed/settings.json
func NewZed() Host {
	return &schemaHost{
		name:       "zed",
		configPath: zedConfigPath(),
		serverKey:  "context_servers",
		format:     formatJSON,
		entryShape: zedEntry,
	}
}

func zedConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Zed", "settings.json")
	default:
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		return filepath.Join(xdg, "zed", "settings.json")
	}
}

// zedEntry builds Zed's context_servers entry value:
//
//	{
//	  "source": "custom",
//	  "command": { "path": "<execPath>", "args": [] }
//	}
//
// Distinct from standardMCPEntry because Zed nests command/args under
// a "command" object instead of using them as siblings.
func zedEntry(execPath string) any {
	return map[string]any{
		"source": "custom",
		"command": map[string]any{
			"path": execPath,
			"args": []string{},
		},
	}
}
