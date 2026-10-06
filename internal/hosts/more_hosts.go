package hosts

import (
	"os"
	"path/filepath"
	"runtime"
)

// NewVSCode returns a Host for VS Code's user-level MCP config
// (Copilot agent mode). VS Code keys servers under `servers`, not
// `mcpServers`, and each entry declares its transport type.
//
//	macOS:   ~/Library/Application Support/Code/User/mcp.json
//	Linux:   $XDG_CONFIG_HOME/Code/User/mcp.json
//	Windows: %APPDATA%/Code/User/mcp.json
//
// The file may contain comments (JSONC); Register then refuses rather
// than rewrite it without them.
func NewVSCode() Host {
	return &schemaHost{
		name:       "vscode",
		configPath: vscodeConfigPath(),
		serverKey:  "servers",
		format:     formatJSON,
		entryShape: vscodeEntry,
	}
}

func vscodeEntry(execPath string) any {
	return map[string]any{
		"type":    "stdio",
		"command": execPath,
		"args":    []string{},
	}
}

func vscodeConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json")
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(appData, "Code", "User", "mcp.json")
	default:
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		return filepath.Join(xdg, "Code", "User", "mcp.json")
	}
}

// NewWindsurf returns a Host for Windsurf (Codeium):
// ~/.codeium/windsurf/mcp_config.json, standard `mcpServers`.
func NewWindsurf() Host {
	return &schemaHost{
		name:       "windsurf",
		configPath: homeJoin(".codeium", "windsurf", "mcp_config.json"),
		serverKey:  "mcpServers",
		format:     formatJSON,
		entryShape: standardMCPEntry,
	}
}

// NewGeminiCLI returns a Host for Google's Gemini CLI:
// ~/.gemini/settings.json, standard `mcpServers` next to other
// settings (which Register preserves).
func NewGeminiCLI() Host {
	return &schemaHost{
		name:       "gemini-cli",
		configPath: homeJoin(".gemini", "settings.json"),
		serverKey:  "mcpServers",
		format:     formatJSON,
		entryShape: standardMCPEntry,
	}
}

func homeJoin(parts ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{home}, parts...)...)
}
