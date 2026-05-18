package hosts

import (
	"os"
	"path/filepath"
)

// NewContinue returns a Host for the Continue.dev assistant. Continue
// supports two config flavours: the older `~/.continue/config.json`
// and the newer `~/.continue/config.yaml`. We detect which file
// actually exists and use that format. If neither file is on disk yet,
// default to JSON — Register will create the file.
//
// Caveat: YAML round-trip via gopkg.in/yaml.v3 does not preserve
// comments or blank lines. Users whose config.yaml has annotations
// they care about should hand-edit instead. Documented in the
// `register --host=continue` help output.
func NewContinue() Host {
	configPath, format := pickContinueConfig()
	return &schemaHost{
		name:       "continue",
		configPath: configPath,
		serverKey:  "mcpServers",
		format:     format,
		entryShape: standardMCPEntry,
	}
}

// pickContinueConfig returns the first existing config file path
// (yaml > yml > json) or, if none exist, the default JSON path.
func pickContinueConfig() (string, configFormat) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", formatJSON
	}
	base := filepath.Join(home, ".continue")
	for _, name := range []string{"config.yaml", "config.yml", "config.json"} {
		p := filepath.Join(base, name)
		if _, err := os.Stat(p); err == nil {
			return p, formatForPath(p)
		}
	}
	// Default to JSON if Continue hasn't been launched yet — matches
	// what a fresh install would create.
	return filepath.Join(base, "config.json"), formatJSON
}
