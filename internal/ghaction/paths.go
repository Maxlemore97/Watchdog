package ghaction

import (
	"path/filepath"
	"strings"
)

// PluginAssetDirs marks plugin-asset directories. A changed file is
// interesting iff one of these appears as a path segment AND the
// per-segment file-type rule matches.
var PluginAssetDirs = map[string]bool{
	".claude-plugin": true, "skills": true, "commands": true, "hooks": true,
}

// IsPluginAsset applies the per-directory rules:
//   - **/.claude-plugin/**     anything
//   - **/skills/**/SKILL.md    only SKILL.md
//   - **/commands/**.md        only .md files
//   - **/hooks/**              anything
func IsPluginAsset(p string) bool {
	parts := strings.Split(filepath.ToSlash(p), "/")
	for i, seg := range parts {
		rest := parts[i+1:]
		if len(rest) == 0 {
			continue
		}
		switch seg {
		case ".claude-plugin":
			return true
		case "hooks":
			return true
		case "commands":
			return strings.HasSuffix(p, ".md")
		case "skills":
			return filepath.Base(p) == "SKILL.md"
		}
	}
	return false
}

// PluginRootFor returns the directory above the first plugin-asset
// segment. Empty string means the asset lives at the repo root.
func PluginRootFor(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	for i, seg := range parts {
		if PluginAssetDirs[seg] {
			if i == 0 {
				return ""
			}
			return strings.Join(parts[:i], "/")
		}
	}
	return ""
}

// GroupByPlugin buckets a list of paths under their plugin roots.
// Non-plugin-asset paths are dropped.
func GroupByPlugin(paths []string) map[string][]string {
	out := map[string][]string{}
	for _, p := range paths {
		if !IsPluginAsset(p) {
			continue
		}
		out[PluginRootFor(p)] = append(out[PluginRootFor(p)], p)
	}
	return out
}
