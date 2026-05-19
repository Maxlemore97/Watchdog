package projectscan

import (
	"github.com/Maxlemore97/watchdog/internal/ledger"
)

// LocalOpts controls a local-plugin scan.
type LocalOpts struct {
	// ExtraRoots is appended to ledger.PluginDirs(). Useful for
	// pointing the scan at host layouts the env-var resolver does
	// not know about (e.g. a corporate-mandated plugin location).
	ExtraRoots []string
	Format     string // json (default) | text
}

// LocalRoots returns the parent directories the local scan should
// walk. Order: WATCHDOG_PLUGIN_DIRS entries, CLAUDE_PLUGINS_DIR,
// ~/.claude/plugins, then explicit ExtraRoots. ledger.PluginDirs
// already filters to existing directories and dedupes, so the
// returned slice can be fed straight to ledger.Discover.
func LocalRoots(opts LocalOpts) []string {
	roots := ledger.PluginDirs()
	for _, r := range opts.ExtraRoots {
		if r == "" {
			continue
		}
		// Dedup against what PluginDirs already returned. PluginDirs
		// abs-paths every entry; do the same here so equal logical
		// paths collapse.
		dedup := true
		for _, existing := range roots {
			if existing == r {
				dedup = false
				break
			}
		}
		if dedup {
			roots = append(roots, r)
		}
	}
	return roots
}
