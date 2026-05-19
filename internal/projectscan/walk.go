package projectscan

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// knownLockfiles is the set of basenames the walker collects for
// dependency analysis. Lockfile-only: bare manifests (package.json,
// Cargo.toml, requirements.txt) are recorded as notes but not
// parsed — see parseLockfile.
var knownLockfiles = map[string]bool{
	"package-lock.json":  true,
	"pnpm-lock.yaml":     true,
	"pipfile.lock":       true,
	"poetry.lock":        true,
	"uv.lock":            true,
	"cargo.lock":         true,
	"gemfile.lock":       true,
	"composer.lock":      true,
	"go.mod":             true,
	"packages.lock.json": true,
}

// unsupportedLockfiles surface as walk notes so the user knows
// detection happened but parsing wasn't attempted (custom formats,
// dropped from v1 scope).
var unsupportedLockfiles = map[string]bool{
	"yarn.lock": true,
}

// skipDirNames are pruned at every level. node_modules / vendor /
// venv all carry resolved sources that don't represent declared
// deps (and a lockfile sits at the project root anyway); .git is
// noise; build outputs are noise.
var skipDirNames = map[string]bool{
	"node_modules":       true,
	"vendor":             true,
	".git":               true,
	".svn":               true,
	".hg":                true,
	"venv":               true,
	".venv":              true,
	"__pycache__":        true,
	"target":             true, // cargo, gradle
	"build":              true,
	"dist":               true,
	".tox":               true,
	".pytest_cache":      true,
	".mypy_cache":        true,
	"bin":                true,
	"obj":                true,
}

// WalkOpts controls discovery.
type WalkOpts struct {
	MaxDepth        int
	SkipGitignored  bool // honor a top-level .gitignore (best-effort, prefix-match)
}

// Discovery is the walker's output. LockfilePaths are absolute
// paths the orchestrator hands to parseLockfile. PluginRoots are
// directories the orchestrator hands to analyzer.AnalyzeLocalPlugin.
// Notes carry non-fatal observations the user should see in the
// report (unsupported lockfile detected, dir skipped, etc.).
type Discovery struct {
	LockfilePaths []string
	PluginRoots   []string
	AgentDocs     []string // standalone CLAUDE.md / agents.md files
	Notes         []string
}

// Walk traverses root depth-first, depth-bounded, pruning the
// skipDirNames set. Returns a deterministic discovery (sorted output)
// so JSON output is stable for diffing across runs.
func Walk(root string, opts WalkOpts) (*Discovery, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 8
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	disc := &Discovery{}
	pluginSet := map[string]bool{}

	gitignore, _ := loadGitignore(absRoot, opts.SkipGitignored)

	err = filepath.WalkDir(absRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(absRoot, p)
		depth := strings.Count(rel, string(filepath.Separator))
		if d.IsDir() {
			name := strings.ToLower(d.Name())
			if name != "." && skipDirNames[name] {
				return filepath.SkipDir
			}
			if depth > opts.MaxDepth {
				return filepath.SkipDir
			}
			if gitignore != nil && gitignore.matches(rel) {
				return filepath.SkipDir
			}
			// Recognize plugin roots: a directory holding any of the
			// pluginInterestingDirs siblings or a .claude-plugin/ child.
			if isPluginRoot(p) && !pluginSet[p] {
				pluginSet[p] = true
				disc.PluginRoots = append(disc.PluginRoots, p)
				// Stop descending: the plugin's own subtree
				// (.claude-plugin, skills, commands, hooks) is one
				// scan unit handed to AnalyzeLocalPlugin, not a set
				// of nested plugins.
				return filepath.SkipDir
			}
			return nil
		}
		base := strings.ToLower(d.Name())
		if knownLockfiles[base] {
			disc.LockfilePaths = append(disc.LockfilePaths, p)
			return nil
		}
		if unsupportedLockfiles[base] {
			disc.Notes = append(disc.Notes, "unsupported lockfile (not parsed): "+rel)
			return nil
		}
		if base == "claude.md" || base == "agents.md" {
			disc.AgentDocs = append(disc.AgentDocs, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(disc.LockfilePaths)
	sort.Strings(disc.PluginRoots)
	sort.Strings(disc.AgentDocs)
	return disc, nil
}

// isPluginRoot recognizes a directory as a plugin / skill / command
// host based on the presence of any of the expected agent-extension
// children. Mirrors fetchers.pluginInterestingDirs without importing
// it (cycle: fetchers already imports types, projectscan would have
// to import fetchers for one slice).
func isPluginRoot(dir string) bool {
	for _, child := range []string{".claude-plugin", "skills", "commands", "hooks"} {
		st, err := os.Stat(filepath.Join(dir, child))
		if err == nil && st.IsDir() {
			return true
		}
	}
	// Host-specific singletons.
	for _, child := range []string{"plugin.json"} {
		st, err := os.Stat(filepath.Join(dir, child))
		if err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// gitignoreMatcher is a tiny prefix matcher — enough to honor the
// common cases (`build/`, `dist/`, `target/`, `node_modules/`).
// Wildcards are NOT supported; pulling in a full gitignore impl is
// out of scope for v1. Most useful patterns are literal directory
// prefixes anyway, and skipDirNames already covers the universals.
type gitignoreMatcher struct {
	prefixes []string
}

func loadGitignore(root string, enabled bool) (*gitignoreMatcher, error) {
	if !enabled {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return nil, err
	}
	m := &gitignoreMatcher{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "*") || strings.HasPrefix(line, "!") {
			continue
		}
		m.prefixes = append(m.prefixes, strings.TrimSuffix(line, "/"))
	}
	return m, nil
}

func (m *gitignoreMatcher) matches(rel string) bool {
	if m == nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, p := range m.prefixes {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}
