package projectscan

import (
	"path/filepath"
	"time"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/ledger"
	"github.com/Maxlemore97/watchdog/internal/log"
	"github.com/Maxlemore97/watchdog/internal/policy"
	"github.com/Maxlemore97/watchdog/internal/preflight"
	"github.com/Maxlemore97/watchdog/internal/types"
)

// ScanOpts controls a project scan.
type ScanOpts struct {
	Root           string
	MaxDepth       int
	SkipGitignored bool
	IncludeDev     bool // currently always-on at parse time; reserved for future filtering
	PackagesOnly   bool
	PluginsOnly    bool
	BudgetSeconds  float64
	Mode           string // forwarded to preflight; default "both"
}

// PackagesResult mirrors a preflight.Result for the dep walk.
type PackagesResult struct {
	Verdict  string             `json:"verdict"`
	Reason   string             `json:"reason"`
	Scanned  int                `json:"scanned"`
	Findings []map[string]any   `json:"findings"`
	Notes    []string           `json:"notes,omitempty"`
	Packages []map[string]any   `json:"packages,omitempty"`
}

// PluginsResult collects per-plugin analyzer verdicts plus an
// aggregate worst-verdict across the set.
type PluginsResult struct {
	Verdict  string             `json:"verdict"`
	Scanned  int                `json:"scanned"`
	Findings []map[string]any   `json:"findings"`
}

// Result is the top-level shape watchdog-scan project emits.
type Result struct {
	Root      string         `json:"root"`
	Packages  PackagesResult `json:"packages"`
	Plugins   PluginsResult  `json:"plugins"`
	AgentDocs []string       `json:"agent_docs,omitempty"`
	Notes     []string       `json:"notes,omitempty"`
	Verdict   string         `json:"verdict"`
	ElapsedMs int64          `json:"elapsed_ms"`
}

// Run executes a project scan end-to-end.
func Run(opts ScanOpts) (*Result, error) {
	start := time.Now()
	disc, err := Walk(opts.Root, WalkOpts{MaxDepth: opts.MaxDepth, SkipGitignored: opts.SkipGitignored})
	if err != nil {
		return nil, err
	}
	r := &Result{
		Root:      mustAbs(opts.Root),
		AgentDocs: disc.AgentDocs,
		Notes:     append([]string{}, disc.Notes...),
	}

	if !opts.PluginsOnly {
		r.Packages = scanPackages(disc.LockfilePaths, opts)
	}
	if !opts.PackagesOnly {
		r.Plugins = scanPlugins(disc.PluginRoots)
	}

	r.Verdict = policy.WorstVerdict([]string{r.Packages.Verdict, r.Plugins.Verdict})
	if r.Verdict == "" {
		// Both phases skipped or no inputs → allow.
		r.Verdict = "allow"
	}
	r.ElapsedMs = time.Since(start).Milliseconds()

	log.Event("projectscan_completed", map[string]any{
		"root":              r.Root,
		"verdict":           r.Verdict,
		"packages_scanned":  r.Packages.Scanned,
		"plugins_scanned":   r.Plugins.Scanned,
		"elapsed_ms":        r.ElapsedMs,
	})
	return r, nil
}

func scanPackages(lockfiles []string, opts ScanOpts) PackagesResult {
	var pkgs []types.Package
	notes := []string{}
	for _, path := range lockfiles {
		parsed, lockNotes, err := parseLockfile(path)
		if err != nil {
			notes = append(notes, "parse failed: "+path+": "+err.Error())
			continue
		}
		notes = append(notes, lockNotes...)
		pkgs = append(pkgs, parsed...)
	}
	pkgs = dedupePackages(pkgs)
	if len(pkgs) == 0 {
		return PackagesResult{
			Verdict: "allow",
			Reason:  "no lockfiles found or all empty",
			Notes:   notes,
		}
	}
	mode := opts.Mode
	if mode == "" {
		mode = "both"
	}
	pre := preflight.Packages(pkgs, nil, preflight.Options{
		Mode:          mode,
		BudgetSeconds: opts.BudgetSeconds,
	})
	return PackagesResult{
		Verdict:  pre.Verdict,
		Reason:   pre.Reason,
		Scanned:  len(pkgs),
		Findings: pre.Findings,
		Notes:    append(notes, pre.Notes...),
		Packages: pre.Packages,
	}
}

func scanPlugins(roots []string) PluginsResult {
	out := PluginsResult{Findings: []map[string]any{}}
	verdicts := make([]string, 0, len(roots))
	for _, dir := range roots {
		name := filepath.Base(dir)
		hash := ledger.ContentHash(dir)
		v := analyzer.AnalyzeLocalPlugin(name, dir, hash)
		out.Scanned++
		verdict, _ := v["verdict"].(string)
		if verdict == "" {
			verdict = "ask"
		}
		verdicts = append(verdicts, verdict)
		finding := map[string]any{
			"name": name,
			"path": dir,
		}
		for k, val := range v {
			finding[k] = val
		}
		out.Findings = append(out.Findings, finding)
	}
	out.Verdict = policy.WorstVerdict(verdicts)
	if out.Verdict == "" {
		out.Verdict = "allow"
	}
	return out
}

func dedupePackages(in []types.Package) []types.Package {
	seen := map[string]bool{}
	out := make([]types.Package, 0, len(in))
	for _, p := range in {
		k := p.Ecosystem + "|" + p.Name + "|" + p.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}
