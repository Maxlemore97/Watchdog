// Package preflight aggregates OSV + LLM verdicts for a pre-parsed
// list of packages. Single source of truth for the preflight decision
// shared across all adapters.
//
// Verdict precedence: allow < ask < deny (worst wins). In mode="both"
// an OSV deny short-circuits the LLM pass. A budget cap returns "ask"
// instead of hanging the host. WATCHDOG_MAX_PACKAGES bounds input
// fan-out: a crafted install with too many packages returns "ask"
// without scanning.
package preflight

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/log"
	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/policy"
	"github.com/Maxlemore97/watchdog/internal/types"
)

var ValidModes = map[string]bool{"osv": true, "claude": true, "both": true}

// DefaultMaxPackages: fresh monorepo `npm install` from a lockfile
// commonly produces >20 packages. Raised to 50 so the legitimate
// happy path doesn't trip the ask-on-fan-out guard.
const DefaultMaxPackages = 50

// Injection seams — production points at the real implementations;
// tests swap these out to avoid network and LLM calls. Keep package-
// level so the production call sites stay simple.
//
// osv.Query already returns (vulns, error); preflight uses err to
// trigger the fail-closed branch.
var (
	queryOSV       func(types.Package) ([]map[string]any, error) = osv.Query
	analyzePackage                                               = analyzer.AnalyzePackage
)

// Options tweaks individual preflight calls.
type Options struct {
	Mode              string  // osv / claude / both
	FailClosedVerdict string  // verdict on OSV/analyzer error (default ask)
	BudgetSeconds     float64 // wall-clock cap; <=0 means no cap
}

// Result is what every adapter renders.
type Result struct {
	Mode     string             `json:"mode"`
	Packages []map[string]any   `json:"packages"`
	Notes    []string           `json:"notes"`
	Verdict  string             `json:"verdict"`
	Reason   string             `json:"reason"`
	Findings []map[string]any   `json:"findings"`
}

// Packages runs OSV + LLM analysis on a list of already-parsed
// Packages. Mirror of Python's adapters._shared.preflight.preflight_packages.
func Packages(pkgs []types.Package, notes []string, opts Options) Result {
	mode := opts.Mode
	if !ValidModes[mode] {
		mode = "both"
	}
	fallback := opts.FailClosedVerdict
	if fallback != "allow" && fallback != "deny" && fallback != "ask" {
		fallback = "ask"
	}

	base := Result{
		Mode:     mode,
		Packages: pkgsToDicts(pkgs),
		Notes:    append([]string{}, notes...),
		Findings: []map[string]any{},
	}

	if len(pkgs) == 0 && len(notes) == 0 {
		base.Verdict = "allow"
		base.Reason = "no install command detected"
		return base
	}
	if len(pkgs) == 0 {
		base.Verdict = "ask"
		base.Reason = "unsupported install form: " + joinSemi(notes)
		return base
	}

	maxPkgs := maxPackages()
	if len(pkgs) > maxPkgs {
		base.Verdict = "ask"
		base.Reason = fmt.Sprintf("too many packages for inline scan (%d > %d); raise WATCHDOG_MAX_PACKAGES or split the install", len(pkgs), maxPkgs)
		return base
	}

	var deadline time.Time
	if opts.BudgetSeconds > 0 {
		deadline = time.Now().Add(time.Duration(opts.BudgetSeconds * float64(time.Second)))
	}
	overBudget := func() bool {
		return !deadline.IsZero() && !time.Now().Before(deadline)
	}

	findings := []map[string]any{}
	var decisions []decision
	budgetHit := false
	processedOSV := 0
	processedClaude := 0

	if mode == "osv" || mode == "both" {
		decisions, findings, processedOSV, budgetHit = osvPhase(pkgs, fallback, overBudget, decisions, findings)
	}

	if (mode == "claude" || mode == "both") && !budgetHit && !osvDenied(decisions) {
		decisions, findings, processedClaude, budgetHit = llmPhase(pkgs, fallback, overBudget, decisions, findings)
	}

	if budgetHit {
		scanned := processedClaude
		if processedOSV > scanned {
			scanned = processedOSV
		}
		base.Verdict = "ask"
		base.Reason = fmt.Sprintf("scan budget exceeded after %d/%d packages (budget=%.2fs)",
			scanned, len(pkgs), opts.BudgetSeconds)
		base.Findings = findings
		return base
	}

	if len(decisions) == 0 {
		base.Verdict = "allow"
		base.Reason = fmt.Sprintf("clean (mode=%s, threshold=%s)", mode, osv.MinSeverity())
		base.Findings = findings
		return base
	}

	verdicts := make([]string, len(decisions))
	for i, d := range decisions {
		verdicts[i] = d.Verdict
	}
	worst := policy.WorstVerdict(verdicts)
	var relevant []string
	for _, d := range decisions {
		if d.Verdict == worst {
			relevant = append(relevant, d.Reason)
		}
	}
	if len(relevant) > 5 {
		relevant = relevant[:5]
	}
	reason := joinSemi(relevant)
	if worst == "allow" && len(notes) > 0 {
		reason += "; also: " + joinSemi(notes)
	}
	log.Event("preflight_packages", map[string]any{
		"mode":     mode,
		"verdict":  worst,
		"packages": labels(pkgs),
		"reason":   truncate(reason, 300),
	})
	base.Verdict = worst
	base.Reason = reason
	base.Findings = findings
	return base
}

type decision struct {
	Verdict string
	Reason  string
}

// osvPhase runs OSV.dev queries in parallel and appends one decision
// per package that errors or carries a finding at-or-above threshold.
// Returns updated (decisions, findings, processed-count, budget-hit).
func osvPhase(
	pkgs []types.Package, fallback string, overBudget func() bool,
	decisions []decision, findings []map[string]any,
) ([]decision, []map[string]any, int, bool) {
	osvResults := runOSVParallel(pkgs)
	processed := 0
	for _, r := range osvResults {
		if overBudget() {
			return decisions, findings, processed, true
		}
		processed++
		if r.err != nil {
			decisions = append(decisions, decision{
				Verdict: fallback,
				Reason:  fmt.Sprintf("OSV unreachable for %s: %v", pkgLabel(r.pkg), r.err),
			})
			continue
		}
		if len(r.vulns) == 0 {
			continue
		}
		filtered := osv.FilterBySeverity(r.vulns)
		if len(filtered) == 0 {
			continue
		}
		decisions = append(decisions, decision{
			Verdict: "deny",
			Reason:  fmt.Sprintf("%s -> %s", pkgLabel(r.pkg), osv.Summarize(filtered)),
		})
		ids := make([]string, 0, len(filtered))
		for _, v := range filtered {
			id, _ := v["id"].(string)
			if id == "" {
				id = "?"
			}
			ids = append(ids, id)
		}
		findings = append(findings, map[string]any{
			"package":            pkgLabel(r.pkg),
			"source":             "osv",
			"vulns":              ids,
			"severity_threshold": osv.MinSeverity(),
		})
	}
	return decisions, findings, processed, false
}

// llmPhase runs the analyzer sequentially. Each non-nil verdict is
// recorded; panics are recovered into a synthetic __error__ entry by
// safeAnalyze. Returns updated (decisions, findings, processed, budget-hit).
func llmPhase(
	pkgs []types.Package, fallback string, overBudget func() bool,
	decisions []decision, findings []map[string]any,
) ([]decision, []map[string]any, int, bool) {
	processed := 0
	for _, pkg := range pkgs {
		if overBudget() {
			return decisions, findings, processed, true
		}
		processed++
		verdict := safeAnalyze(pkg)
		if verdict == nil {
			continue
		}
		if errStr, ok := verdict["__error__"].(string); ok {
			decisions = append(decisions, decision{
				Verdict: fallback,
				Reason:  fmt.Sprintf("analyzer error for %s: %s", pkgLabel(pkg), errStr),
			})
			continue
		}
		v, _ := verdict["verdict"].(string)
		if v == "" {
			v = "ask"
		}
		reason, _ := verdict["reason"].(string)
		decisions = append(decisions, decision{
			Verdict: v,
			Reason:  fmt.Sprintf("[claude] %s: %s", pkgLabel(pkg), reason),
		})
		finding := map[string]any{
			"package": pkgLabel(pkg),
			"source":  "claude",
		}
		for k, val := range verdict {
			finding[k] = val
		}
		findings = append(findings, finding)
	}
	return decisions, findings, processed, false
}

// osvDenied reports whether any decision so far is a deny — used to
// short-circuit the LLM phase when OSV alone is enough to block.
func osvDenied(decisions []decision) bool {
	for _, d := range decisions {
		if d.Verdict == "deny" {
			return true
		}
	}
	return false
}

type osvResult struct {
	pkg   types.Package
	vulns []map[string]any
	err   error
}

func runOSVParallel(pkgs []types.Package) []osvResult {
	results := make([]osvResult, len(pkgs))
	workers := len(pkgs)
	if workers > 8 {
		workers = 8
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, pkg := range pkgs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p types.Package) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					results[i] = osvResult{pkg: p, err: fmt.Errorf("panic: %v", r)}
				}
			}()
			vulns, err := queryOSV(p)
			results[i] = osvResult{pkg: p, vulns: vulns, err: err}
		}(i, pkg)
	}
	wg.Wait()
	return results
}

func safeAnalyze(pkg types.Package) (out map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			out = map[string]any{"__error__": fmt.Sprintf("%v", r)}
		}
	}()
	return analyzePackage(pkg.Ecosystem, pkg.Name, pkg.Version)
}

func maxPackages() int {
	if raw := os.Getenv("WATCHDOG_MAX_PACKAGES"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			return v
		}
	}
	return DefaultMaxPackages
}

func pkgsToDicts(pkgs []types.Package) []map[string]any {
	out := make([]map[string]any, 0, len(pkgs))
	for _, p := range pkgs {
		entry := map[string]any{"ecosystem": p.Ecosystem, "name": p.Name}
		if p.Version == "" {
			entry["version"] = nil
		} else {
			entry["version"] = p.Version
		}
		out = append(out, entry)
	}
	return out
}

func pkgLabel(p types.Package) string {
	if p.Version != "" {
		return fmt.Sprintf("%s:%s@%s", p.Ecosystem, p.Name, p.Version)
	}
	return fmt.Sprintf("%s:%s", p.Ecosystem, p.Name)
}

func labels(pkgs []types.Package) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = pkgLabel(p)
	}
	return out
}

func joinSemi(parts []string) string {
	return strings.Join(parts, "; ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
