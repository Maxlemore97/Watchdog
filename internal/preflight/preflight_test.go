package preflight

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// pkg is a tiny constructor.
func pkg(name, version string) types.Package {
	return types.Package{Ecosystem: "npm", Name: name, Version: version}
}

// stubOK returns no vulns, no error — production "clean" path.
func stubOK(types.Package) ([]map[string]any, error) {
	return []map[string]any{}, nil
}

// stubErr returns no vulns, an error — production "OSV unreachable".
func stubErr(types.Package) ([]map[string]any, error) {
	return nil, errors.New("net down")
}

// withStubs swaps the OSV+analyzer hooks at the package level for the
// duration of a test. Returns a restore func.
func withStubs(t *testing.T,
	q func(types.Package) ([]map[string]any, error),
	a func(string, string, string) map[string]any,
) func() {
	t.Helper()
	origQ, origA := queryOSV, analyzePackage
	queryOSV = q
	analyzePackage = a
	return func() {
		queryOSV = origQ
		analyzePackage = origA
	}
}

func TestPackages_Empty(t *testing.T) {
	r := Packages(nil, nil, Options{Mode: "both"})
	if r.Verdict != "allow" {
		t.Errorf("empty pkgs = %q", r.Verdict)
	}
}

func TestPackages_NotesOnly(t *testing.T) {
	r := Packages(nil, []string{"requirements file"}, Options{Mode: "both"})
	if r.Verdict != "ask" {
		t.Errorf("notes-only = %q", r.Verdict)
	}
}

func TestPackages_Clean(t *testing.T) {
	restore := withStubs(t,
		stubOK,
		func(eco, name, ver string) map[string]any { return nil },
	)
	defer restore()
	r := Packages([]types.Package{pkg("lodash", "1")}, nil, Options{Mode: "both"})
	if r.Verdict != "allow" {
		t.Errorf("clean = %q reason=%q", r.Verdict, r.Reason)
	}
}

func TestPackages_OSVHitDenies(t *testing.T) {
	vuln := map[string]any{
		"id":                "GHSA-x",
		"database_specific": map[string]any{"severity": "high"},
	}
	analyzerCalled := false
	restore := withStubs(t,
		func(types.Package) ([]map[string]any, error) { return []map[string]any{vuln}, nil },
		func(string, string, string) map[string]any {
			analyzerCalled = true
			return nil
		},
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1")}, nil, Options{Mode: "both"})
	if r.Verdict != "deny" {
		t.Errorf("verdict = %q", r.Verdict)
	}
	if !strings.Contains(r.Reason, "GHSA-x") {
		t.Errorf("reason missing GHSA-x: %q", r.Reason)
	}
	if analyzerCalled {
		t.Error("OSV deny should short-circuit LLM")
	}
}

func TestPackages_ClaudeOnlySkipsOSV(t *testing.T) {
	osvCalled := false
	restore := withStubs(t,
		func(types.Package) ([]map[string]any, error) { osvCalled = true; return nil, nil },
		func(string, string, string) map[string]any {
			return map[string]any{"verdict": "allow", "reason": "ok"}
		},
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1")}, nil, Options{Mode: "claude"})
	if osvCalled {
		t.Error("mode=claude must not call OSV")
	}
	if r.Verdict != "allow" {
		t.Errorf("verdict = %q", r.Verdict)
	}
}

func TestPackages_OSVOnlySkipsClaude(t *testing.T) {
	llmCalled := false
	restore := withStubs(t,
		stubOK,
		func(string, string, string) map[string]any { llmCalled = true; return map[string]any{} },
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1")}, nil, Options{Mode: "osv"})
	if llmCalled {
		t.Error("mode=osv must not call analyzer")
	}
	if r.Verdict != "allow" {
		t.Errorf("verdict = %q", r.Verdict)
	}
}

func TestPackages_InvalidModeFallsBack(t *testing.T) {
	restore := withStubs(t,
		stubOK,
		func(string, string, string) map[string]any { return nil },
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1")}, nil, Options{Mode: "banana"})
	if r.Mode != "both" {
		t.Errorf("mode = %q", r.Mode)
	}
}

func TestPackages_WorstVerdictWins(t *testing.T) {
	verdicts := []map[string]any{
		{"verdict": "allow", "reason": "ok"},
		{"verdict": "deny", "reason": "bad"},
	}
	idx := 0
	restore := withStubs(t,
		stubOK,
		func(string, string, string) map[string]any {
			v := verdicts[idx]
			idx++
			return v
		},
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1"), pkg("b", "1")}, nil, Options{Mode: "claude"})
	if r.Verdict != "deny" {
		t.Errorf("verdict = %q", r.Verdict)
	}
}

// ---------- package cap ------------------------------------------

func TestPackages_AboveDefaultCapReturnsAsk(t *testing.T) {
	osvCalls := 0
	llmCalls := 0
	restore := withStubs(t,
		func(types.Package) ([]map[string]any, error) { osvCalls++; return nil, nil },
		func(string, string, string) map[string]any { llmCalls++; return nil },
	)
	defer restore()
	pkgs := make([]types.Package, DefaultMaxPackages+1)
	for i := range pkgs {
		pkgs[i] = pkg(fmt.Sprintf("p%d", i), "1")
	}
	r := Packages(pkgs, nil, Options{Mode: "both"})
	if r.Verdict != "ask" {
		t.Errorf("verdict = %q", r.Verdict)
	}
	if !strings.Contains(r.Reason, "too many packages") {
		t.Errorf("reason = %q", r.Reason)
	}
	if osvCalls != 0 || llmCalls != 0 {
		t.Errorf("cap should short-circuit; osv=%d llm=%d", osvCalls, llmCalls)
	}
}

func TestPackages_AtCapStillScans(t *testing.T) {
	var scanned atomic.Bool
	restore := withStubs(t,
		func(types.Package) ([]map[string]any, error) {
			scanned.Store(true)
			return []map[string]any{}, nil
		},
		func(string, string, string) map[string]any { return nil },
	)
	defer restore()
	pkgs := make([]types.Package, DefaultMaxPackages)
	for i := range pkgs {
		pkgs[i] = pkg(fmt.Sprintf("p%d", i), "1")
	}
	r := Packages(pkgs, nil, Options{Mode: "osv"})
	if !scanned.Load() {
		t.Error("at-cap should be scanned")
	}
	if r.Verdict != "allow" {
		t.Errorf("verdict = %q", r.Verdict)
	}
}

func TestPackages_CapOverridableViaEnv(t *testing.T) {
	t.Setenv("WATCHDOG_MAX_PACKAGES", "2")
	osvCalls := 0
	restore := withStubs(t,
		func(types.Package) ([]map[string]any, error) { osvCalls++; return nil, nil },
		func(string, string, string) map[string]any { return nil },
	)
	defer restore()
	pkgs := []types.Package{pkg("a", "1"), pkg("b", "1"), pkg("c", "1")}
	r := Packages(pkgs, nil, Options{Mode: "both"})
	if r.Verdict != "ask" {
		t.Errorf("verdict = %q", r.Verdict)
	}
	if osvCalls != 0 {
		t.Errorf("env cap not honored; osv=%d", osvCalls)
	}
}

// ---------- offline decisions ------------------------------------

func TestPackages_OSVErrorUsesOfflineDecision(t *testing.T) {
	restore := withStubs(t,
		stubErr,
		func(string, string, string) map[string]any { return nil },
	)
	defer restore()
	r := Packages([]types.Package{pkg("bad", "1")}, nil, Options{Mode: "osv", OfflineDecision: "deny"})
	if r.Verdict != "deny" {
		t.Errorf("verdict = %q reason=%q", r.Verdict, r.Reason)
	}
	if !strings.Contains(r.Reason, "OSV unreachable") {
		t.Errorf("reason = %q", r.Reason)
	}
}

// ---------- budget --------------------------------------------------

func TestPackages_ZeroBudgetNotEnforced(t *testing.T) {
	// 0 means no budget — same as unset.
	restore := withStubs(t,
		stubOK,
		func(string, string, string) map[string]any { return map[string]any{"verdict": "allow"} },
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1")}, nil, Options{Mode: "claude", BudgetSeconds: 0})
	if r.Verdict != "allow" {
		t.Errorf("verdict = %q", r.Verdict)
	}
}

func TestPackages_BudgetExceededMidway(t *testing.T) {
	restore := withStubs(t,
		stubOK,
		func(string, string, string) map[string]any {
			time.Sleep(50 * time.Millisecond)
			return map[string]any{"verdict": "allow"}
		},
	)
	defer restore()
	r := Packages(
		[]types.Package{pkg("a", "1"), pkg("b", "1"), pkg("c", "1"), pkg("d", "1")},
		nil, Options{Mode: "claude", BudgetSeconds: 0.06},
	)
	if r.Verdict != "ask" || !strings.Contains(r.Reason, "budget") {
		t.Errorf("verdict = %q reason=%q", r.Verdict, r.Reason)
	}
}

// ---------- packages key -----------------------------------------

func TestPackages_ReturnsPackagesKey(t *testing.T) {
	restore := withStubs(t,
		stubOK,
		func(string, string, string) map[string]any { return nil },
	)
	defer restore()
	pkgs := []types.Package{pkg("a", "1"), {Ecosystem: "npm", Name: "b"}}
	r := Packages(pkgs, nil, Options{Mode: "both"})
	if len(r.Packages) != 2 {
		t.Errorf("packages len = %d", len(r.Packages))
	}
	if r.Packages[0]["name"] != "a" {
		t.Errorf("first name = %v", r.Packages[0]["name"])
	}
	if r.Packages[1]["version"] != nil {
		t.Errorf("second version should be nil, got %v", r.Packages[1]["version"])
	}
}

// ---------- findings -----------------------------------------------

func TestPackages_FindingsIncludeOSVAboveThreshold(t *testing.T) {
	vuln := map[string]any{
		"id":                "GHSA-1",
		"database_specific": map[string]any{"severity": "high"},
	}
	restore := withStubs(t,
		func(types.Package) ([]map[string]any, error) { return []map[string]any{vuln}, nil },
		func(string, string, string) map[string]any { return nil },
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1")}, nil, Options{Mode: "both"})
	if len(r.Findings) != 1 || r.Findings[0]["source"] != "osv" {
		t.Errorf("findings = %v", r.Findings)
	}
}


// ---------- edge paths ------------------------------------------

// TestPackages_BudgetExceeded verifies that a slow analyzer trips
// the wall-clock budget cap (preflight.go:101-208) and returns
// `ask` with a budget-mentioning reason rather than blocking the
// host indefinitely.
func TestPackages_BudgetExceeded(t *testing.T) {
	restore := withStubs(t,
		stubOK,
		func(eco, name, ver string) map[string]any {
			time.Sleep(200 * time.Millisecond)
			return map[string]any{"verdict": "allow", "reason": "fine"}
		},
	)
	defer restore()
	r := Packages(
		[]types.Package{pkg("a", "1"), pkg("b", "1"), pkg("c", "1")},
		nil,
		Options{Mode: "claude", BudgetSeconds: 0.05},
	)
	if r.Verdict != "ask" {
		t.Errorf("budget verdict = %q, want ask", r.Verdict)
	}
	if !strings.Contains(r.Reason, "budget") {
		t.Errorf("budget reason missing keyword: %q", r.Reason)
	}
}

// TestPackages_AnalyzerPanic verifies safeAnalyze recovers, surfaces
// __error__, and preflight falls back to the offline decision rather
// than crashing the host.
func TestPackages_AnalyzerPanic(t *testing.T) {
	restore := withStubs(t,
		stubOK,
		func(string, string, string) map[string]any {
			panic("analyzer exploded")
		},
	)
	defer restore()
	r := Packages([]types.Package{pkg("a", "1")}, nil, Options{
		Mode:            "claude",
		OfflineDecision: "deny",
	})
	if r.Verdict != "deny" {
		t.Errorf("panic + OfflineDecision=deny: verdict=%q want deny", r.Verdict)
	}
	if !strings.Contains(r.Reason, "analyzer error") {
		t.Errorf("missing analyzer-error in reason: %q", r.Reason)
	}
}

// TestRunOSVParallel_PanicRecover verifies one panicking worker
// doesn't take down siblings: 8 packages, the 4th's stub panics,
// the rest must return results.
func TestRunOSVParallel_PanicRecover(t *testing.T) {
	var calls atomic.Int32
	restore := withStubs(t,
		func(p types.Package) ([]map[string]any, error) {
			n := calls.Add(1)
			if n == 4 {
				panic("osv worker exploded")
			}
			return []map[string]any{}, nil
		},
		func(string, string, string) map[string]any { return nil },
	)
	defer restore()

	pkgs := make([]types.Package, 8)
	for i := range pkgs {
		pkgs[i] = pkg(fmt.Sprintf("pkg-%d", i), "1")
	}
	r := Packages(pkgs, nil, Options{Mode: "osv", OfflineDecision: "ask"})
	// The panicking worker yields verdict=ask (offline-decision); the
	// other 7 are clean. Worst-wins -> ask.
	if r.Verdict != "ask" {
		t.Errorf("verdict = %q, want ask", r.Verdict)
	}
	// Must mention the panic recovery somewhere.
	if !strings.Contains(r.Reason, "panic") && !strings.Contains(r.Reason, "OSV unreachable") {
		t.Errorf("expected panic mention in reason: %q", r.Reason)
	}
}
