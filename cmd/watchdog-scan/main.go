// watchdog-scan: manual /watchdog-scan slash command entry.
//
// Usage:
//
//	watchdog-scan <target>            # one published package or git URL
//	watchdog-scan project [DIR]       # walk a project tree
//
// target = npm/PyPI package name, name@version, or git URL.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/policy"
	"github.com/Maxlemore97/watchdog/internal/projectscan"
	"github.com/Maxlemore97/watchdog/internal/version"
)

var gitURLRE = regexp.MustCompile(`^(https?://|git@|ssh://).+`)

type resultEntry struct {
	Ecosystem string         `json:"ecosystem"`
	Name      string         `json:"name"`
	Version   string         `json:"version,omitempty"`
	Verdict   map[string]any `json:"-"`
}

func main() {
	if version.HandleFlag(os.Args[0], os.Args[1:], os.Stdout) {
		return
	}
	if len(os.Args) < 2 {
		fmt.Println(`{"verdict":"ask","reason":"no target supplied"}`)
		return
	}
	_ = config.MustLoad()

	if os.Args[1] == "project" {
		os.Exit(runProject(os.Args[2:]))
	}

	target := strings.TrimSpace(os.Args[1])

	type plan struct {
		Ecosystem string
		Name      string
		Version   string
	}
	var plans []plan
	switch {
	case gitURLRE.MatchString(target) || strings.HasSuffix(target, ".git"):
		plans = append(plans, plan{"plugin", target, ""})
	case strings.Contains(target, "@") && !strings.HasPrefix(target, "@"):
		at := strings.Index(target, "@")
		name, ver := target[:at], target[at+1:]
		plans = append(plans,
			plan{"npm", name, ver},
			plan{"PyPI", name, ver})
	default:
		plans = append(plans,
			plan{"npm", target, ""},
			plan{"PyPI", target, ""})
	}

	results := []map[string]any{}
	for _, p := range plans {
		v := analyzer.AnalyzePackage(p.Ecosystem, p.Name, p.Version)
		if v == nil {
			continue
		}
		entry := map[string]any{"ecosystem": p.Ecosystem, "name": p.Name}
		if p.Version != "" {
			entry["version"] = p.Version
		}
		for k, val := range v {
			entry[k] = val
		}
		results = append(results, entry)
	}

	// Sort by verdict rank descending so the worst comes first
	// (matches the Python `max(... key=rank)` behaviour).
	if len(results) > 1 {
		worstIdx := 0
		for i := 1; i < len(results); i++ {
			if policy.Rank(verdictStr(results[i])) > policy.Rank(verdictStr(results[worstIdx])) {
				worstIdx = i
			}
		}
		if worstIdx != 0 {
			results[0], results[worstIdx] = results[worstIdx], results[0]
		}
	}

	out := map[string]any{"target": target, "results": results}
	data, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(data))
}

func verdictStr(m map[string]any) string {
	if s, ok := m["verdict"].(string); ok {
		return s
	}
	return "ask"
}

// runProject handles `watchdog-scan project [DIR] [flags]`. Exit
// code mirrors the worst verdict: 0 = allow, 1 = ask or deny. JSON
// goes to stdout; lockfile parse notes and walker notes land in the
// `notes` field of the result so the user sees what was skipped.
func runProject(args []string) int {
	fs := flag.NewFlagSet("project", flag.ContinueOnError)
	depth := fs.Int("depth", 8, "max recursion depth")
	skipGI := fs.Bool("skip-gitignored", true, "honor a top-level .gitignore")
	includeDev := fs.Bool("include-dev", true, "include devDependencies")
	pkgsOnly := fs.Bool("packages-only", false, "skip the plugin walk")
	pluginsOnly := fs.Bool("plugins-only", false, "skip the dependency walk")
	format := fs.String("format", "json", "output format: json or text")
	budget := fs.Float64("budget-secs", 120, "wall-clock cap for preflight (seconds)")
	mode := fs.String("mode", "", "preflight mode override (osv/claude/both)")
	// Pop the optional positional DIR before parsing flags so the
	// usual `cmd DIR --flags` ordering works; Go's flag package
	// otherwise stops at the first non-flag token.
	root := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		root = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	result, err := projectscan.Run(projectscan.ScanOpts{
		Root:           root,
		MaxDepth:       *depth,
		SkipGitignored: *skipGI,
		IncludeDev:     *includeDev,
		PackagesOnly:   *pkgsOnly,
		PluginsOnly:    *pluginsOnly,
		BudgetSeconds:  *budget,
		Mode:           *mode,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "project scan failed: %v\n", err)
		return 2
	}
	switch *format {
	case "text":
		fmt.Printf("root:     %s\n", result.Root)
		fmt.Printf("verdict:  %s\n", result.Verdict)
		fmt.Printf("packages: %s  (%d scanned)\n", result.Packages.Verdict, result.Packages.Scanned)
		if result.Packages.Reason != "" {
			fmt.Printf("  reason: %s\n", result.Packages.Reason)
		}
		fmt.Printf("plugins:  %s  (%d scanned)\n", result.Plugins.Verdict, result.Plugins.Scanned)
		for _, n := range result.Notes {
			fmt.Printf("  note: %s\n", n)
		}
	default:
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	}
	if policy.Rank(result.Verdict) >= policy.Rank("ask") {
		return 1
	}
	return 0
}
