// watchdog-scan: manual /watchdog-scan slash command entry.
//
// Usage:
//
//	watchdog-scan <target>
//
// target = npm/PyPI package name, name@version, or git URL.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/analyzer"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/policy"
)

var gitURLRE = regexp.MustCompile(`^(https?://|git@|ssh://).+`)

type resultEntry struct {
	Ecosystem string         `json:"ecosystem"`
	Name      string         `json:"name"`
	Version   string         `json:"version,omitempty"`
	Verdict   map[string]any `json:"-"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(`{"verdict":"ask","reason":"no target supplied"}`)
		return
	}
	_ = config.MustLoad()
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
		name, version := target[:at], target[at+1:]
		plans = append(plans,
			plan{"npm", name, version},
			plan{"PyPI", name, version})
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
