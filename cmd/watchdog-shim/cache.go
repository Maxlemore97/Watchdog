package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/paths"
)

func cacheUsage() {
	fmt.Fprintln(os.Stderr, `watchdog-shim cache stats
watchdog-shim cache clear [--type=llm|osv|all] [--older-than=DURATION] [--dry-run]

The cache is opaque to package names (entries are SHA-256-hashed), so
filtering by package isn't supported. --older-than understands Go's
time-duration syntax plus "Nd" for N days.`)
}

func cmdCache(args []string) int {
	if len(args) < 1 {
		cacheUsage()
		return 2
	}
	switch args[0] {
	case "stats":
		return cmdCacheStats()
	case "clear":
		return cmdCacheClear(args[1:])
	default:
		cacheUsage()
		return 2
	}
}

// cacheEntry is a file in the cache dir classified by its content
// shape so the user can target llm-vs-OSV without rm-rf'ing both.
type cacheEntry struct {
	path  string
	size  int64
	mtime time.Time
	kind  string // llm | osv | ledger | unknown
}

func scanCache() ([]cacheEntry, error) {
	dir := paths.CacheDir()
	f, err := os.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	var out []cacheEntry
	for _, n := range names {
		// Tmp staging files from in-flight cache writes; ignore.
		if strings.Contains(n, ".tmp") {
			continue
		}
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		path := filepath.Join(dir, n)
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			continue
		}
		out = append(out, cacheEntry{
			path: path, size: st.Size(), mtime: st.ModTime(),
			kind: classifyCacheFile(path, n),
		})
	}
	return out, nil
}

// classifyCacheFile peeks at the JSON shape to tell apart the three
// kinds of cache files. The OSV cache stores a top-level array; the
// analyzer cache stores an object with a "verdict" key; the ledger
// has a fixed filename.
func classifyCacheFile(path, name string) string {
	if name == "vetted_plugins.json" {
		return "ledger"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	var probe any
	if err := json.Unmarshal(data, &probe); err != nil {
		return "unknown"
	}
	switch v := probe.(type) {
	case []any:
		return "osv"
	case map[string]any:
		if _, ok := v["verdict"]; ok {
			return "llm"
		}
	}
	return "unknown"
}

func cmdCacheStats() int {
	entries, err := scanCache()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cache stats: %v\n", err)
		return 1
	}
	type bucket struct {
		count int
		bytes int64
	}
	buckets := map[string]*bucket{}
	for _, e := range entries {
		b, ok := buckets[e.kind]
		if !ok {
			b = &bucket{}
			buckets[e.kind] = b
		}
		b.count++
		b.bytes += e.size
	}
	fmt.Printf("Cache dir: %s\n\n", paths.CacheDir())
	var totalCount int
	var totalBytes int64
	for _, k := range []string{"llm", "osv", "ledger", "unknown"} {
		b := buckets[k]
		if b == nil {
			b = &bucket{}
		}
		fmt.Printf("  %-8s %5d entries  %s\n", k, b.count, humanBytes(b.bytes))
		totalCount += b.count
		totalBytes += b.bytes
	}
	fmt.Println("  --")
	fmt.Printf("  %-8s %5d entries  %s\n", "total", totalCount, humanBytes(totalBytes))
	return 0
}

func cmdCacheClear(args []string) int {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	typeFlag := fs.String("type", "llm", "what to clear: llm, osv, all")
	olderFlag := fs.String("older-than", "", "only clear entries older than DURATION (e.g. 24h, 7d)")
	dryRun := fs.Bool("dry-run", false, "show what would be cleared without deleting")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	typ := strings.ToLower(*typeFlag)
	if typ != "llm" && typ != "osv" && typ != "all" {
		fmt.Fprintf(os.Stderr, "cache clear: unknown --type=%q (want llm/osv/all)\n", typ)
		return 2
	}

	var olderThan time.Duration
	if *olderFlag != "" {
		d, err := parseAgeDuration(*olderFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cache clear: invalid --older-than=%q: %v\n", *olderFlag, err)
			return 2
		}
		olderThan = d
	}

	entries, err := scanCache()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cache clear: %v\n", err)
		return 1
	}

	cutoff := time.Now().Add(-olderThan)
	var matched int
	var freed int64
	for _, e := range entries {
		// The persistent ledger is intentionally exempt; users who
		// really want it gone can delete vetted_plugins.json by hand.
		if e.kind == "ledger" {
			continue
		}
		if typ != "all" && e.kind != typ {
			continue
		}
		if olderThan > 0 && !e.mtime.Before(cutoff) {
			continue
		}
		matched++
		freed += e.size
		if *dryRun {
			fmt.Printf("would remove %s (%s, %s)\n",
				filepath.Base(e.path), e.kind, e.mtime.Format(time.RFC3339))
			continue
		}
		if err := os.Remove(e.path); err != nil {
			fmt.Fprintf(os.Stderr, "  remove %s: %v\n", e.path, err)
		}
	}
	verb := "removed"
	if *dryRun {
		verb = "would remove"
	}
	fmt.Printf("%s %d entries (%s)\n", verb, matched, humanBytes(freed))
	return 0
}

// parseAgeDuration accepts Go's time-duration syntax plus the "Nd"
// shorthand for N days. Go's stdlib tops out at hours, which is
// awkward for cache-age cleanup.
func parseAgeDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		if n < 0 {
			return 0, fmt.Errorf("negative days")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGT"[exp])
}
