// watchdog-shim: install, uninstall, status, and doctor for the
// PATH-prepend wrappers that intercept package-manager binaries.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/audit"
	"github.com/Maxlemore97/watchdog/internal/integrity"
	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/providers"
	"github.com/Maxlemore97/watchdog/internal/shim"
	"github.com/Maxlemore97/watchdog/internal/version"
)

func usage() {
	fmt.Fprintln(os.Stderr, `watchdog-shim install   [--dir DIR] [--no-overwrite]
watchdog-shim uninstall [--dir DIR]
watchdog-shim status    [--dir DIR]
watchdog-shim doctor
watchdog-shim doctor    [--llm-smoke] [--llm-smoke-timeout=DUR]
watchdog-shim cache     stats | clear [--type=llm|osv|all] [--older-than=DUR] [--dry-run]
watchdog-shim --version`)
}

func main() {
	if version.HandleFlag(os.Args[0], os.Args[1:], os.Stdout) {
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	rest := os.Args[2:]
	switch cmd {
	case "install":
		os.Exit(cmdInstall(rest))
	case "uninstall":
		os.Exit(cmdUninstall(rest))
	case "status":
		os.Exit(cmdStatus(rest))
	case "doctor":
		os.Exit(cmdDoctor(rest))
	case "cache":
		os.Exit(cmdCache(rest))
	default:
		usage()
		os.Exit(2)
	}
}

func parseDir(args []string) (dir string, overwrite bool, rest []string) {
	fs := flag.NewFlagSet("dir", flag.ExitOnError)
	dirFlag := fs.String("dir", "", "shim directory (default: ~/.watchdog/bin)")
	noOverwrite := fs.Bool("no-overwrite", false, "skip tools that already have a shim")
	_ = fs.Parse(args)
	dir = *dirFlag
	overwrite = !*noOverwrite
	rest = fs.Args()
	return
}

func cmdInstall(args []string) int {
	dir, overwrite, _ := parseDir(args)
	target := dir
	if target == "" {
		target = shim.DefaultShimDir()
	}
	written, err := shim.Install(shim.InstallOpts{
		ShimDir:   dir,
		Overwrite: overwrite,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
		return 1
	}
	fmt.Printf("Installed %d shims into %s\n", len(written), target)
	for _, p := range written {
		fmt.Printf("  %s\n", filepath.Base(p))
	}

	// Snapshot the install state into ~/.watchdog/manifest.json. Every
	// hot-path entry point (pretool, shim-exec, session, mcp) verifies
	// against this. A missing manifest is treated as "no integrity
	// enforcement" — back-compat for manually-installed setups — so
	// failure here is a warning, not a fatal error.
	m, mErr := integrity.Build()
	if mErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not build integrity manifest: %v\n", mErr)
	} else if wErr := integrity.WriteManifest(m); wErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write integrity manifest: %v\n", wErr)
	} else {
		audit.Record("manifest.written", map[string]any{
			"shim_dir":     m.ShimDir,
			"binary_count": len(m.Binaries),
			"shim_count":   len(m.Shims),
		})
		fmt.Printf("  manifest %s\n", paths.ManifestPath())
	}

	fmt.Println()
	fmt.Println("Add this directory to the FRONT of your PATH:")
	if runtime.GOOS == "windows" {
		fmt.Printf("  $env:Path = \"%s;\" + $env:Path        (PowerShell)\n", target)
		fmt.Printf("  setx PATH \"%s;%%PATH%%\"             (cmd.exe, persistent)\n", target)
	} else {
		fmt.Printf("  export PATH=\"%s:$PATH\"\n", target)
		fmt.Println("Then restart your shell or `source` your rc file.")
	}
	return 0
}

func cmdUninstall(args []string) int {
	dir, _, _ := parseDir(args)
	target := dir
	if target == "" {
		target = shim.DefaultShimDir()
	}
	removed, err := shim.Uninstall(shim.InstallOpts{ShimDir: dir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
		return 1
	}
	fmt.Printf("Removed %d shims from %s\n", len(removed), target)
	for _, p := range removed {
		fmt.Printf("  %s\n", filepath.Base(p))
	}
	// Remove the manifest so subsequent hook invocations see "clean
	// uninstall" and fail-open. Without this, hook wrappers would
	// detect a missing binary alongside a present manifest and
	// fail-closed for install commands — wrong for a deliberate
	// uninstall.
	if err := os.Remove(paths.ManifestPath()); err == nil {
		fmt.Printf("Removed manifest %s\n", paths.ManifestPath())
		audit.Record("manifest.removed", map[string]any{
			"path": paths.ManifestPath(),
		})
	}
	return 0
}

func cmdStatus(args []string) int {
	dir, _, _ := parseDir(args)
	target := dir
	if target == "" {
		target = shim.DefaultShimDir()
	}
	fmt.Printf("Shim dir: %s\n", target)
	st := shim.Status(shim.InstallOpts{ShimDir: dir})
	// Print in ShimmedTools order for determinism.
	for _, t := range shim.ShimmedTools {
		marker := "-- "
		if st[t] {
			marker = "ok "
		}
		fmt.Printf("  %s %s\n", marker, t)
	}
	return 0
}

// cmdDoctor checks the user's environment for the most common
// install-time problems.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	smoke := fs.Bool("llm-smoke", false,
		"send a tiny prompt to the detected LLM CLI (costs a few tokens)")
	smokeTimeout := fs.Duration("llm-smoke-timeout", 5*time.Second,
		"how long to wait for the smoke response")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := shim.DefaultShimDir()
	if v := os.Getenv("WATCHDOG_SHIM_DIR"); v != "" {
		target = v
	}
	fmt.Println("watchdog-shim doctor:")
	fmt.Printf("  --  watchdog-shim version: %s\n", version.String())

	// 1. shim dir on PATH and first
	pathEnv := os.Getenv("PATH")
	parts := strings.Split(pathEnv, string(os.PathListSeparator))
	if len(parts) > 0 && samePath(parts[0], target) {
		fmt.Println("  ok  shim dir is first on PATH")
	} else if containsPath(parts, target) {
		fmt.Println("  warn shim dir is on PATH but not first — installs invoke the real binary directly")
	} else {
		fmt.Printf("  fail shim dir %s is not on PATH\n", target)
	}

	// 2. watchdog-shim-exec discoverable
	if _, err := exec.LookPath("watchdog-shim-exec"); err == nil {
		fmt.Println("  ok  watchdog-shim-exec found on PATH")
	} else {
		fmt.Println("  fail watchdog-shim-exec not on PATH (shim wrappers will fail to exec)")
	}

	// 3. at least one LLM CLI on PATH
	prov, provErr := providers.ResolveProvider()
	if provErr == nil {
		fmt.Println("  ok  at least one LLM provider CLI on PATH")
		if *smoke {
			runLLMSmoke(os.Stdout, prov, *smokeTimeout, prov.Invoke)
		}
	} else {
		fmt.Println("  warn no LLM provider CLI on PATH (claude/gemini/openai/ollama) — analyzer falls back to OSV-only")
		if *smoke {
			fmt.Println("  --  llm smoke skipped: no provider resolved")
		}
	}

	// 4. cache dir writable
	if err := os.MkdirAll(paths.CacheDir(), 0o755); err != nil {
		fmt.Printf("  fail cache dir %s not writable: %v\n", paths.CacheDir(), err)
	} else {
		probe := filepath.Join(paths.CacheDir(), ".watchdog-doctor.tmp")
		if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
			fmt.Printf("  fail cache dir %s not writable: %v\n", paths.CacheDir(), err)
		} else {
			_ = os.Remove(probe)
			fmt.Printf("  ok  cache dir writable (%s)\n", paths.CacheDir())
		}
	}

	// 5. integrity manifest — verify against installed state.
	st := integrity.VerifyDeep()
	switch {
	case st.Disabled:
		fmt.Println("  --  integrity check skipped: WATCHDOG_DISABLE is set")
	case st.OK:
		fmt.Printf("  ok  integrity manifest matches (%s)\n", paths.ManifestPath())
	case st.ManifestMissing:
		fmt.Printf("  warn no integrity manifest at %s — run `watchdog-shim install` to create one\n",
			paths.ManifestPath())
	default:
		fmt.Printf("  fail integrity check failed (%d issue(s)):\n", len(st.Failures))
		for _, f := range st.Failures {
			where := f.Path
			if where == "" {
				where = "—"
			}
			fmt.Printf("       %s  %s\n", f.Code, f.Detail)
			fmt.Printf("         path: %s\n", where)
		}
	}
	return 0
}

// invokeFn is the subset of provider.Invoke that the smoke runner
// needs. Pulled out so tests can swap in a stub instead of shelling
// out to a real LLM CLI.
type invokeFn func(prompt string, cfg providers.Config) (string, error)

// runLLMSmoke sends a one-token challenge to the resolved provider
// and reports ok/warn/fail to w. AppendSystem is cleared so the call
// doesn't drag in the full analyzer system prompt — the goal is to
// prove the CLI authenticates and responds, not to scan anything.
func runLLMSmoke(w io.Writer, prov providers.Provider, timeout time.Duration, invoke invokeFn) {
	cfg := providers.BuildConfig(prov, "")
	cfg.Timeout = timeout
	cfg.AppendSystem = false

	start := time.Now()
	output, err := invoke("Respond with the four-letter token PING and nothing else.", cfg)
	elapsed := time.Since(start).Round(time.Millisecond)

	if err != nil {
		msg := err.Error()
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		fmt.Fprintf(w, "  fail %s smoke test failed in %s: %s\n", prov.Name, elapsed, msg)
		return
	}
	if !strings.Contains(strings.ToUpper(output), "PING") {
		fmt.Fprintf(w, "  warn %s responded in %s but output didn't include the PING marker (model=%s)\n",
			prov.Name, elapsed, cfg.Model)
		return
	}
	fmt.Fprintf(w, "  ok  %s smoke test passed in %s (model=%s)\n",
		prov.Name, elapsed, cfg.Model)
}

func samePath(a, b string) bool {
	ra, _ := filepath.EvalSymlinks(a)
	rb, _ := filepath.EvalSymlinks(b)
	if ra == "" {
		ra = a
	}
	if rb == "" {
		rb = b
	}
	return filepath.Clean(ra) == filepath.Clean(rb)
}

func containsPath(parts []string, target string) bool {
	for _, p := range parts {
		if samePath(p, target) {
			return true
		}
	}
	return false
}
