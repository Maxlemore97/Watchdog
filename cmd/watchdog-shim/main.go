// watchdog-shim: install, uninstall, status, and doctor for the
// PATH-prepend wrappers that intercept package-manager binaries.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/providers"
	"github.com/Maxlemore97/watchdog/internal/shim"
)

func usage() {
	fmt.Fprintln(os.Stderr, `watchdog-shim install   [--dir DIR] [--no-overwrite]
watchdog-shim uninstall [--dir DIR]
watchdog-shim status    [--dir DIR]
watchdog-shim doctor`)
}

func main() {
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
	_ = args
	target := shim.DefaultShimDir()
	if v := os.Getenv("WATCHDOG_SHIM_DIR"); v != "" {
		target = v
	}
	fmt.Println("watchdog-shim doctor:")

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
	if _, err := providers.ResolveProvider(); err == nil {
		fmt.Println("  ok  at least one LLM provider CLI on PATH")
	} else {
		fmt.Println("  warn no LLM provider CLI on PATH (claude/gemini/openai/ollama) — analyzer falls back to OSV-only")
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
	return 0
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
