// watchdog-shim: install, uninstall, status, and doctor for the
// PATH-prepend wrappers that intercept package-manager binaries.
package main

import (
	"bufio"
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
	"github.com/Maxlemore97/watchdog/internal/cli"
	"github.com/Maxlemore97/watchdog/internal/daemon"
	"github.com/Maxlemore97/watchdog/internal/hosts"
	"github.com/Maxlemore97/watchdog/internal/integrity"
	"github.com/Maxlemore97/watchdog/internal/paths"
	"github.com/Maxlemore97/watchdog/internal/providers"
	"github.com/Maxlemore97/watchdog/internal/shim"
	"github.com/Maxlemore97/watchdog/internal/version"
)

func usage() {
	fmt.Fprintln(os.Stderr, `watchdog-shim install     [--dir DIR] [--no-overwrite] [--register | --no-register | -y]
watchdog-shim uninstall   [--dir DIR]
watchdog-shim status      [--dir DIR]
watchdog-shim doctor      [--llm-smoke] [--llm-smoke-timeout=DUR]
watchdog-shim register    [--host=NAME] [--all]
watchdog-shim unregister  [--host=NAME] [--all]
watchdog-shim daemon      install [--listen=ADDR] | uninstall | status
watchdog-shim cache       stats | clear [--type=llm|osv|all] [--older-than=DUR] [--dry-run]
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
	case "register":
		os.Exit(cmdRegister(rest))
	case "unregister":
		os.Exit(cmdUnregister(rest))
	case "daemon":
		os.Exit(cmdDaemon(rest))
	case "cache":
		os.Exit(cmdCache(rest))
	default:
		usage()
		os.Exit(2)
	}
}

type installFlags struct {
	dir        string
	overwrite  bool
	register   bool // explicit --register / -y
	noRegister bool // explicit --no-register
}

func parseInstallFlags(args []string) installFlags {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	dirFlag := fs.String("dir", "", "shim directory (default: ~/.watchdog/bin)")
	noOverwrite := fs.Bool("no-overwrite", false, "skip tools that already have a shim")
	register := fs.Bool("register", false, "auto-register with every detected MCP host (no prompt)")
	noRegister := fs.Bool("no-register", false, "skip the post-install host-registration prompt")
	yes := fs.Bool("y", false, "alias for --register")
	_ = fs.Parse(args)
	return installFlags{
		dir:        *dirFlag,
		overwrite:  !*noOverwrite,
		register:   *register || *yes,
		noRegister: *noRegister,
	}
}

// parseDir keeps backwards-compat for uninstall/status/cache which
// only consume the --dir / --no-overwrite pair.
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
	f := parseInstallFlags(args)
	target := f.dir
	if target == "" {
		target = shim.DefaultShimDir()
	}
	written, err := shim.Install(shim.InstallOpts{
		ShimDir:   f.dir,
		Overwrite: f.overwrite,
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

	maybeRegisterHosts(f)

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

// maybeRegisterHosts runs the post-install host-registration flow.
// Behaviour:
//   - --no-register: do nothing
//   - --register / -y: register every detected & unregistered host
//   - else if stdin is a TTY: prompt
//   - else: print a one-line hint, no prompt (non-interactive install
//     contexts like CI don't hang)
//
// When the list of pending hosts is empty, nothing prints. Audit:
// `install.registered_via_prompt` or `install.register_skipped`.
func maybeRegisterHosts(f installFlags) {
	if f.noRegister {
		audit.Record("install.register_skipped", map[string]any{"reason": "flag"})
		return
	}
	pending := []hosts.Host{}
	for _, h := range hosts.Detect() {
		if !h.IsRegistered() {
			pending = append(pending, h)
		}
	}
	if len(pending) == 0 {
		return
	}
	execPath := resolveMCPExec()
	if execPath == "" {
		fmt.Fprintln(os.Stderr, "watchdog-mcp binary not found; skipping host registration. Run `watchdog-shim register --all` once it's on PATH.")
		return
	}

	names := []string{}
	for _, h := range pending {
		names = append(names, h.Name())
	}
	listStr := strings.Join(names, ", ")

	approve := f.register
	if !approve && cli.IsTerminal(os.Stdin) {
		fmt.Printf("\nDetected MCP-aware host(s) not yet registered: %s\n", listStr)
		fmt.Print("Register watchdog-mcp with each? [Y/n] ")
		reader := bufio.NewReader(os.Stdin)
		ans, err := reader.ReadString('\n')
		if err == nil {
			a := strings.ToLower(strings.TrimSpace(ans))
			approve = a == "" || a == "y" || a == "yes"
		}
	} else if !approve {
		// Non-interactive context with no flag: print the hint and bail.
		fmt.Printf("\nDetected unregistered MCP host(s): %s. To wire them up, run:\n  watchdog-shim register --all\n",
			listStr)
		audit.Record("install.register_skipped", map[string]any{"reason": "non_tty", "pending": names})
		return
	}
	if !approve {
		audit.Record("install.register_skipped", map[string]any{"reason": "declined", "pending": names})
		return
	}

	registered := []string{}
	for _, h := range pending {
		if err := h.Register(execPath); err != nil {
			fmt.Fprintf(os.Stderr, "register %s: %v\n", h.Name(), err)
			continue
		}
		registered = append(registered, h.Name())
		fmt.Printf("  registered %s (%s)\n", h.Name(), h.ConfigPath())
	}
	if len(registered) > 0 {
		audit.Record("install.registered_via_prompt", map[string]any{
			"hosts":     registered,
			"exec_path": execPath,
		})
	}
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

	// 6. MCP host registration — show detected hosts and whether
	// watchdog-mcp is wired into each. Read-only; modifications go
	// through `watchdog-shim register/unregister`.
	detected := hosts.Detect()
	if len(detected) == 0 {
		fmt.Println("  --  no MCP-aware hosts detected (Claude Desktop / Cursor)")
	} else {
		for _, h := range detected {
			if h.IsRegistered() {
				fmt.Printf("  ok  %s: watchdog-mcp registered (%s)\n", h.Name(), h.ConfigPath())
			} else {
				fmt.Printf("  warn %s detected but not registered — run `watchdog-shim register --host=%s`\n",
					h.Name(), h.Name())
			}
		}
	}
	return 0
}

// resolveMCPExec returns the absolute path to watchdog-mcp. Prefers
// a sibling of watchdog-shim (so a freshly-installed tree finds its
// own binary before PATH catches up), then falls back to exec.LookPath.
// Empty return means the binary isn't installed.
func resolveMCPExec() string {
	name := "watchdog-mcp"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), name)
		if st, err := os.Stat(sibling); err == nil && !st.IsDir() {
			if abs, err := filepath.Abs(sibling); err == nil {
				return abs
			}
			return sibling
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// parseHostFlag returns the host name targeted by --host (or "" for
// "use --all logic") and whether --all was set. Mutually-exclusive
// flags would be nicer, but flag doesn't support it without custom
// parsing — we treat --host as taking precedence if both are set.
func parseHostFlag(args []string) (host string, all bool) {
	fs := flag.NewFlagSet("host", flag.ExitOnError)
	hostFlag := fs.String("host", "", "host name (e.g., claude-desktop, cursor)")
	allFlag := fs.Bool("all", false, "apply to every detected host")
	_ = fs.Parse(args)
	return *hostFlag, *allFlag
}

func cmdRegister(args []string) int {
	hostName, all := parseHostFlag(args)
	execPath := resolveMCPExec()
	if execPath == "" {
		fmt.Fprintln(os.Stderr, "register: watchdog-mcp binary not found on PATH or alongside watchdog-shim")
		return 1
	}

	var targets []hosts.Host
	switch {
	case hostName != "":
		h := hosts.ByName(hostName)
		if h == nil {
			fmt.Fprintf(os.Stderr, "register: unknown host %q\n", hostName)
			return 2
		}
		if !h.Exists() {
			fmt.Fprintf(os.Stderr, "register: %s not installed (no config dir at %s)\n",
				hostName, filepath.Dir(h.ConfigPath()))
			return 1
		}
		targets = []hosts.Host{h}
	case all:
		targets = hosts.Detect()
		if len(targets) == 0 {
			fmt.Println("register: no MCP-aware hosts detected")
			return 0
		}
	default:
		fmt.Fprintln(os.Stderr, "register: specify --host=NAME or --all")
		return 2
	}

	rc := 0
	for _, h := range targets {
		if err := h.Register(execPath); err != nil {
			fmt.Fprintf(os.Stderr, "register %s: %v\n", h.Name(), err)
			rc = 1
			continue
		}
		audit.Record("host.registered", map[string]any{
			"host":      h.Name(),
			"config":    h.ConfigPath(),
			"exec_path": execPath,
		})
		fmt.Printf("Registered watchdog-mcp with %s (%s)\n", h.Name(), h.ConfigPath())
	}
	return rc
}

// cmdDaemon dispatches the `watchdog-shim daemon …` subcommands.
// Available verbs: install [--listen=ADDR], uninstall, status.
func cmdDaemon(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr,
			"daemon: subcommand required (install | uninstall | status)")
		return 2
	}
	verb := args[0]
	rest := args[1:]
	switch verb {
	case "install":
		return cmdDaemonInstall(rest)
	case "uninstall":
		return cmdDaemonUninstall(rest)
	case "status":
		return cmdDaemonStatus(rest)
	default:
		fmt.Fprintf(os.Stderr, "daemon: unknown subcommand %q\n", verb)
		return 2
	}
}

func cmdDaemonInstall(args []string) int {
	fs := flag.NewFlagSet("daemon install", flag.ExitOnError)
	listen := fs.String("listen", "auto",
		"address to serve on (auto = unix://~/.watchdog/mcp.sock; tcp://127.0.0.1:PORT; unix:///path)")
	logPath := fs.String("log", filepath.Join(paths.WatchdogDir(), "daemon.log"),
		"path for daemon stderr/stdout; empty disables")
	_ = fs.Parse(args)
	execPath := resolveMCPExec()
	if execPath == "" {
		fmt.Fprintln(os.Stderr, "daemon install: watchdog-mcp binary not found on PATH")
		return 1
	}
	st, err := daemon.Install(daemon.Options{
		ExecPath:   execPath,
		ListenAddr: *listen,
		LogPath:    *logPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon install: %v\n", err)
		return 1
	}
	audit.Record("daemon.installed", map[string]any{
		"listen":       *listen,
		"service_file": st.ServiceFilePath,
		"exec_path":    execPath,
	})
	fmt.Printf("Installed watchdog-mcp daemon: %s\n", st.ServiceFilePath)
	if st.Detail != "" {
		fmt.Printf("  %s\n", st.Detail)
	}
	return 0
}

func cmdDaemonUninstall(args []string) int {
	_ = args
	st, err := daemon.Uninstall()
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon uninstall: %v\n", err)
		return 1
	}
	audit.Record("daemon.uninstalled", map[string]any{
		"service_file": st.ServiceFilePath,
	})
	fmt.Printf("Daemon: %s\n", st.Detail)
	return 0
}

func cmdDaemonStatus(args []string) int {
	_ = args
	st, err := daemon.CurrentStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon status: %v\n", err)
		return 1
	}
	fmt.Printf("Service file: %s\n", st.ServiceFilePath)
	fmt.Printf("Installed:    %t\n", st.Installed)
	fmt.Printf("Active:       %t\n", st.Active)
	if st.Detail != "" {
		fmt.Printf("Detail:       %s\n", st.Detail)
	}
	return 0
}

func cmdUnregister(args []string) int {
	hostName, all := parseHostFlag(args)

	var targets []hosts.Host
	switch {
	case hostName != "":
		h := hosts.ByName(hostName)
		if h == nil {
			fmt.Fprintf(os.Stderr, "unregister: unknown host %q\n", hostName)
			return 2
		}
		targets = []hosts.Host{h}
	case all:
		// Unregister even from hosts that aren't currently "Exists"
		// (the user may have deleted the config dir but we still
		// want to clean up any stale entry if their config file
		// still lives somewhere).
		targets = hosts.All()
	default:
		fmt.Fprintln(os.Stderr, "unregister: specify --host=NAME or --all")
		return 2
	}

	rc := 0
	for _, h := range targets {
		if err := h.Unregister(); err != nil {
			fmt.Fprintf(os.Stderr, "unregister %s: %v\n", h.Name(), err)
			rc = 1
			continue
		}
		audit.Record("host.unregistered", map[string]any{
			"host":   h.Name(),
			"config": h.ConfigPath(),
		})
		fmt.Printf("Unregistered watchdog-mcp from %s\n", h.Name())
	}
	return rc
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
