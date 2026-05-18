// watchdog-shim-exec: per-call shim dispatcher. Invoked as
//
//	watchdog-shim-exec <toolname> <args...>
//
// Each wrapper script in the shim dir invokes this binary with the
// tool name as first arg. We reconstruct the install command,
// classify it via parsers.CollectPackages, run the shared preflight
// for any detected install, and either exec the real binary (allow),
// exit 1 (deny), or prompt on a TTY (ask).
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/audit"
	"github.com/Maxlemore97/watchdog/internal/cli"
	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/decisions"
	"github.com/Maxlemore97/watchdog/internal/integrity"
	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/preflight"
	"github.com/Maxlemore97/watchdog/internal/shim"
)

func mode() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_MODE")))
	if !preflight.ValidModes[v] {
		return "both"
	}
	return v
}

// failClosedVerdict picks the verdict to emit when a check cannot
// run (OSV unreachable, LLM CLI missing, analyzer panic). The shim's
// default is `deny`, unlike the Claude Code hook (`ask`), because the
// shim has no host UI to surface a question through.
func failClosedVerdict() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_FAILCLOSED_VERDICT")))
	switch v {
	case "allow", "deny", "ask":
		return v
	}
	return "deny"
}

func shimDir() string {
	if v := os.Getenv("WATCHDOG_SHIM_DIR"); v != "" {
		return v
	}
	return shim.DefaultShimDir()
}

// execReal replaces this process with the real binary. Implemented in
// exec_unix.go (syscall.Exec for true argv[0] semantics) and
// exec_windows.go (spawn child and exit with its status — Windows has
// no exec-in-place primitive).

func confirmTTY(reason string) bool {
	fmt.Fprintf(os.Stderr, "watchdog: %s\n", reason)
	fmt.Fprint(os.Stderr, "Proceed with install? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(answer))
	return a == "y" || a == "yes"
}

func resolveDecision(verdict, reason string) bool {
	switch verdict {
	case "allow":
		return true
	case "deny":
		fmt.Fprintf(os.Stderr, "watchdog: blocked install. %s\n", reason)
		return false
	}
	// ask
	if cli.IsTerminal(os.Stdin) && cli.IsTerminal(os.Stderr) {
		return confirmTTY(reason)
	}
	fallback := failClosedVerdict()
	fmt.Fprintf(os.Stderr, "watchdog: %s (no TTY, falling back to %s)\n", reason, fallback)
	return fallback == "allow"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "watchdog-shim-exec: missing tool name")
		os.Exit(2)
	}
	// Validate env config at startup unless disabled. We do this AFTER
	// the args check (so a malformed invocation still gets the clear
	// "missing tool name" message) but BEFORE any env-derived branches.
	if !config.Disabled() {
		_ = config.MustLoad()
	}
	toolname := filepath.Base(os.Args[1])
	// On Windows, strip a trailing .cmd/.exe from argv[0] so we look up
	// the real `npm`, not `npm.cmd`.
	for _, ext := range []string{".cmd", ".exe", ".bat"} {
		if strings.HasSuffix(strings.ToLower(toolname), ext) {
			toolname = toolname[:len(toolname)-len(ext)]
			break
		}
	}
	toolArgs := os.Args[2:]

	real := shim.FindRealBinary(toolname, []string{shimDir()})
	if real == "" {
		fmt.Fprintf(os.Stderr, "watchdog-shim-exec: real binary %q not found on PATH (after excluding shim dir %s)\n",
			toolname, shimDir())
		os.Exit(127)
	}

	// Visibility: if user has the shim dir on PATH but NOT first,
	// some installs may resolve to the real binary directly,
	// bypassing watchdog. Warn once per invocation, only on a TTY so
	// CI logs don't get noisy.
	if cli.IsTerminal(os.Stderr) && !shim.IsShimDirFirstOnPath(shimDir()) {
		fmt.Fprintln(os.Stderr,
			"watchdog: WARNING — shim dir not first on PATH; installs may bypass scanning. Run `watchdog-shim doctor` for the fix.")
	}

	if config.Disabled() {
		os.Exit(execReal(real, toolname, toolArgs))
	}
	if !shim.IsShimmed(toolname) {
		os.Exit(execReal(real, toolname, toolArgs))
	}

	// Reconstruct the install command via shell-quote join.
	cmdParts := append([]string{toolname}, toolArgs...)
	cmdLine := parsers.JoinShell(cmdParts)
	pkgs, notes := parsers.CollectPackages(cmdLine, osv.ResolveVersion)

	if len(pkgs) == 0 && len(notes) == 0 {
		os.Exit(execReal(real, toolname, toolArgs))
	}

	// Integrity gate. The shim only ever sees install-shaped invocations
	// here, so any verified failure should fail-closed. ManifestMissing
	// is treated as back-compat (no `watchdog-shim install` was ever
	// run) and falls through to the regular preflight.
	st := integrity.Verify()
	if !st.OK && !st.Disabled && !st.ManifestMissing {
		audit.Record("integrity.deny", map[string]any{
			"tool":     "shim-exec",
			"binary":   toolname,
			"reason":   "integrity_failed",
			"failures": st.Failures,
		})
		fmt.Fprintf(os.Stderr,
			"watchdog: integrity check failed (%s) — refusing install. Run `watchdog-shim doctor` to diagnose.\n",
			st.FirstReason())
		os.Exit(1)
	}

	// Decision-token short-circuit. If an MCP-aware agent already
	// preflighted this exact command (within TTL), honour the cached
	// verdict instead of re-running OSV/LLM. Cache key is sha256 of
	// the canonical command — see internal/decisions for properties.
	if t, err := decisions.Read(cmdLine); err == nil {
		switch t.Verdict {
		case "allow":
			os.Exit(execReal(real, toolname, toolArgs))
		case "deny":
			fmt.Fprintf(os.Stderr,
				"watchdog: blocked install (MCP-cached decision). %s\n", t.Reason)
			os.Exit(1)
		}
	} else if !errors.Is(err, decisions.ErrNoDecision) &&
		!errors.Is(err, decisions.ErrExpired) &&
		!errors.Is(err, decisions.ErrUnsignedToken) {
		// Corrupt token or unexpected I/O — fall through to full
		// preflight rather than fail hard. The error is already in
		// the audit log.
		_ = err
	}

	result := preflight.Packages(pkgs, notes, preflight.Options{
		Mode:              mode(),
		FailClosedVerdict: failClosedVerdict(),
	})
	if resolveDecision(result.Verdict, result.Reason) {
		os.Exit(execReal(real, toolname, toolArgs))
	}
	os.Exit(1)
}
