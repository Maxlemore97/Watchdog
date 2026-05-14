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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Maxlemore97/watchdog/internal/osv"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/preflight"
	"github.com/Maxlemore97/watchdog/internal/shim"
)

func disabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_DISABLE")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func mode() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_MODE")))
	if !preflight.ValidModes[v] {
		return "both"
	}
	return v
}

// Shim's offline default is `deny`, unlike the Claude Code hook
// (`ask`), because the shim has no host UI to surface a question to.
func offlineDecision() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("WATCHDOG_OFFLINE_DECISION")))
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

// execReal replaces this process with the real binary. On Unix uses
// syscall.Exec for true argv[0] semantics; on Windows spawns a child
// and exits with its status.
func execReal(real, toolname string, args []string) int {
	argv := append([]string{toolname}, args...)
	if err := syscall.Exec(real, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog-shim: failed to exec %s: %v\n", real, err)
		return 127
	}
	return 0 // unreachable
}

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

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
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
	if isTTY(os.Stdin) && isTTY(os.Stderr) {
		return confirmTTY(reason)
	}
	fallback := offlineDecision()
	fmt.Fprintf(os.Stderr, "watchdog: %s (no TTY, falling back to %s)\n", reason, fallback)
	return fallback == "allow"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "watchdog-shim-exec: missing tool name")
		os.Exit(2)
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

	if disabled() {
		os.Exit(execReal(real, toolname, toolArgs))
	}
	if !shim.IsShimmed(toolname) {
		os.Exit(execReal(real, toolname, toolArgs))
	}

	// Reconstruct the install command via shell-quote join.
	cmdParts := append([]string{toolname}, toolArgs...)
	cmdLine := joinShell(cmdParts)
	pkgs, notes := parsers.CollectPackages(cmdLine, osv.ResolveVersion)

	if len(pkgs) == 0 && len(notes) == 0 {
		os.Exit(execReal(real, toolname, toolArgs))
	}

	result := preflight.Packages(pkgs, notes, preflight.Options{
		Mode:            mode(),
		OfflineDecision: offlineDecision(),
	})
	if resolveDecision(result.Verdict, result.Reason) {
		os.Exit(execReal(real, toolname, toolArgs))
	}
	os.Exit(1)
}

// joinShell single-quotes tokens for downstream tokenizer round-trip.
func joinShell(tokens []string) string {
	parts := make([]string, len(tokens))
	for i, t := range tokens {
		parts[i] = shellQuote(t)
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '@' || r == '%' || r == '+' || r == '=' ||
			r == ':' || r == ',' || r == '.' || r == '/' || r == '-' || r == '_'
		if !ok {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
