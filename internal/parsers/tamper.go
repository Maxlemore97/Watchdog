package parsers

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Tamper codes — stable strings logged to the audit log and surfaced
// in permissionDecisionReason. Match what the plan and the audit
// schema expect; do not rename without bumping the audit schema.
const (
	TamperUnsetPath        = "UNSET_PATH"
	TamperPathOverride     = "PATH_OVERRIDE"
	TamperAbsPathInstall   = "ABS_PATH_INSTALL"
	TamperSettingsJSONEdit = "SETTINGS_JSON_EDIT"
	TamperWatchdogKill     = "WATCHDOG_KILL"
	TamperWatchdogRemove   = "WATCHDOG_REMOVE"
	TamperManifestTamper   = "MANIFEST_TAMPER"
	// TamperWatchdogEnv: the command sets a WATCHDOG_* variable
	// (`WATCHDOG_DISABLE=1 npm i x`, `export WATCHDOG_MODE=osv`). Every
	// Watchdog binary reads its configuration from the environment, so
	// an agent-controlled assignment can switch scanning off for the
	// child process. Configuration belongs in the user's shell profile,
	// not in an agent-issued command.
	TamperWatchdogEnv = "WATCHDOG_ENV_OVERRIDE"
)

// Cheap, broad regexes used for whole-command matches. Anchors are
// deliberately loose because the tokens may appear inside quoted
// strings, redirections, or subshells — we err on the side of
// over-matching, since this is a security check.
var (
	// settingsJSONRE matches user-level agent-host configs that
	// register hooks or MCP servers: Claude Code, Claude Desktop,
	// Cursor, Windsurf, Cline, Continue, Zed, VS Code, Gemini CLI,
	// Codex. Project-level `.mcp.json` is excluded — editing it is a
	// routine request and goes through the Edit/Write guard instead.
	settingsJSONRE = regexp.MustCompile(`(?i)` +
		`\.claude/settings(\.local)?\.json|\.claude\.json\b|claude_desktop_config\.json|` +
		`\.cursor/mcp\.json|\.codeium/windsurf/mcp_config\.json|cline_mcp_settings\.json|` +
		`\.continue/config\.(json|ya?ml)|zed/settings\.json|code/user/(settings|mcp)\.json|` +
		`\.gemini/settings\.json|\.codex/config\.toml`)
	interpreterWriteRE = regexp.MustCompile(`(?i)\bopen\([^)]*['"][wax]\+?b?['"]|` +
		`\.write(_text|_bytes)?\(|\bwritefile(sync)?\b|\bappendfile(sync)?\b|` +
		`\b(os|shutil)\.(remove|unlink|rename|replace|rmtree|move)\b|\.unlink\(|` +
		`\bfs\.(rm|rmsync|unlinksync|unlink|renamesync|rename|copyfilesync|cpsync)\b|` +
		`\bfile\.(write|delete)\b|\bfileutils\.|\bunlink\s*\(|` +
		`set-content|out-file|remove-item|add-content`)
	manifestPathRE = regexp.MustCompile(`(?:^|[/\s'"])\.watchdog/manifest\.json\b`)
	// Watchdog process names: pkill / killall accept basenames.
	watchdogProcRE = regexp.MustCompile(`\bwatchdog-(pretool|prompt|session|shim|shim-exec|mcp|scan|action)\b`)
	watchdogEnvRE  = regexp.MustCompile(`^WATCHDOG_[A-Za-z0-9_]*=`)
)

// TamperPatterns inspects a shell command for signatures of attempts
// to disable, evade, or remove Watchdog. Returns a sorted, deduped
// list of matched codes (empty = clean).
//
// Conservative: prefers false positives (over-blocking) to false
// negatives (under-blocking). Walks subshells recursively up to a
// shallow depth so `bash -c "unset PATH; npm install evil"` is
// caught.
func TamperPatterns(cmd string) []string {
	hits := map[string]bool{}
	scan(cmd, hits, 0)
	if len(hits) == 0 {
		return nil
	}
	out := make([]string, 0, len(hits))
	for code := range hits {
		out = append(out, code)
	}
	// Stable order so audit-log entries and tests are deterministic.
	sortStrings(out)
	return out
}

func scan(cmd string, hits map[string]bool, depth int) {
	if cmd == "" || depth > 3 {
		return
	}

	// Whole-command regex checks — match through quotes and redirects.
	if settingsJSONRE.MatchString(cmd) {
		// Only flag when paired with a write/edit/delete verb. Reading
		// settings.json is fine.
		if hasWriteVerb(cmd) {
			hits[TamperSettingsJSONEdit] = true
		}
	}
	if manifestPathRE.MatchString(cmd) && hasWriteVerb(cmd) {
		hits[TamperManifestTamper] = true
	}

	// Token-level checks per shell-operator segment. Here-document
	// bodies are data unless a shell reads them (then: nested script).
	cmd, bodies := splitHeredocs(cmd)
	for _, b := range bodies {
		scan(b, hits, depth+1)
	}
	for _, seg := range SplitOnOperators(cmd) {
		tokens, err := Tokenize(strings.TrimSpace(seg))
		if err != nil || len(tokens) == 0 {
			continue
		}
		scanTokens(tokens, hits)
	}

	// Recurse into subshells: `bash -c "..."`.
	for _, inner := range ExtractSubshells(cmd) {
		scan(inner, hits, depth+1)
	}
}

func scanTokens(tokens []string, hits map[string]bool) {
	// 1. PATH manipulation: `unset PATH`, `PATH=...`, `env -u PATH`, etc.
	for i, tok := range tokens {
		// `unset PATH` or `unset -v PATH` or `unset FOO PATH BAR`.
		if tok == "unset" {
			for _, rest := range tokens[i+1:] {
				if rest == "PATH" {
					hits[TamperUnsetPath] = true
					break
				}
			}
		}
		// `env -u PATH ...`.
		if tok == "env" {
			for j := i + 1; j+1 < len(tokens); j++ {
				if tokens[j] == "-u" && tokens[j+1] == "PATH" {
					hits[TamperUnsetPath] = true
					break
				}
			}
		}
	}
	// `PATH=...` / `WATCHDOG_*=...` — only tokens in assignment
	// position count: command prefixes (`PATH=x npm i`, `sudo
	// WATCHDOG_DISABLE=1 …`, `env PATH=x …`) and arguments of the
	// assignment builtins (`export PATH=…`, `declare -x WATCHDOG_X=…`).
	// The same text as an ordinary argument (`grep 'PATH=' f`,
	// `echo WATCHDOG_MODE=osv`) assigns nothing.
	for _, a := range assignmentTokens(tokens) {
		if strings.HasPrefix(a, "PATH=") {
			hits[TamperPathOverride] = true
		}
		if watchdogEnvRE.MatchString(a) {
			hits[TamperWatchdogEnv] = true
		}
	}
	// macOS `launchctl setenv WATCHDOG_X …` sets it for GUI apps.
	if st := stripCommandPrefixes(tokens); len(st.tokens) > 2 &&
		filepath.Base(st.tokens[0]) == "launchctl" && st.tokens[1] == "setenv" &&
		(strings.HasPrefix(st.tokens[2], "WATCHDOG_") || st.tokens[2] == "PATH") {
		if st.tokens[2] == "PATH" {
			hits[TamperPathOverride] = true
		} else {
			hits[TamperWatchdogEnv] = true
		}
	}

	// 2. Path-qualified package manager + install subcommand
	//    (`/opt/homebrew/bin/npm install x`, `./node_modules/.bin/pnpm
	//    add x`). A path skips PATH lookup and therefore the shim.
	//    Wrapper prefixes (`sudo`, `env`, `VAR=x`) are peeled first.
	st := stripCommandPrefixes(tokens)
	if len(st.tokens) > 0 {
		head := st.tokens[0]
		if strings.ContainsAny(head, "/\\") || strings.HasPrefix(head, "~") {
			if _, viaPython, ok := detectInstall(st.tokens); ok && !viaPython {
				hits[TamperAbsPathInstall] = true
			}
		}
	}

	// 3. pkill / killall against watchdog-*.
	if len(st.tokens) > 0 {
		head := filepath.Base(st.tokens[0])
		if head == "pkill" || head == "killall" {
			for _, rest := range st.tokens[1:] {
				if strings.HasPrefix(rest, "watchdog") {
					hits[TamperWatchdogKill] = true
					break
				}
				// `pkill -f watchdog` — argv across flags.
				if watchdogProcRE.MatchString(rest) {
					hits[TamperWatchdogKill] = true
					break
				}
			}
		}
	}

	// 4. rm / mv / chmod against ~/.watchdog/ or its contents.
	if len(st.tokens) > 0 {
		head := filepath.Base(st.tokens[0])
		switch head {
		case "rm", "mv", "chmod", "chown", "unlink", "truncate", "shred":
			for _, rest := range st.tokens[1:] {
				if isWatchdogPath(rest) {
					hits[TamperWatchdogRemove] = true
					// Manifest-specific: bump the more-specific code too.
					if strings.Contains(rest, "manifest.json") {
						hits[TamperManifestTamper] = true
					}
				}
			}
		}
	}
}

// TamperWatchdogStateEdit: a file-editing tool (Edit/Write/…) targets
// Watchdog's own state or shim directory.
const TamperWatchdogStateEdit = "WATCHDOG_STATE_EDIT"

// WritePathVerdict classifies a path that a file-editing agent tool
// (Edit, Write, MultiEdit, NotebookEdit) is about to write. Those
// tools never pass through the Bash checks, so this is the only gate
// for them.
//
//   - Watchdog state or shim dir → "deny" (WATCHDOG_STATE_EDIT)
//   - agent-host hook/MCP config (user-level settings, project
//     .mcp.json, .claude/settings*.json) → "ask" (SETTINGS_JSON_EDIT):
//     legitimate on request, but the user should see it happen
//   - anything else → "" (no opinion)
func WritePathVerdict(p, watchdogDir, shimDir string) (verdict, code string) {
	if p == "" {
		return "", ""
	}
	clean := filepath.Clean(p)
	for _, dir := range []string{watchdogDir, shimDir} {
		if dir == "" {
			continue
		}
		d := filepath.Clean(dir)
		if clean == d || strings.HasPrefix(clean, d+string(filepath.Separator)) {
			return "deny", TamperWatchdogStateEdit
		}
	}
	slash := filepath.ToSlash(clean)
	if settingsJSONRE.MatchString(slash) || strings.EqualFold(filepath.Base(clean), ".mcp.json") {
		return "ask", TamperSettingsJSONEdit
	}
	return "", ""
}

// assignmentBuiltins take NAME=value arguments that modify the
// shell environment.
var assignmentBuiltins = map[string]bool{
	"export": true, "declare": true, "typeset": true, "local": true, "readonly": true,
}

// assignmentTokens returns the NAME=value tokens of a segment that
// actually assign: prefix assignments (also after env/sudo/command
// wrappers) and arguments of export/declare/typeset/local/readonly.
func assignmentTokens(tokens []string) []string {
	st := stripCommandPrefixes(tokens)
	out := append([]string{}, st.envs...)
	if len(st.tokens) > 0 && assignmentBuiltins[st.tokens[0]] {
		for _, t := range st.tokens[1:] {
			if envAssignRE.MatchString(t) {
				out = append(out, t)
			}
		}
	}
	return out
}

// isWatchdogPath reports whether tok refers to ~/.watchdog or any
// path beneath it. Accepts tilde-prefixed paths and absolute paths
// under any user's home directory (since agents may resolve $HOME).
func isWatchdogPath(tok string) bool {
	// Strip surrounding quotes if Tokenize left them (it shouldn't,
	// but defensive).
	t := strings.Trim(tok, `"'`)
	if strings.HasPrefix(t, "~/.watchdog") {
		return true
	}
	// Match anywhere in path: covers `/Users/foo/.watchdog/...` and
	// `/home/foo/.watchdog/...`.
	return strings.Contains(t, "/.watchdog/") || strings.HasSuffix(t, "/.watchdog")
}

// hasWriteVerb reports whether the command contains a verb commonly
// used to write or delete a file. Conservative: looks at the raw
// string (post-quoting) so redirections like `>` and `>>` count.
func hasWriteVerb(cmd string) bool {
	// Quick path: redirection operators.
	if strings.Contains(cmd, ">") {
		return true
	}
	// Inline interpreter code that writes or deletes files
	// (`python3 -c "open(p,'w')…"`, `node -e "fs.rmSync(p)"`, a
	// `python3 - <<EOF` heredoc). Reads stay allowed.
	if interpreterWriteRE.MatchString(cmd) {
		return true
	}
	// Token-level command names.
	tokens, err := Tokenize(cmd)
	if err != nil {
		// Unparseable: cannot rule a write out.
		return true
	}
	for i, tok := range tokens {
		head := filepath.Base(tok)
		switch head {
		case "rm", "mv", "cp", "tee", "ln", "dd", "truncate", "install", "rsync",
			"sponge", "shred", "unlink", "touch", "chmod", "chown", "patch", "ed", "ex":
			return true
		case "perl", "ruby":
			for _, rest := range tokens[i+1:] {
				if strings.HasPrefix(rest, "-i") || strings.HasPrefix(rest, "-pi") {
					return true
				}
			}
		case "sed":
			// Only flag in-place edits.
			for _, rest := range tokens[i+1:] {
				if rest == "-i" || strings.HasPrefix(rest, "-i") {
					return true
				}
			}
		case "echo", "printf", "cat":
			// These only write when paired with `>`/`>>`/`tee`, which
			// the quick path above already caught.
		case "jq":
			// jq is read-only without -i (which jq doesn't have); ignore.
		}
	}
	return false
}

// sortStrings is a tiny dependency-free string sort so this file can
// stay outside `sort` if we ever vendor; right now just calls into the
// standard sort.Strings.
func sortStrings(s []string) {
	// Use insertion sort: lists are tiny (≤ 7 entries).
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
