package parsers

import (
	"regexp"
	"strings"
)

// Command-normalisation helpers shared by the install parser and the
// tamper scanner. An agent can wrap an install in prefixes (`env`,
// `sudo`, `command`, `xargs`, `VAR=x`), shell keywords (`then`, `do`),
// grouping (`(npm i x)`, `{ npm i x; }`) or redirections — none of
// which change what runs. stripCommandPrefixes peels those away so the
// install verb lands in tokens[0].

// prefixCommands are wrappers that run their trailing argv as a
// command. Value = flags that consume the following token.
var prefixCommands = map[string]map[string]bool{
	"env":        {"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true, "--split-string": true},
	"sudo":       {"-u": true, "-g": true, "-U": true, "-p": true, "-C": true, "-D": true, "-h": true, "-r": true, "-t": true, "-T": true},
	"doas":       {"-u": true, "-C": true},
	"command":    {},
	"builtin":    {},
	"exec":       {"-a": true},
	"nohup":      {},
	"time":       {"-f": true, "--format": true, "-o": true, "--output": true},
	"nice":       {"-n": true, "--adjustment": true},
	"ionice":     {"-c": true, "-n": true, "-p": true},
	"stdbuf":     {"-i": true, "-o": true, "-e": true},
	"caffeinate": {"-t": true, "-w": true},
	"timeout":    {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
	"xargs": {
		"-I": true, "-n": true, "-P": true, "-L": true, "-d": true,
		"-a": true, "-E": true, "-s": true, "--max-args": true, "--max-procs": true,
		"--delimiter": true, "--arg-file": true, "--replace": true,
	},
}

// positionalPrefixArgs: wrappers that take N positional args before
// the wrapped command (e.g. `timeout 30 npm i x`).
var positionalPrefixArgs = map[string]int{"timeout": 1}

// shellKeywords never change which program runs next.
var shellKeywords = map[string]bool{
	"then": true, "do": true, "else": true, "elif": true, "if": true,
	"while": true, "until": true, "!": true, "{": true, "(": true,
}

var envAssignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// redirectRE matches a redirection token: optional fd, operator,
// optional inline target. Group 2 empty → the target is the next token.
var redirectRE = regexp.MustCompile(`^[0-9]*(?:&>>?|>>?&?|<<?<?|<&|>\|)(.*)$`)

// stripped is the result of peeling prefixes off a token list.
type stripped struct {
	tokens  []string // remaining argv, tokens[0] = real command
	envs    []string // VAR=value assignments seen in prefix position
	viaArgs string   // non-empty when argv is extended at runtime (xargs)
}

// stripCommandPrefixes removes env assignments, wrapper commands,
// shell keywords and grouping punctuation from the front of tokens,
// and drops redirection tokens everywhere. Bounded to avoid pathological
// inputs looping.
func stripCommandPrefixes(tokens []string) stripped {
	var out stripped
	toks := dropRedirections(tokens)
	for guard := 0; guard < 16 && len(toks) > 0; guard++ {
		head := toks[0]
		// Grouping: `(npm`, `{`, `$(npm` are handled by trimming the
		// leading punctuation; a bare `(`/`{` is a keyword.
		if trimmed := strings.TrimLeft(head, "({"); trimmed != head {
			if trimmed == "" {
				toks = toks[1:]
			} else {
				toks = append([]string{trimmed}, toks[1:]...)
			}
			continue
		}
		if shellKeywords[head] {
			toks = toks[1:]
			continue
		}
		if envAssignRE.MatchString(head) {
			out.envs = append(out.envs, head)
			toks = toks[1:]
			continue
		}
		base := lastPathSegment(head)
		flags, ok := prefixCommands[base]
		if !ok {
			break
		}
		if base == "xargs" {
			out.viaArgs = "xargs"
		}
		i := 1
		for i < len(toks) {
			t := toks[i]
			if t == "--" {
				i++
				break
			}
			if !strings.HasPrefix(t, "-") || t == "-" {
				break
			}
			if strings.Contains(t, "=") { // --flag=value
				i++
				continue
			}
			if flags[t] {
				i += 2
				continue
			}
			i++
		}
		// env also accepts VAR=val assignments after its flags.
		if base == "env" {
			for i < len(toks) && envAssignRE.MatchString(toks[i]) {
				out.envs = append(out.envs, toks[i])
				i++
			}
		}
		i += positionalPrefixArgs[base]
		if i > len(toks) {
			i = len(toks)
		}
		toks = toks[i:]
	}
	// Trailing grouping punctuation: `evil)` / `evil;}` leftovers.
	for i := range toks {
		toks[i] = strings.TrimRight(toks[i], ")}")
	}
	clean := toks[:0]
	for _, t := range toks {
		if t != "" {
			clean = append(clean, t)
		}
	}
	out.tokens = clean
	return out
}

// dropRedirections removes `>file`, `2>&1`, `> file`, `<in` etc. so a
// redirection target is never mistaken for a package name.
func dropRedirections(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		// redirectRE only matches tokens that start with a digit or an
		// operator, so pip specifiers like `requests>=2` never match.
		if m := redirectRE.FindStringSubmatch(t); m != nil {
			if m[1] == "" {
				i++ // target is the next token
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

// registryEnvPrefixes are environment variables that redirect a
// package manager to a different registry/index. Seeing one in an
// install's prefix means the scanned artifact may not be what gets
// installed.
var registryEnvPrefixes = []string{
	"NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG",
	"NPM_CONFIG_@", // scoped registries: npm_config_@scope:registry
	"YARN_NPM_REGISTRY_SERVER", "YARN_REGISTRY",
	"BUN_CONFIG_REGISTRY",
	"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE",
	"UV_INDEX", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_FIND_LINKS",
	"POETRY_REPOSITORIES_",
	"CARGO_REGISTRIES_", "CARGO_REGISTRY_",
	"GOPROXY", "GOFLAGS", "GONOSUMDB", "GONOSUMCHECK", "GOSUMDB", "GOPRIVATE", "GOINSECURE",
	"COMPOSER_", "GEM_SOURCE", "HOMEBREW_BOTTLE_DOMAIN", "HOMEBREW_API_DOMAIN",
	"NUGET_",
}

// registryEnvNotes returns a note for each env assignment that
// redirects package resolution.
func registryEnvNotes(envs []string) []string {
	var notes []string
	for _, e := range envs {
		name := strings.ToUpper(e[:strings.Index(e, "=")])
		for _, p := range registryEnvPrefixes {
			if strings.HasPrefix(name, p) {
				notes = append(notes, "registry override via environment: "+name)
				break
			}
		}
	}
	return notes
}

// heredocRE matches a here-document operator (`<<EOF`, `<<-'EOF'`,
// `<< "EOF"`) but not a here-string (`<<<`).
var heredocRE = regexp.MustCompile(`(?:^|[^<])<<(-?)[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)(['"]?)`)

// splitHeredocs removes here-document bodies from cmd and returns the
// remaining command text plus the bodies that will execute as shell
// code. A body is shell code when the line feeding it runs a shell
// (`bash <<EOF`, `cat <<EOF | sh`, `eval`/`source`); otherwise it is
// data (`python3 - <<EOF`, `cat > f <<EOF`) and only its command
// substitutions run — and only when the delimiter is unquoted.
func splitHeredocs(cmd string) (string, []string) {
	if !strings.Contains(cmd, "<<") {
		return cmd, nil
	}
	lines := strings.Split(cmd, "\n")
	var outer, bodies []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		outer = append(outer, line)
		ms := heredocRE.FindAllStringSubmatch(line, -1)
		if len(ms) == 0 {
			continue
		}
		feedsShell := lineFeedsShell(line)
		for _, m := range ms {
			stripTabs, quoted, delim := m[1] == "-", m[2] != "", m[3]
			var body []string
			for i+1 < len(lines) {
				i++
				l := lines[i]
				if stripTabs {
					l = strings.TrimLeft(l, "\t")
				}
				if l == delim {
					break
				}
				body = append(body, lines[i])
			}
			text := strings.Join(body, "\n")
			switch {
			case feedsShell:
				bodies = append(bodies, text)
			case !quoted:
				bodies = append(bodies, ExtractSubstitutions(text)...)
			}
		}
	}
	return strings.Join(outer, "\n"), bodies
}

// lineFeedsShell reports whether any command on a heredoc line is a
// shell interpreter reading stdin, or eval/source.
func lineFeedsShell(line string) bool {
	for _, seg := range SplitOnOperators(line) {
		toks, err := Tokenize(seg)
		if err != nil {
			return true // cannot tell — treat as code
		}
		st := stripCommandPrefixes(toks)
		if len(st.tokens) == 0 {
			continue
		}
		head := normalizeBinary(st.tokens[0])
		if shellBinaries[head] || head == "eval" || head == "source" || head == "." {
			return true
		}
	}
	return false
}
