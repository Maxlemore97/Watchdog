package parsers

import (
	"fmt"
	"strings"
)

// Tokenize splits a shell-like command line into POSIX tokens while
// respecting single and double quotes and backslash escapes. Errors
// on unbalanced quotes — callers translate the error into a note so
// the adapter emits an `ask` rather than silently allowing.
//
// This replaces the Python `shlex.split(..., posix=True)` call path.
// It is intentionally narrow: we do not expand globs, variables, or
// command substitutions because we never execute the parsed string —
// we only inspect it to detect install commands.
func Tokenize(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inDouble := false
	inSingle := false
	hasToken := false
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '\\' && !inSingle && i+1 < len(runes) && runes[i+1] == '\n':
			// Line continuation: backslash-newline is removed entirely.
			i++
		case c == '\\' && !inSingle && i+1 < len(runes):
			i++
			cur.WriteRune(runes[i])
			hasToken = true
		case c == '"' && !inSingle:
			inDouble = !inDouble
			hasToken = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			hasToken = true
		case (c == ' ' || c == '\t' || c == '\n') && !inSingle && !inDouble:
			if hasToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				hasToken = false
			}
		default:
			cur.WriteRune(c)
			hasToken = true
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("malformed shell command: unbalanced quote")
	}
	if hasToken {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}

// SplitOnOperators splits cmd on top-level shell control operators
// (&&, ||, ;, |, |&, & and newline) while respecting quoting.
// Redirections (`2>&1`) and version specifiers (<, >) stay within their
// segments. Falls back to a naive split if tokenization fails (e.g.
// unbalanced quotes).
func SplitOnOperators(cmd string) []string {
	tokens, ops, err := tokenizeWithOps(cmd)
	if err != nil {
		// Naive fallback: split on &&, ||, ;
		fallback := splitNaive(cmd)
		out := make([]string, 0, len(fallback))
		for _, seg := range fallback {
			seg = strings.TrimSpace(seg)
			if seg != "" {
				out = append(out, seg)
			}
		}
		return out
	}
	segments := [][]string{{}}
	for i, tok := range tokens {
		if ops[i] {
			// Every control operator starts a new command: the right
			// side of a pipe or a backgrounded `&` runs just like the
			// right side of `&&`.
			segments = append(segments, []string{})
			continue
		}
		segments[len(segments)-1] = append(segments[len(segments)-1], tok)
	}
	out := make([]string, 0, len(segments))
	for _, seg := range segments {
		if len(seg) == 0 {
			continue
		}
		out = append(out, joinShell(seg))
	}
	return out
}

// tokenizeWithOps returns tokens alongside a parallel mask of which
// tokens are shell operators. Operators recognised: && || ; | &.
func tokenizeWithOps(s string) ([]string, []bool, error) {
	var tokens []string
	var isOp []bool
	var cur strings.Builder
	inDouble := false
	inSingle := false
	hasToken := false
	flush := func() {
		if hasToken {
			tokens = append(tokens, cur.String())
			isOp = append(isOp, false)
			cur.Reset()
			hasToken = false
		}
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '\\' && !inSingle && i+1 < len(runes) && runes[i+1] == '\n':
			// Line continuation: backslash-newline is removed entirely.
			i++
		case c == '\\' && !inSingle && i+1 < len(runes):
			i++
			cur.WriteRune(runes[i])
			hasToken = true
		case c == '"' && !inSingle:
			inDouble = !inDouble
			hasToken = true
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			hasToken = true
		case !inSingle && !inDouble && isRedirectAmp(runes, i, cur.String()):
			// `2>&1`, `&>file`, `>|file`: part of a redirection, not
			// a control operator.
			cur.WriteRune(c)
			hasToken = true
		case !inSingle && !inDouble && (c == '&' || c == '|' || c == ';' || c == '\n'):
			flush()
			// Read whole operator (&&, ||, |&, &, |, ;). A newline
			// separates commands exactly like `;`.
			op := string(c)
			if c == '\n' {
				op = ";"
			} else if i+1 < len(runes) && runes[i+1] == c && (c == '&' || c == '|') {
				op = string(c) + string(c)
				i++
			} else if c == '|' && i+1 < len(runes) && runes[i+1] == '&' {
				op = "|&"
				i++
			}
			tokens = append(tokens, op)
			isOp = append(isOp, true)
		case (c == ' ' || c == '\t' || c == '\r') && !inSingle && !inDouble:
			flush()
		default:
			cur.WriteRune(c)
			hasToken = true
		}
	}
	if inSingle || inDouble {
		return nil, nil, fmt.Errorf("malformed shell command: unbalanced quote")
	}
	flush()
	return tokens, isOp, nil
}

// isRedirectAmp reports whether the `&` or `|` at runes[i] belongs to
// a redirection (`>&`, `<&`, `&>`, `>|`) rather than being a control
// operator. cur is the token accumulated so far.
func isRedirectAmp(runes []rune, i int, cur string) bool {
	c := runes[i]
	prevRedir := strings.HasSuffix(cur, ">") || strings.HasSuffix(cur, "<")
	switch c {
	case '&':
		if prevRedir {
			return true
		}
		// `&>file` / `&>>file`, but not `&&`.
		return i+1 < len(runes) && runes[i+1] == '>'
	case '|':
		return strings.HasSuffix(cur, ">") // `>|` noclobber override
	}
	return false
}

func splitNaive(s string) []string {
	// Split on && || ;
	var out []string
	cur := strings.Builder{}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == ';' || c == '\n' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		if c == '&' || c == '|' {
			out = append(out, cur.String())
			cur.Reset()
			if i+1 < len(runes) && (runes[i+1] == c || runes[i+1] == '&') {
				i++
			}
			continue
		}
		cur.WriteRune(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// JoinShell re-quotes tokens for downstream Tokenize round-tripping.
// Single source of truth for POSIX shell quoting — also used by the
// shim-exec dispatcher when it reconstructs the install command line.
func JoinShell(tokens []string) string {
	parts := make([]string, len(tokens))
	for i, t := range tokens {
		parts[i] = ShellQuote(t)
	}
	return strings.Join(parts, " ")
}

// ShellQuote single-quotes a token using POSIX rules. Empty string
// becomes ”. A token containing only safe chars (alphanumerics and
// a small allowlist) is returned unquoted.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if IsShellSafe(s) {
		return s
	}
	// Wrap in single quotes; escape embedded single quotes via the
	// POSIX '"'"' trick.
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// IsShellSafe reports whether s is composed only of characters that
// never need shell quoting (alphanumerics + a small allowlist).
func IsShellSafe(s string) bool {
	for _, r := range s {
		safe := r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '@' || r == '%' || r == '+' || r == '=' ||
			r == ':' || r == ',' || r == '.' || r == '/' || r == '-' ||
			r == '_'
		if !safe {
			return false
		}
	}
	return true
}

// joinShell keeps the lowercase name available for
// internal callers (SplitOnOperators) without churn. They forward to
// the exported variants so behavior stays single-sourced.
func joinShell(tokens []string) string { return JoinShell(tokens) }
