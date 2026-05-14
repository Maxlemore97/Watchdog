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

// SplitOnOperators splits cmd on top-level shell operators (&&, ||, ;)
// while respecting quoting. Other operators (|, &) and version
// specifiers (<, >) are preserved within their segments. Falls back to
// a naive split if tokenization fails (e.g. unbalanced quotes).
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
			if tok == "&&" || tok == "||" || tok == ";" {
				segments = append(segments, []string{})
				continue
			}
			// |, & — kept inside segment as their own token
			segments[len(segments)-1] = append(segments[len(segments)-1], tok)
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
		case !inSingle && !inDouble && (c == '&' || c == '|' || c == ';'):
			flush()
			// Read whole operator (&&, ||, &, |, ;)
			op := string(c)
			if i+1 < len(runes) && runes[i+1] == c && (c == '&' || c == '|') {
				op = string(c) + string(c)
				i++
			}
			tokens = append(tokens, op)
			isOp = append(isOp, true)
		case (c == ' ' || c == '\t' || c == '\n') && !inSingle && !inDouble:
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

func splitNaive(s string) []string {
	// Split on && || ;
	var out []string
	cur := strings.Builder{}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		if c == ';' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		if (c == '&' || c == '|') && i+1 < len(runes) && runes[i+1] == c {
			out = append(out, cur.String())
			cur.Reset()
			i++
			continue
		}
		cur.WriteRune(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// joinShell re-quotes tokens for downstream Tokenize round-tripping.
func joinShell(tokens []string) string {
	parts := make([]string, len(tokens))
	for i, t := range tokens {
		parts[i] = shellQuote(t)
	}
	return strings.Join(parts, " ")
}

// shellQuote single-quotes a token using POSIX rules. Empty string
// becomes ''. A token containing only safe chars (alphanumerics and
// a small allowlist) is returned unquoted.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if isShellSafe(s) {
		return s
	}
	// Wrap in single quotes; escape embedded single quotes via the
	// POSIX '"'"' trick.
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func isShellSafe(s string) bool {
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
