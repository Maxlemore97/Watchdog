// Package hiddentext finds characters that render invisibly (or
// reorder what is shown) but are still read by an LLM or a compiler:
// the delivery channel of "rules file backdoor" style prompt
// injection in CLAUDE.md, SKILL.md, .cursorrules and MCP tool
// descriptions, of Trojan Source bidi tricks in code, and of
// GlassWorm-style payloads encoded in variation selectors.
//
// The check is deterministic and runs before any LLM: models often do
// not "see" these characters the way a reviewer would, and a human
// reading the file sees nothing at all.
package hiddentext

import (
	"fmt"
	"strings"
	"unicode"
)

// Findings counts suspicious code points in one text.
type Findings struct {
	// TagChars: Unicode tag block U+E0000–U+E007F outside emoji flag
	// sequences. Each maps 1:1 to an ASCII character, so a run of them
	// is invisible ASCII text — Decoded holds it.
	TagChars int
	Decoded  string
	// Bidi: embedding/override/isolate controls U+202A–U+202E,
	// U+2066–U+2069 (Trojan Source).
	Bidi int
	// ZeroWidth: zero-width space/non-joiner, word joiner, invisible
	// operators, Mongolian vowel separator, and BOMs past offset 0.
	// The zero-width joiner U+200D is excluded: emoji sequences use it.
	ZeroWidth int
	// VariationSupplement: U+E0100–U+E01EF not attached to a CJK
	// ideograph (where ideographic variation sequences legitimately
	// use them). Long runs encode binary payloads.
	VariationSupplement int
}

// Thresholds above which a finding is reported. Tag characters and
// bidi controls have no business in agent instructions, so one is
// enough; zero-width characters and variation selectors show up in
// pasted text, so only runs count.
const (
	zeroWidthThreshold = 10
	variationThreshold = 4
)

// Scan inspects s.
func Scan(s string) Findings {
	var f Findings
	var decoded strings.Builder
	runes := []rune(s)
	inFlag := false // inside a 🏴 + tag + cancel-tag flag sequence
	for i, r := range runes {
		switch {
		case r == 0x1F3F4: // WAVING BLACK FLAG starts subdivision flags
			inFlag = true
		case r >= 0xE0000 && r <= 0xE007F:
			if inFlag {
				if r == 0xE007F { // CANCEL TAG ends the flag
					inFlag = false
				}
				continue
			}
			f.TagChars++
			if c := r - 0xE0000; c >= 0x20 && c < 0x7F && decoded.Len() < 200 {
				decoded.WriteRune(c)
			}
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			f.Bidi++
		case r == 0x200B, r == 0x200C, r == 0x2060, r >= 0x2061 && r <= 0x2064, r == 0x180E:
			f.ZeroWidth++
		case r == 0xFEFF && i > 0:
			f.ZeroWidth++
		case r >= 0xE0100 && r <= 0xE01EF:
			if i == 0 || !unicode.Is(unicode.Han, runes[i-1]) {
				f.VariationSupplement++
			}
		default:
			inFlag = false
		}
	}
	f.Decoded = decoded.String()
	return f
}

// Verdict maps findings to a decision. code=true for executable
// content, where bidi controls are Trojan Source; in prose (Markdown
// docs, instructions) they are only suspicious. Returns "" when
// nothing crosses a threshold.
func (f Findings) Verdict(code bool) (verdict, reason string) {
	switch {
	case f.TagChars > 0:
		msg := fmt.Sprintf("hidden Unicode tag characters (%d)", f.TagChars)
		if f.Decoded != "" {
			msg += fmt.Sprintf(", decoding to %q", f.Decoded)
		}
		return "deny", msg
	case f.VariationSupplement >= variationThreshold:
		return "deny", fmt.Sprintf("%d stray Unicode variation selectors (encoded payload)", f.VariationSupplement)
	case f.Bidi > 0 && code:
		return "deny", fmt.Sprintf("bidirectional control characters in code (%d, Trojan Source)", f.Bidi)
	case f.Bidi > 0:
		return "ask", fmt.Sprintf("bidirectional control characters (%d) can reorder what a reviewer sees", f.Bidi)
	case f.ZeroWidth >= zeroWidthThreshold:
		return "ask", fmt.Sprintf("%d zero-width characters (possible hidden text)", f.ZeroWidth)
	}
	return "", ""
}
