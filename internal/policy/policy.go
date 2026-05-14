// Package policy aggregates verdicts. The three permission decisions
// are ordered from least to most restrictive: allow < ask < deny.
// Multiple verdicts (e.g. one per package in a chained install) are
// combined by taking the worst.
package policy

// Rank returns the precedence of a verdict string. Unknown verdicts
// collapse to "ask" (1) as the conservative default: anything we
// don't recognise gets human review.
func Rank(verdict string) int {
	switch verdict {
	case "allow":
		return 0
	case "ask":
		return 1
	case "deny":
		return 2
	default:
		return 1
	}
}

// WorstVerdict returns the worst verdict by Rank, normalized to one
// of allow/ask/deny. Empty input → "ask". Unknown strings collapse to
// "ask" (matching Rank's conservative default) so callers comparing
// the result by string see canonical values, never the raw input.
func WorstVerdict(verdicts []string) string {
	best := ""
	for _, v := range verdicts {
		if best == "" || Rank(v) > Rank(best) {
			best = v
		}
	}
	switch best {
	case "allow", "ask", "deny":
		return best
	}
	return "ask"
}
