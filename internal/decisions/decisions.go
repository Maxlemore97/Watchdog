// Package decisions implements a short-TTL cache the MCP server uses
// to hand verdicts off to the shim — a coordination mechanism, not a
// substitute for either layer.
//
// Flow when an MCP-aware agent honestly calls watchdog_preflight_install:
//
//  1. MCP computes the verdict (preflight.Packages) and calls Write.
//  2. Agent runs the install in shell. PATH routes it to the shim.
//  3. Shim canonicalizes the command, looks up the same key, and on
//     hit short-circuits to the cached verdict — no duplicate OSV/LLM
//     work.
//
// Properties:
//   - Cache key is sha256 of the canonical command. An agent who got
//     `lodash` approved cannot sneak `lodash-evil` past the shim on
//     the same key.
//   - On `deny`, the shim also denies — even if the agent ignored the
//     MCP response and ran it anyway.
//   - No token = shim runs its own preflight from scratch. Always
//     safe, just no fast path.
//   - `ask` verdicts are NOT cached. The shim's TTY prompt path is
//     stateful (TTY availability), so re-running the check is correct.
//
// Tokens are unsigned in v1. Same threat model as the integrity
// manifest: a filesystem-write adversary can forge approvals, but
// the audit log records both Write and Read events so a missing pair
// is itself forensic evidence.
package decisions

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/audit"
	"github.com/Maxlemore97/watchdog/internal/integrity"
	"github.com/Maxlemore97/watchdog/internal/parsers"
	"github.com/Maxlemore97/watchdog/internal/paths"
)

// DefaultTTL is how long a decision is honoured by the shim before
// it's treated as stale and re-analyzed. 60s is the right tradeoff
// between "long enough that the agent's MCP call → shell-exec gap
// fits" and "short enough that stale state can't accumulate."
const DefaultTTL = 60 * time.Second

// TTL returns the configured decision lifetime. Override via
// WATCHDOG_DECISION_TTL (seconds, decimal allowed).
func TTL() time.Duration {
	if raw := os.Getenv("WATCHDOG_DECISION_TTL"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v > 0 {
			return time.Duration(v * float64(time.Second))
		}
	}
	return DefaultTTL
}

// Dir returns the directory tokens live in: $WATCHDOG_DIR/decisions.
func Dir() string {
	return filepath.Join(paths.WatchdogDir(), "decisions")
}

// Token is the on-disk record. Verdict is "allow" or "deny" — see
// package doc for why "ask" is not cached.
type Token struct {
	Verdict   string    `json:"verdict"`
	Reason    string    `json:"reason,omitempty"`
	Command   string    `json:"command"`
	WrittenAt time.Time `json:"written_at"`
	WriterPID int       `json:"writer_pid,omitempty"`
	// Signature is a base64-encoded Ed25519 signature over the canonical
	// JSON of the preceding fields (with Signature cleared). Tokens
	// without a valid signature are not consumed — see ErrUnsignedToken.
	Signature string `json:"signature,omitempty"`
}

// canonicalize tokenizes and re-joins the command so semantically
// equivalent inputs (extra whitespace, redundant quoting) produce the
// same cache key. Returns the original command verbatim if
// tokenization fails — better a missed cache hit than a wrongly
// shared one.
func canonicalize(cmd string) string {
	tokens, err := parsers.Tokenize(strings.TrimSpace(cmd))
	if err != nil || len(tokens) == 0 {
		return cmd
	}
	return parsers.JoinShell(tokens)
}

// Key returns the cache key for a command (exported so callers can
// log the key for forensic correlation).
func Key(command string) string {
	sum := sha256.Sum256([]byte(canonicalize(command)))
	return hex.EncodeToString(sum[:])
}

func tokenPath(key string) string {
	return filepath.Join(Dir(), key+".json")
}

// Write persists a decision for command. Skips silently when verdict
// is not "allow" or "deny" — "ask" decisions are intentionally not
// cached because the shim's TTY-prompt resolution is stateful.
//
// Atomic via temp + rename to avoid the shim reading a half-written
// token. Failures are logged to audit but do not propagate: an
// unwritable dir should never break MCP's primary contract.
func Write(command, verdict, reason string) {
	switch verdict {
	case "allow", "deny":
	default:
		return
	}
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		audit.Record("decision.write_failed", map[string]any{
			"reason": "mkdir: " + err.Error(),
		})
		return
	}
	t := Token{
		Verdict:   verdict,
		Reason:    reason,
		Command:   command,
		WrittenAt: time.Now().UTC(),
		WriterPID: os.Getpid(),
	}
	// Sign before serialization. Failure to sign is non-fatal: an
	// unsigned token is rejected on read (ErrUnsignedToken) and the
	// shim falls back to a fresh preflight. Better than blocking the
	// MCP call when the signing key isn't writable.
	if priv, _, err := integrity.LoadOrCreateKey(); err == nil {
		canon, cErr := integrity.CanonicalJSON(t)
		if cErr == nil {
			t.Signature = integrity.SignBytes(priv, canon)
		}
	}
	data, err := json.Marshal(t)
	if err != nil {
		audit.Record("decision.write_failed", map[string]any{
			"reason": "marshal: " + err.Error(),
		})
		return
	}
	key := Key(command)
	path := tokenPath(key)
	tmp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		audit.Record("decision.write_failed", map[string]any{
			"reason": "write: " + err.Error(),
		})
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		audit.Record("decision.write_failed", map[string]any{
			"reason": "rename: " + err.Error(),
		})
		_ = os.Remove(tmp)
		return
	}
	audit.Record("decision.written", map[string]any{
		"key":     key,
		"verdict": verdict,
	})
}

// ErrNoDecision is returned by Read when no token matches.
var ErrNoDecision = errors.New("no cached decision")

// ErrExpired is returned by Read when a token exists but has aged
// past TTL. The expired token is also deleted.
var ErrExpired = errors.New("cached decision expired")

// ErrUnsignedToken is returned by Read when a token has no signature
// (legacy token from before signing was enabled), an invalid
// signature (tamper-shaped), or the local public key needed to
// verify is missing. The token is deleted so it doesn't keep
// failing reads.
var ErrUnsignedToken = errors.New("cached decision has missing or invalid signature")

// Read looks up a cached decision for command. Returns the token on
// hit, ErrNoDecision when absent, ErrExpired when stale. Any other
// I/O error means "no useful cache" — caller should fall back to
// running its own analysis.
//
// On a successful read, an audit `decision.consumed` event is
// recorded so the audit trail pairs the MCP write with the shim
// read. Missing pairs in post-incident review are themselves a
// signal.
func Read(command string) (*Token, error) {
	key := Key(command)
	path := tokenPath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			audit.Record("decision.miss", map[string]any{"key": key})
			return nil, ErrNoDecision
		}
		return nil, err
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		// Corrupt token: delete it so it doesn't keep failing reads.
		_ = os.Remove(path)
		audit.Record("decision.corrupt", map[string]any{
			"key":    key,
			"reason": err.Error(),
		})
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	age := time.Since(t.WrittenAt)
	if age > TTL() {
		_ = os.Remove(path)
		audit.Record("decision.expired", map[string]any{
			"key":     key,
			"age_sec": age.Seconds(),
		})
		return nil, ErrExpired
	}

	// Signature verification. A token without a signature is from
	// before signing was wired up, or is forged. Either way we don't
	// honour it — the shim falls back to a fresh preflight.
	if err := verifyTokenSignature(&t); err != nil {
		_ = os.Remove(path)
		audit.Record("decision.unsigned", map[string]any{
			"key":    key,
			"reason": err.Error(),
		})
		return nil, ErrUnsignedToken
	}

	audit.Record("decision.consumed", map[string]any{
		"key":     key,
		"verdict": t.Verdict,
		"age_sec": age.Seconds(),
	})
	return &t, nil
}

// verifyTokenSignature confirms t.Signature is non-empty and valid
// for t's canonical bytes (with the signature field cleared) under
// the local public key.
func verifyTokenSignature(t *Token) error {
	if t.Signature == "" {
		return errors.New("missing signature")
	}
	pub, err := integrity.LoadPublicKey()
	if err != nil {
		return fmt.Errorf("public key unavailable: %w", err)
	}
	sig := t.Signature
	t.Signature = ""
	canon, cErr := integrity.CanonicalJSON(t)
	t.Signature = sig
	if cErr != nil {
		return fmt.Errorf("canonicalize: %w", cErr)
	}
	return integrity.VerifyBytes(pub, canon, sig)
}

// Cleanup removes expired tokens. Best-effort; errors are swallowed.
// Returns the number of tokens removed. Safe to call from a hot path
// (cheap directory walk).
func Cleanup() int {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		return 0
	}
	now := time.Now()
	cutoff := TTL()
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		full := filepath.Join(Dir(), e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > cutoff {
			if err := os.Remove(full); err == nil {
				removed++
			}
		}
	}
	if removed > 0 {
		audit.Record("decision.gc", map[string]any{"removed": removed})
	}
	return removed
}

// Count returns how many tokens currently live in the cache. Used by
// watchdog_health for observability.
func Count() int {
	entries, err := os.ReadDir(Dir())
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}
