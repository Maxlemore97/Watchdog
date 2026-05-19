package projectscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalRoots_EnvVarHonored: WATCHDOG_PLUGIN_DIRS is the canonical
// override. Existing dirs make it through; nonexistent paths are
// filtered.
func TestLocalRoots_EnvVarHonored(t *testing.T) {
	existing := t.TempDir()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	t.Setenv("WATCHDOG_PLUGIN_DIRS", existing+string(os.PathListSeparator)+missing)
	t.Setenv("CLAUDE_PLUGINS_DIR", "")
	t.Setenv("HOME", t.TempDir()) // empty home → no ~/.claude/plugins fallback

	roots := LocalRoots(LocalOpts{})
	if len(roots) != 1 || roots[0] != existing {
		t.Errorf("expected [%q], got %v", existing, roots)
	}
}

// TestLocalRoots_ExtraRootsAppended: caller-supplied --root entries
// are appended to whatever the env-var resolver returned.
func TestLocalRoots_ExtraRootsAppended(t *testing.T) {
	env := t.TempDir()
	extra := t.TempDir()
	t.Setenv("WATCHDOG_PLUGIN_DIRS", env)
	t.Setenv("CLAUDE_PLUGINS_DIR", "")
	t.Setenv("HOME", t.TempDir())

	roots := LocalRoots(LocalOpts{ExtraRoots: []string{extra}})
	if len(roots) != 2 {
		t.Fatalf("expected 2 roots, got %v", roots)
	}
	if !strings.Contains(strings.Join(roots, ","), extra) {
		t.Errorf("extra root missing from result: %v", roots)
	}
}

// TestLocalRoots_NoDefaultsReturnsEmpty: with no env vars set and no
// ~/.claude/plugins dir, LocalRoots must return nil/empty so the
// caller can surface a "nothing to scan" note instead of touching
// arbitrary user dirs.
func TestLocalRoots_NoDefaultsReturnsEmpty(t *testing.T) {
	t.Setenv("WATCHDOG_PLUGIN_DIRS", "")
	t.Setenv("CLAUDE_PLUGINS_DIR", "")
	t.Setenv("HOME", t.TempDir())
	roots := LocalRoots(LocalOpts{})
	if len(roots) != 0 {
		t.Errorf("expected empty roots, got %v", roots)
	}
}
