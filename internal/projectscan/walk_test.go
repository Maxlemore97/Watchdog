package projectscan

import (
	"os"
	"path/filepath"
	"testing"
)

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalk_FindsLockfilesAndPlugins(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package-lock.json"), `{"packages":{}}`)
	writeFile(t, filepath.Join(root, "sub", "Cargo.lock"), ``)
	writeFile(t, filepath.Join(root, "plug", ".claude-plugin", "plugin.json"), `{"name":"plug"}`)
	writeFile(t, filepath.Join(root, "agents.md"), `# agents`)
	mkdirs(t, filepath.Join(root, "node_modules", "should-be-pruned"))
	writeFile(t, filepath.Join(root, "node_modules", "should-be-pruned", "package-lock.json"), ``)

	disc, err := Walk(root, WalkOpts{MaxDepth: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(disc.LockfilePaths) != 2 {
		t.Errorf("expected 2 lockfiles, got %d: %v", len(disc.LockfilePaths), disc.LockfilePaths)
	}
	for _, lp := range disc.LockfilePaths {
		if filepath.Base(filepath.Dir(lp)) == "should-be-pruned" {
			t.Errorf("node_modules not pruned: %s", lp)
		}
	}
	if len(disc.PluginRoots) != 1 {
		t.Errorf("expected 1 plugin root, got %v", disc.PluginRoots)
	}
	if len(disc.AgentDocs) != 1 {
		t.Errorf("expected 1 agent doc, got %v", disc.AgentDocs)
	}
}

func TestWalk_UnsupportedLockfileNoted(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "yarn.lock"), `# yarn v1`)
	disc, err := Walk(root, WalkOpts{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range disc.Notes {
		if filepath.Base(n) == "yarn.lock" || (len(n) > 0 && (n[len(n)-9:] == "yarn.lock")) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected yarn.lock note, got notes: %v", disc.Notes)
	}
}

func TestWalk_RespectsDepthLimit(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "d", "e", "f")
	writeFile(t, filepath.Join(deep, "Cargo.lock"), ``)
	disc, err := Walk(root, WalkOpts{MaxDepth: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(disc.LockfilePaths) != 0 {
		t.Errorf("expected lockfile below depth limit to be skipped, got %v", disc.LockfilePaths)
	}
}

func TestWalk_GitignorePrunes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".gitignore"), "build/\n")
	writeFile(t, filepath.Join(root, "build", "Cargo.lock"), ``)
	writeFile(t, filepath.Join(root, "src", "Cargo.lock"), ``)
	disc, err := Walk(root, WalkOpts{SkipGitignored: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(disc.LockfilePaths) != 1 {
		t.Errorf("expected 1 lockfile (src/Cargo.lock), got %v", disc.LockfilePaths)
	}
}
