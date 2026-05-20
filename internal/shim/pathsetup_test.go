package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsurePathExport_AppendsBlockWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(rcPath, []byte("# user line\nexport FOO=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	added, err := EnsurePathExport(ShellRC{Path: rcPath, Shell: "zsh"}, "/opt/wd/bin")
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("expected added=true on first write")
	}
	out, _ := os.ReadFile(rcPath)
	s := string(out)
	if !strings.Contains(s, pathSetupMarker) || !strings.Contains(s, pathSetupMarkerEnd) {
		t.Errorf("missing markers in:\n%s", s)
	}
	if !strings.Contains(s, `export PATH="/opt/wd/bin":$PATH`) {
		t.Errorf("missing zsh export line in:\n%s", s)
	}
	if !strings.HasPrefix(s, "# user line") {
		t.Errorf("user content must be preserved at top:\n%s", s)
	}
}

func TestEnsurePathExport_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(rcPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := ShellRC{Path: rcPath, Shell: "zsh"}
	if _, err := EnsurePathExport(rc, "/opt/wd/bin"); err != nil {
		t.Fatal(err)
	}
	added2, err := EnsurePathExport(rc, "/opt/wd/bin")
	if err != nil {
		t.Fatal(err)
	}
	if added2 {
		t.Error("second call must report added=false (block unchanged)")
	}
}

func TestEnsurePathExport_ReplacesWhenShimDirChanges(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(rcPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := ShellRC{Path: rcPath, Shell: "zsh"}
	if _, err := EnsurePathExport(rc, "/old/bin"); err != nil {
		t.Fatal(err)
	}
	added2, err := EnsurePathExport(rc, "/new/bin")
	if err != nil {
		t.Fatal(err)
	}
	if !added2 {
		t.Error("new shim dir should rewrite block")
	}
	out, _ := os.ReadFile(rcPath)
	s := string(out)
	if strings.Contains(s, "/old/bin") {
		t.Errorf("old shim dir not removed:\n%s", s)
	}
	if !strings.Contains(s, "/new/bin") {
		t.Errorf("new shim dir not present:\n%s", s)
	}
	if strings.Count(s, pathSetupMarker) != 1 {
		t.Errorf("expected exactly one managed block:\n%s", s)
	}
}

func TestEnsurePathExport_FishUsesFishAddPath(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "config.fish")
	if _, err := EnsurePathExport(ShellRC{Path: rcPath, Shell: "fish"}, "/opt/wd/bin"); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(rcPath)
	if !strings.Contains(string(out), "fish_add_path --prepend /opt/wd/bin") {
		t.Errorf("fish should use fish_add_path:\n%s", out)
	}
}

func TestRemovePathExport_StripsManagedBlock(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(rcPath, []byte("# top\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := ShellRC{Path: rcPath, Shell: "zsh"}
	if _, err := EnsurePathExport(rc, "/opt/wd/bin"); err != nil {
		t.Fatal(err)
	}
	removed, err := RemovePathExport(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Error("expected removed=true")
	}
	out, _ := os.ReadFile(rcPath)
	if strings.Contains(string(out), pathSetupMarker) {
		t.Errorf("marker still present after remove:\n%s", out)
	}
	if !strings.Contains(string(out), "# top") {
		t.Errorf("user content must be preserved:\n%s", out)
	}
}

func TestRemovePathExport_NoOpWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(rcPath, []byte("just user content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	removed, err := RemovePathExport(ShellRC{Path: rcPath, Shell: "zsh"})
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Error("expected removed=false when no block present")
	}
}