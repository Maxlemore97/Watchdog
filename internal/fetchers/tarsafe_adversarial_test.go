package fetchers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// buildTar builds a tar.gz with the supplied members in archive order.
// Used by the adversarial test corpus to feed walkTar hostile inputs
// in a controlled way.
func buildTar(t *testing.T, members []tar.Header, bodies map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := range members {
		h := members[i]
		body := bodies[h.Name]
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("write header %q: %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatalf("write body %q: %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// walkAll passes the tar.gz through walkTar with a permissive
// predicate so we only see what safeTarMember kept. The returned
// map's keys are the cleaned member names.
func walkAll(t *testing.T, gz []byte) map[string]string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, _, err := walkTar(r, false,
		func(name string, parts []string) bool { return true },
		func(name string, parts []string) string { return name },
	)
	if err != nil {
		t.Fatalf("walkTar: %v", err)
	}
	return out
}

// Each case asserts that the hostile member never appears in walkTar
// output. Anything safeTarMember rejects is silently dropped; that's
// the contract.

func TestTarAdversarial_Symlink(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "good.txt", Typeflag: tar.TypeReg},
		{Name: "evil-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	}, map[string]string{"good.txt": "ok"})
	out := walkAll(t, gz)
	if _, bad := out["evil-link"]; bad {
		t.Error("symlink leaked through")
	}
	if _, ok := out["good.txt"]; !ok {
		t.Error("good entry dropped")
	}
}

func TestTarAdversarial_Hardlink(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "good.txt", Typeflag: tar.TypeReg},
		{Name: "evil-hardlink", Typeflag: tar.TypeLink, Linkname: "good.txt"},
	}, map[string]string{"good.txt": "ok"})
	out := walkAll(t, gz)
	if _, bad := out["evil-hardlink"]; bad {
		t.Error("hardlink leaked through")
	}
}

func TestTarAdversarial_CharDevice(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "dev-null", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3},
	}, nil)
	out := walkAll(t, gz)
	if len(out) != 0 {
		t.Errorf("char device leaked: %v", out)
	}
}

func TestTarAdversarial_BlockDevice(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "block", Typeflag: tar.TypeBlock, Devmajor: 8, Devminor: 0},
	}, nil)
	out := walkAll(t, gz)
	if len(out) != 0 {
		t.Errorf("block device leaked: %v", out)
	}
}

func TestTarAdversarial_Fifo(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "fifo", Typeflag: tar.TypeFifo},
	}, nil)
	out := walkAll(t, gz)
	if len(out) != 0 {
		t.Errorf("fifo leaked: %v", out)
	}
}

func TestTarAdversarial_AbsolutePath(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "/etc/passwd", Typeflag: tar.TypeReg},
	}, map[string]string{"/etc/passwd": "root:x:0:0"})
	out := walkAll(t, gz)
	if len(out) != 0 {
		t.Errorf("absolute path leaked: %v", out)
	}
}

func TestTarAdversarial_Traversal(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "../../etc/passwd", Typeflag: tar.TypeReg},
		{Name: "a/../../b/evil", Typeflag: tar.TypeReg},
	}, map[string]string{
		"../../etc/passwd": "x",
		"a/../../b/evil":   "x",
	})
	out := walkAll(t, gz)
	if len(out) != 0 {
		t.Errorf("traversal leaked: %v", out)
	}
}

func TestTarAdversarial_EmptyName(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: "", Typeflag: tar.TypeReg},
	}, map[string]string{"": "x"})
	out := walkAll(t, gz)
	if len(out) != 0 {
		t.Errorf("empty-name entry leaked: %v", out)
	}
}

func TestTarAdversarial_OversizeMemberTruncated(t *testing.T) {
	// File larger than MaxFileBytes*2 must be truncated to that limit
	// rather than allowed to balloon memory.
	big := strings.Repeat("a", MaxFileBytes*4)
	gz := buildTar(t, []tar.Header{
		{Name: "big.txt", Typeflag: tar.TypeReg},
	}, map[string]string{"big.txt": big})
	out := walkAll(t, gz)
	got, ok := out["big.txt"]
	if !ok {
		t.Fatal("big.txt dropped entirely")
	}
	if len(got) > MaxFileBytes*2 {
		t.Errorf("big.txt not truncated: len=%d, cap=%d", len(got), MaxFileBytes*2)
	}
}

// TestTarAdversarial_DotOnly verifies that a member named exactly "."
// or ".." (rejected at the path.Clean check) doesn't slip through.
func TestTarAdversarial_DotOnly(t *testing.T) {
	gz := buildTar(t, []tar.Header{
		{Name: ".", Typeflag: tar.TypeReg},
		{Name: "..", Typeflag: tar.TypeReg},
	}, map[string]string{".": "x", "..": "y"})
	out := walkAll(t, gz)
	if len(out) != 0 {
		t.Errorf("./.. leaked: %v", out)
	}
}
