package cli

import (
	"os"
	"testing"
)

func TestIsTerminal_NilSafe(t *testing.T) {
	if IsTerminal(nil) {
		t.Error("nil file should report false")
	}
}

func TestIsTerminal_PipeIsNotTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	if IsTerminal(r) {
		t.Error("pipe read end should not be a terminal")
	}
}

func TestIsTerminal_TempFileIsNotTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if IsTerminal(f) {
		t.Error("regular file should not be a terminal")
	}
}
