// Package cli holds tiny helpers shared by the cmd/ binaries.
//
// Right now: a single TTY-detection function. Lives in internal/ so
// the test surface is unit-testable and shared without each cmd
// repeating the same six lines.
package cli

import "os"

// IsTerminal reports whether f is connected to a terminal (a
// character device). Used by the shim's "ask the human" prompt path
// and by install's auto-register flow to decide whether to prompt
// interactively or print a non-interactive hint.
//
// On non-Unix platforms the implementation is identical because
// os.ModeCharDevice is portable.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
