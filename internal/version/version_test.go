package version

import (
	"bytes"
	"strings"
	"testing"
)

func TestString_DefaultsToDev(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = ""
	if got := String(); got != "dev" {
		t.Errorf("String() with empty Version = %q, want dev", got)
	}
}

func TestString_ReturnsInjected(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Errorf("String() = %q, want v1.2.3", got)
	}
}

func TestHandleFlag_VersionLong(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "v9.9.9"
	var buf bytes.Buffer
	if !HandleFlag("/usr/local/bin/watchdog-shim", []string{"--version"}, &buf) {
		t.Fatal("HandleFlag returned false for --version")
	}
	out := buf.String()
	if !strings.Contains(out, "watchdog-shim") || !strings.Contains(out, "v9.9.9") {
		t.Errorf("HandleFlag output = %q", out)
	}
}

func TestHandleFlag_SubcommandStyle(t *testing.T) {
	var buf bytes.Buffer
	if !HandleFlag("watchdog-shim", []string{"version"}, &buf) {
		t.Fatal("HandleFlag returned false for `version` subcommand")
	}
}

func TestHandleFlag_RejectsShortV(t *testing.T) {
	// `-v` is widely used as verbose by package managers; we don't
	// intercept it to avoid surprising delegation.
	var buf bytes.Buffer
	if HandleFlag("watchdog-shim", []string{"-v"}, &buf) {
		t.Error("HandleFlag must NOT intercept -v")
	}
}

func TestHandleFlag_NoMatchNoOutput(t *testing.T) {
	var buf bytes.Buffer
	if HandleFlag("watchdog-shim", []string{"install", "--dir", "/x"}, &buf) {
		t.Error("HandleFlag returned true for unrelated args")
	}
	if buf.Len() != 0 {
		t.Errorf("HandleFlag wrote %q on no-match", buf.String())
	}
}
