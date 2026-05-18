package daemon

import (
	"strings"
	"testing"
)

func TestRenderLaunchdPlist_ContainsCoreFields(t *testing.T) {
	got, err := RenderLaunchdPlist(Options{
		ExecPath:   "/usr/local/bin/watchdog-mcp",
		ListenAddr: "auto",
		LogPath:    "/var/log/watchdog.log",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, got, "<key>Label</key>")
	mustContain(t, got, LaunchdLabel)
	mustContain(t, got, "/usr/local/bin/watchdog-mcp")
	mustContain(t, got, "--listen=auto")
	mustContain(t, got, "<key>RunAtLoad</key>")
	mustContain(t, got, "<key>KeepAlive</key>")
	mustContain(t, got, "<key>StandardErrorPath</key>")
	mustContain(t, got, "/var/log/watchdog.log")
}

func TestRenderLaunchdPlist_OmitsLogPathWhenEmpty(t *testing.T) {
	got, err := RenderLaunchdPlist(Options{
		ExecPath: "/usr/local/bin/watchdog-mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "StandardErrorPath") {
		t.Errorf("expected no StandardErrorPath key when LogPath empty:\n%s", got)
	}
	mustContain(t, got, "--listen=auto") // default fallback
}

func TestRenderSystemdUnit_ContainsCoreFields(t *testing.T) {
	got, err := RenderSystemdUnit(Options{
		ExecPath:   "/usr/local/bin/watchdog-mcp",
		ListenAddr: "unix:///tmp/mcp.sock",
		LogPath:    "/var/log/watchdog.log",
	})
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, got, "[Unit]")
	mustContain(t, got, "[Service]")
	mustContain(t, got, "[Install]")
	mustContain(t, got, "ExecStart=/usr/local/bin/watchdog-mcp --listen=unix:///tmp/mcp.sock")
	mustContain(t, got, "Restart=on-failure")
	mustContain(t, got, "WantedBy=default.target")
	mustContain(t, got, "StandardError=append:/var/log/watchdog.log")
}

func TestRenderSystemdUnit_OmitsLogWhenEmpty(t *testing.T) {
	got, err := RenderSystemdUnit(Options{ExecPath: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "StandardError=") || strings.Contains(got, "StandardOutput=") {
		t.Errorf("expected no log directives when LogPath empty:\n%s", got)
	}
}

func TestResolvedListen_Default(t *testing.T) {
	if got := resolvedListen(Options{}); got != "auto" {
		t.Errorf("default = %q, want auto", got)
	}
}

func TestResolvedListen_Override(t *testing.T) {
	if got := resolvedListen(Options{ListenAddr: "tcp://127.0.0.1:9000"}); got != "tcp://127.0.0.1:9000" {
		t.Errorf("override = %q", got)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("output missing %q:\n%s", needle, haystack)
	}
}
