package daemon

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

// systemdUnitTemplate renders a per-user systemd .service unit. The
// service is restart-on-failure with a 10s back-off so a quick bind
// hiccup recovers without leaning hard on the bus.
const systemdUnitTemplate = `[Unit]
Description=Watchdog MCP server (long-running daemon mode)
Documentation=https://github.com/Maxlemore97/Watchdog
After=network.target

[Service]
Type=simple
ExecStart={{.ExecPath}} --listen={{.Listen}}
Restart=on-failure
RestartSec=10
{{- if .LogPath}}
StandardError=append:{{.LogPath}}
StandardOutput=append:{{.LogPath}}
{{- end}}

[Install]
WantedBy=default.target
`

// systemdUnitPath returns ~/.config/systemd/user/watchdog-mcp.service.
func systemdUnitPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	cfgHome := os.Getenv("XDG_CONFIG_HOME")
	if cfgHome == "" {
		cfgHome = filepath.Join(home, ".config")
	}
	return filepath.Join(cfgHome, "systemd", "user", SystemdUnit+".service")
}

// RenderSystemdUnit materializes the unit content for opts. Exported
// so tests can assert against the rendered string.
func RenderSystemdUnit(opts Options) (string, error) {
	tmpl, err := template.New("unit").Parse(systemdUnitTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	data := struct {
		ExecPath string
		Listen   string
		LogPath  string
	}{
		ExecPath: opts.ExecPath,
		Listen:   resolvedListen(opts),
		LogPath:  opts.LogPath,
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func installSystemd(opts Options) (Status, error) {
	st := Status{ServiceFilePath: systemdUnitPath()}
	if opts.ExecPath == "" {
		return st, fmt.Errorf("install: ExecPath required")
	}
	content, err := RenderSystemdUnit(opts)
	if err != nil {
		return st, fmt.Errorf("render unit: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(st.ServiceFilePath), 0o755); err != nil {
		return st, fmt.Errorf("mkdir systemd unit dir: %w", err)
	}
	tmp := st.ServiceFilePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return st, fmt.Errorf("write unit: %w", err)
	}
	if err := os.Rename(tmp, st.ServiceFilePath); err != nil {
		_ = os.Remove(tmp)
		return st, fmt.Errorf("rename unit: %w", err)
	}
	st.Installed = true

	// Reload + enable+start. enable --now is idempotent.
	if err := run("systemctl", "--user", "daemon-reload"); err != nil {
		st.Detail = "daemon-reload: " + err.Error()
		return st, err
	}
	if err := run("systemctl", "--user", "enable", "--now", SystemdUnit+".service"); err != nil {
		st.Detail = "enable --now: " + err.Error()
		return st, err
	}
	st.Active = true
	st.Detail = "enabled and started"
	return st, nil
}

func uninstallSystemd() (Status, error) {
	st := Status{ServiceFilePath: systemdUnitPath()}
	if _, err := os.Stat(st.ServiceFilePath); err != nil {
		if os.IsNotExist(err) {
			st.Detail = "not installed"
			return st, nil
		}
		return st, err
	}
	st.Installed = true

	_ = run("systemctl", "--user", "disable", "--now", SystemdUnit+".service")
	if err := os.Remove(st.ServiceFilePath); err != nil {
		return st, fmt.Errorf("remove unit: %w", err)
	}
	_ = run("systemctl", "--user", "daemon-reload")
	st.Installed = false
	st.Active = false
	st.Detail = "removed"
	return st, nil
}

func statusSystemd() (Status, error) {
	st := Status{ServiceFilePath: systemdUnitPath()}
	if _, err := os.Stat(st.ServiceFilePath); err == nil {
		st.Installed = true
	}
	out, err := exec.Command("systemctl", "--user", "is-active", SystemdUnit+".service").CombinedOutput()
	state := strings.TrimSpace(string(out))
	if err == nil && state == "active" {
		st.Active = true
	}
	if state != "" {
		st.Detail = state
	}
	return st, nil
}
