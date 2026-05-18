package daemon

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// launchdPlistTemplate renders a per-user LaunchAgent plist. The
// template intentionally omits KeepAlive=true to allow the service
// to exit on errors that should not loop indefinitely (e.g.,
// repeated bind failures). RunAtLoad=true means it starts at user
// login; bootstrap below also activates it immediately.
const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{{.Label}}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{{.ExecPath}}</string>
    <string>--listen={{.Listen}}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>{{if .LogPath}}
  <key>StandardErrorPath</key>
  <string>{{.LogPath}}</string>
  <key>StandardOutPath</key>
  <string>{{.LogPath}}</string>{{end}}
</dict>
</plist>
`

// launchdPlistPath returns ~/Library/LaunchAgents/<label>.plist.
func launchdPlistPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist")
}

// RenderLaunchdPlist materializes the plist content for opts. Pulled
// out so tests can assert against a known string without touching
// the filesystem.
func RenderLaunchdPlist(opts Options) (string, error) {
	tmpl, err := template.New("plist").Parse(launchdPlistTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	data := struct {
		Label    string
		ExecPath string
		Listen   string
		LogPath  string
	}{
		Label:    LaunchdLabel,
		ExecPath: opts.ExecPath,
		Listen:   resolvedListen(opts),
		LogPath:  opts.LogPath,
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func installLaunchd(opts Options) (Status, error) {
	st := Status{ServiceFilePath: launchdPlistPath()}
	if opts.ExecPath == "" {
		return st, fmt.Errorf("install: ExecPath required")
	}
	content, err := RenderLaunchdPlist(opts)
	if err != nil {
		return st, fmt.Errorf("render plist: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(st.ServiceFilePath), 0o755); err != nil {
		return st, fmt.Errorf("mkdir LaunchAgents: %w", err)
	}
	tmp := st.ServiceFilePath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return st, fmt.Errorf("write plist: %w", err)
	}
	if err := os.Rename(tmp, st.ServiceFilePath); err != nil {
		_ = os.Remove(tmp)
		return st, fmt.Errorf("rename plist: %w", err)
	}
	st.Installed = true

	// Bootstrap and enable. Bootout first to clear any prior version;
	// errors from bootout when the service wasn't loaded are expected
	// and silenced.
	uid := strconv.Itoa(os.Getuid())
	domain := "gui/" + uid
	_ = run("launchctl", "bootout", domain+"/"+LaunchdLabel)
	if err := run("launchctl", "bootstrap", domain, st.ServiceFilePath); err != nil {
		st.Detail = "bootstrap failed: " + err.Error()
		return st, fmt.Errorf("launchctl bootstrap: %w", err)
	}
	_ = run("launchctl", "enable", domain+"/"+LaunchdLabel)
	st.Active = true
	st.Detail = "bootstrapped " + domain + "/" + LaunchdLabel
	return st, nil
}

func uninstallLaunchd() (Status, error) {
	st := Status{ServiceFilePath: launchdPlistPath()}
	if _, err := os.Stat(st.ServiceFilePath); err != nil {
		if os.IsNotExist(err) {
			st.Detail = "not installed"
			return st, nil
		}
		return st, err
	}
	st.Installed = true

	uid := strconv.Itoa(os.Getuid())
	_ = run("launchctl", "bootout", "gui/"+uid+"/"+LaunchdLabel)
	if err := os.Remove(st.ServiceFilePath); err != nil {
		return st, fmt.Errorf("remove plist: %w", err)
	}
	st.Installed = false
	st.Active = false
	st.Detail = "removed"
	return st, nil
}

func statusLaunchd() (Status, error) {
	st := Status{ServiceFilePath: launchdPlistPath()}
	if _, err := os.Stat(st.ServiceFilePath); err == nil {
		st.Installed = true
	}
	uid := strconv.Itoa(os.Getuid())
	out, err := exec.Command("launchctl", "print", "gui/"+uid+"/"+LaunchdLabel).CombinedOutput()
	if err == nil {
		st.Active = true
		// Trim to a one-liner so doctor output stays compact.
		first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
		st.Detail = first
	}
	return st, nil
}

// run executes a command and returns its error. Stderr is captured
// into the error message so failures are debuggable.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
