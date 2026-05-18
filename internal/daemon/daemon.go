// Package daemon installs and manages a long-running watchdog-mcp
// service via the host OS's user-level service supervisor: launchd
// on macOS, systemd --user on Linux.
//
// Use case: a single watchdog-mcp instance that survives across host
// session restarts and can be talked to over a unix socket. Avoids
// each MCP host spawning its own stdio child, and allows hosts that
// natively speak HTTP/SSE MCP to share one watchdog server.
//
// Windows daemon mode is not yet supported.
package daemon

import (
	"errors"
	"fmt"
	"runtime"
)

// Service identifiers used by the supervisor — kept stable across
// install/uninstall so reverse operations find what they need.
const (
	// LaunchdLabel is the launchd job label. Matches the plist
	// `<key>Label</key>` value.
	LaunchdLabel = "com.maxlemore97.watchdog"
	// SystemdUnit is the systemd unit filename without the .service
	// suffix.
	SystemdUnit = "watchdog-mcp"
)

// ErrUnsupportedOS is returned by Install/Uninstall/Status when the
// current platform has no implementation. Currently: Windows.
var ErrUnsupportedOS = errors.New("daemon mode is not supported on this OS")

// Options control how the service file is generated.
type Options struct {
	// ExecPath is the absolute path to the watchdog-mcp binary the
	// service should run. Required; resolved by the cmd layer.
	ExecPath string
	// ListenAddr is the value passed as --listen=… to watchdog-mcp.
	// Default "auto" → unix://$WATCHDOG_DIR/mcp.sock.
	ListenAddr string
	// LogPath is where StandardErrorPath / StandardOutputPath point.
	// Empty means the supervisor's default (/dev/null effectively).
	LogPath string
}

// Status is what Install/Status/Uninstall report back to the caller.
type Status struct {
	// Installed reports whether the service file exists on disk.
	Installed bool
	// Active reports whether the supervisor currently has the service
	// loaded / running. Best-effort; some supervisors report this
	// asynchronously.
	Active bool
	// ServiceFilePath is the on-disk location of the plist / unit.
	ServiceFilePath string
	// Detail is a free-form string suitable for the doctor output —
	// supervisor command output, error messages, etc.
	Detail string
}

// Install writes the service file and activates the service. On macOS:
// drops a plist under ~/Library/LaunchAgents and runs `launchctl
// bootstrap`. On Linux: drops a unit under ~/.config/systemd/user
// and runs `systemctl --user enable --now`. Idempotent — re-running
// updates the file in place.
func Install(opts Options) (Status, error) {
	switch runtime.GOOS {
	case "darwin":
		return installLaunchd(opts)
	case "linux":
		return installSystemd(opts)
	default:
		return Status{}, fmt.Errorf("%w: %s", ErrUnsupportedOS, runtime.GOOS)
	}
}

// Uninstall stops the service and removes the service file. Safe to
// call when the service was never installed (no-op).
func Uninstall() (Status, error) {
	switch runtime.GOOS {
	case "darwin":
		return uninstallLaunchd()
	case "linux":
		return uninstallSystemd()
	default:
		return Status{}, fmt.Errorf("%w: %s", ErrUnsupportedOS, runtime.GOOS)
	}
}

// CurrentStatus reads the current state without modifying anything.
func CurrentStatus() (Status, error) {
	switch runtime.GOOS {
	case "darwin":
		return statusLaunchd()
	case "linux":
		return statusSystemd()
	default:
		return Status{}, fmt.Errorf("%w: %s", ErrUnsupportedOS, runtime.GOOS)
	}
}

// resolvedListen returns the listen string the service file should
// use. Falls back to "auto" when opts.ListenAddr is empty.
func resolvedListen(opts Options) string {
	if opts.ListenAddr == "" {
		return "auto"
	}
	return opts.ListenAddr
}
