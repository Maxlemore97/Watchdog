// Package version exposes the build-time-injected release tag.
//
// The Version variable is overridden by release builds via ldflags:
//
//	go build -ldflags '-X github.com/Maxlemore97/watchdog/internal/version.Version=v0.4.0' ./...
//
// Untagged builds (go install, local go build) carry "dev".
package version

import (
	"fmt"
	"io"
	"path/filepath"
)

// Version is the release tag injected at link time. Defaults to "dev"
// for unstamped builds.
var Version = "dev"

// String returns the version, normalised so an accidentally cleared
// ldflag value still prints something useful.
func String() string {
	if Version == "" {
		return "dev"
	}
	return Version
}

// HandleFlag returns true if args contains "--version" or "version"
// and writes "<basename(argv0)> <version>" to w. Callers should exit
// 0 when this returns true.
//
// "-v" is intentionally NOT recognised: too many package-manager
// commands use it as verbose, and a shared short-flag would cause
// surprising interception in tools that delegate argv onward.
func HandleFlag(argv0 string, args []string, w io.Writer) bool {
	for _, a := range args {
		switch a {
		case "--version", "version":
			fmt.Fprintf(w, "%s %s\n", filepath.Base(argv0), String())
			return true
		}
	}
	return false
}
