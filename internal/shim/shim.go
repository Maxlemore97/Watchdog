// Package shim holds shared logic for the path_shim adapter: which
// tools we wrap, the wrapper-script templates (POSIX + Windows), the
// install / uninstall / status flow, and resolution of the real
// binary on PATH while excluding the shim dir.
package shim

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ShimmedTools lists the package-manager binaries Watchdog intercepts.
var ShimmedTools = []string{
	"npm", "pnpm", "yarn", "bun",
	"pip", "pip3", "uv", "poetry",
	"cargo", "gem", "composer",
}

// DefaultShimDir is where wrapper scripts land.
func DefaultShimDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".watchdog/bin"
	}
	return filepath.Join(home, ".watchdog", "bin")
}

// PosixWrapperTemplate writes a tiny shell script that exec's the
// watchdog-shim-exec binary with the tool name as first arg.
const PosixWrapperTemplate = `#!/usr/bin/env bash
# Watchdog shim for %s. Do not edit by hand; regenerate via
# ` + "`" + `watchdog-shim install` + "`" + `.
exec "%s" "%s" "$@"
`

// WindowsWrapperTemplate is the .cmd counterpart. %s slots: tool
// name comment, exec path, tool name.
const WindowsWrapperTemplate = `@echo off
:: Watchdog shim for %s. Do not edit by hand; regenerate via
:: ` + "`" + `watchdog-shim install` + "`" + `.
"%s" "%s" %%*
`

// FindRealBinary walks PATH and returns the first executable named
// `name` whose parent directory is NOT in excludeDirs. Symlinked
// shim dirs still match because both sides are normalised via
// filepath.EvalSymlinks.
func FindRealBinary(name string, excludeDirs []string) string {
	excluded := map[string]struct{}{}
	for _, d := range excludeDirs {
		if real, err := filepath.EvalSymlinks(d); err == nil {
			excluded[real] = struct{}{}
		} else {
			excluded[d] = struct{}{}
		}
	}
	path := os.Getenv("PATH")
	for _, entry := range strings.Split(path, string(os.PathListSeparator)) {
		if entry == "" {
			continue
		}
		realEntry, err := filepath.EvalSymlinks(entry)
		if err != nil {
			realEntry = entry
		}
		if _, skip := excluded[realEntry]; skip {
			continue
		}
		candidate := filepath.Join(entry, name)
		if isExecutable(candidate) {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return candidate
			}
			return abs
		}
		// On Windows try common extensions if no extension supplied.
		if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
			for _, ext := range []string{".exe", ".cmd", ".bat"} {
				if isExecutable(candidate + ext) {
					abs, err := filepath.Abs(candidate + ext)
					if err != nil {
						return candidate + ext
					}
					return abs
				}
			}
		}
	}
	return ""
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true // PATHEXT handling is on the OS; existence is enough here
	}
	return st.Mode()&0o111 != 0
}

// IsShimmed reports whether the given tool name is in our intercept
// list.
func IsShimmed(name string) bool {
	for _, t := range ShimmedTools {
		if t == name {
			return true
		}
	}
	return false
}

// IsShimDirFirstOnPath reports whether shimDir is the FIRST entry in
// PATH (after resolving symlinks). Returns false if the user
// accidentally appended the shim dir instead of prepending — in that
// case real binaries on earlier PATH entries take precedence and
// installs silently bypass watchdog.
func IsShimDirFirstOnPath(shimDir string) bool {
	if shimDir == "" {
		return false
	}
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return false
	}
	first := strings.SplitN(pathEnv, string(os.PathListSeparator), 2)[0]
	first = strings.TrimSpace(first)
	if first == "" {
		return false
	}
	shimResolved := shimDir
	if r, err := filepath.EvalSymlinks(shimDir); err == nil {
		shimResolved = r
	}
	firstResolved := first
	if r, err := filepath.EvalSymlinks(first); err == nil {
		firstResolved = r
	}
	return firstResolved == shimResolved
}
