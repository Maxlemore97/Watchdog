// Package shim holds shared logic for the path_shim adapter: which
// tools we wrap, the wrapper-script templates (POSIX + Windows), the
// install / uninstall / status flow, and resolution of the real
// binary on PATH while excluding the shim dir.
package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/config"
	"github.com/Maxlemore97/watchdog/internal/parsers"
)

// DefaultShimmedTools lists the package-manager binaries Watchdog
// intercepts by default. Operators can shrink or grow this set with
// WATCHDOG_SHIMMED_TOOLS_ADD / _SKIP — see EffectiveShimmedTools.
var DefaultShimmedTools = []string{
	"npm", "pnpm", "yarn", "bun",
	"pip", "pip3", "pipx", "uv", "poetry",
	"cargo", "gem", "composer",
	"brew", "go", "dotnet",
}

// EffectiveShimmedTools applies the WATCHDOG_SHIMMED_TOOLS_ADD /
// WATCHDOG_SHIMMED_TOOLS_SKIP deltas to DefaultShimmedTools and
// validates that every name maps to a known package manager
// (parsers.EcosystemByCmd). Returns an error naming any unknown
// entries so the install fails loudly rather than writing a wrapper
// that nothing dispatches to.
func EffectiveShimmedTools(add, skip []string) ([]string, error) {
	skipSet := map[string]bool{}
	for _, s := range skip {
		skipSet[s] = true
	}
	addSet := map[string]bool{}
	for _, a := range add {
		addSet[a] = true
	}
	var unknown []string
	for _, name := range add {
		if _, ok := parsers.EcosystemByCmd[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	for _, name := range skip {
		if _, ok := parsers.EcosystemByCmd[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown tool name(s) in WATCHDOG_SHIMMED_TOOLS_ADD/_SKIP: %s (valid: see parsers.EcosystemByCmd)", strings.Join(unknown, ", "))
	}
	seen := map[string]bool{}
	var out []string
	for _, t := range DefaultShimmedTools {
		if skipSet[t] {
			continue
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range add {
		if skipSet[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	_ = addSet
	return out, nil
}

// EffectiveShimmedToolsFromEnv reads the two delta env vars and
// resolves the effective set. Returns DefaultShimmedTools unchanged
// when both env vars are unset.
func EffectiveShimmedToolsFromEnv() ([]string, error) {
	return EffectiveShimmedTools(
		config.EnvList("WATCHDOG_SHIMMED_TOOLS_ADD"),
		config.EnvList("WATCHDOG_SHIMMED_TOOLS_SKIP"),
	)
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

// IsShimmed reports whether the given tool name is in the effective
// intercept set. Reads env vars on every call so the shim-exec
// dispatcher honours the operator's configured set without process
// restart. On env error falls back to DefaultShimmedTools.
func IsShimmed(name string) bool {
	tools, err := EffectiveShimmedToolsFromEnv()
	if err != nil {
		tools = DefaultShimmedTools
	}
	for _, t := range tools {
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
