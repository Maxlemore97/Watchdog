// Package projectscan walks a project tree and enumerates the
// inputs Watchdog can review without running an install: pinned
// dependency lockfiles (for the OSV + install-hook lane) and agent
// extension roots (for the LLM lane). The scan/orchestrator wires
// these into the same preflight + analyzer engine the install-time
// adapters use.
//
// Lockfiles only. A bare manifest without its lockfile is reported
// as a note, not parsed — pinned versions are what the cache and
// the OSV layer need, and walking floating constraints would let
// the scan disagree with what the package manager actually resolves
// at install time.
package projectscan

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// parseLockfile dispatches by filename. Returns parsed packages plus
// any non-fatal notes (skipped sections, malformed entries). Unknown
// filenames return (nil, nil) — caller decides whether that's an
// error or "not a lockfile we recognize".
func parseLockfile(path string) ([]types.Package, []string, error) {
	base := strings.ToLower(filepath.Base(path))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	switch base {
	case "package-lock.json":
		return parseNpmLock(data)
	case "pnpm-lock.yaml":
		return parsePnpmLock(data)
	case "pipfile.lock":
		return parsePipfileLock(data)
	case "poetry.lock":
		return parsePoetryLock(data)
	case "uv.lock":
		return parseUvLock(data)
	case "cargo.lock":
		return parseCargoLock(data)
	case "gemfile.lock":
		return parseGemfileLock(data)
	case "composer.lock":
		return parseComposerLock(data)
	case "go.mod":
		return parseGoMod(data)
	case "packages.lock.json":
		return parseNugetLock(data)
	}
	return nil, nil, nil
}

// ---------- npm ---------------------------------------------------

type npmLock struct {
	Packages map[string]struct {
		Version  string `json:"version"`
		Dev      bool   `json:"dev"`
		Resolved string `json:"resolved"`
	} `json:"packages"`
}

func parseNpmLock(data []byte) ([]types.Package, []string, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	var pkgs []types.Package
	for key, entry := range lock.Packages {
		if key == "" || entry.Version == "" {
			continue
		}
		// npm v7+ keys are "node_modules/<name>" or
		// "node_modules/<scope>/<name>". The root project lives at "".
		idx := strings.LastIndex(key, "node_modules/")
		if idx == -1 {
			continue
		}
		name := key[idx+len("node_modules/"):]
		if name == "" {
			continue
		}
		pkgs = append(pkgs, types.Package{Ecosystem: "npm", Name: name, Version: entry.Version})
	}
	return pkgs, nil, nil
}

// ---------- pnpm --------------------------------------------------

func parsePnpmLock(data []byte) ([]types.Package, []string, error) {
	var lock struct {
		Packages map[string]any `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	// pnpm keys look like "/lodash@4.17.21" or
	// "/@scope/name@1.0.0(peer@x)". Strip the leading slash + the
	// trailing peer-deps suffix, then split on the last '@' before
	// any '(' to separate name from version.
	pnpmKeyRE := regexp.MustCompile(`^/((?:@[^/]+/)?[^@]+)@([^(]+)`)
	var pkgs []types.Package
	for k := range lock.Packages {
		m := pnpmKeyRE.FindStringSubmatch(k)
		if len(m) != 3 {
			continue
		}
		pkgs = append(pkgs, types.Package{Ecosystem: "npm", Name: m[1], Version: strings.TrimSpace(m[2])})
	}
	return pkgs, nil, nil
}

// ---------- Python: Pipfile / poetry / uv -----------------------

type pipfileLock struct {
	Default map[string]struct {
		Version string `json:"version"`
	} `json:"default"`
	Develop map[string]struct {
		Version string `json:"version"`
	} `json:"develop"`
}

func parsePipfileLock(data []byte) ([]types.Package, []string, error) {
	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	var pkgs []types.Package
	for _, section := range []map[string]struct {
		Version string `json:"version"`
	}{lock.Default, lock.Develop} {
		for name, entry := range section {
			ver := strings.TrimPrefix(entry.Version, "==")
			if ver == "" {
				continue
			}
			pkgs = append(pkgs, types.Package{Ecosystem: "PyPI", Name: name, Version: ver})
		}
	}
	return pkgs, nil, nil
}

type poetryLock struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
}

func parsePoetryLock(data []byte) ([]types.Package, []string, error) {
	var lock poetryLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	pkgs := make([]types.Package, 0, len(lock.Package))
	for _, p := range lock.Package {
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, types.Package{Ecosystem: "PyPI", Name: p.Name, Version: p.Version})
	}
	return pkgs, nil, nil
}

// uv.lock shares the same package-array shape as poetry.lock.
func parseUvLock(data []byte) ([]types.Package, []string, error) {
	return parsePoetryLock(data)
}

// ---------- Cargo -------------------------------------------------

type cargoLock struct {
	Package []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  string `toml:"source"`
	} `toml:"package"`
}

func parseCargoLock(data []byte) ([]types.Package, []string, error) {
	var lock cargoLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	var pkgs []types.Package
	for _, p := range lock.Package {
		// Skip path-only / git deps — they have no registry source.
		// OSV only resolves crates.io advisories.
		if p.Source == "" || !strings.HasPrefix(p.Source, "registry+") {
			continue
		}
		pkgs = append(pkgs, types.Package{Ecosystem: "crates.io", Name: p.Name, Version: p.Version})
	}
	return pkgs, nil, nil
}

// ---------- Ruby: Gemfile.lock -----------------------------------

// Gemfile.lock has a custom plaintext shape. The GEM section lists
// `    name (version)` indented under `  specs:`. Other sections
// (PATH, GIT, BUNDLED WITH, ...) we ignore — they're either local
// paths or metadata.
func parseGemfileLock(data []byte) ([]types.Package, []string, error) {
	var pkgs []types.Package
	inGemSpecs := false
	gemEntry := regexp.MustCompile(`^\s{4}([^\s(]+)\s+\(([^)]+)\)\s*$`)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		if trim == "GEM" || trim == "specs:" {
			inGemSpecs = inGemSpecs || trim == "specs:"
			continue
		}
		// Reset on top-level section headers (no leading space).
		if line != "" && line[0] != ' ' {
			inGemSpecs = strings.HasPrefix(line, "GEM")
			continue
		}
		if !inGemSpecs {
			continue
		}
		m := gemEntry.FindStringSubmatch(line)
		if len(m) == 3 {
			pkgs = append(pkgs, types.Package{Ecosystem: "RubyGems", Name: m[1], Version: m[2]})
		}
	}
	return pkgs, nil, scanner.Err()
}

// ---------- Composer ----------------------------------------------

type composerLock struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`
	DevPackages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages-dev"`
}

func parseComposerLock(data []byte) ([]types.Package, []string, error) {
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	pkgs := make([]types.Package, 0, len(lock.Packages)+len(lock.DevPackages))
	for _, p := range append(lock.Packages, lock.DevPackages...) {
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, types.Package{Ecosystem: "Packagist", Name: p.Name, Version: p.Version})
	}
	return pkgs, nil, nil
}

// ---------- Go ---------------------------------------------------

// go.mod is the source of truth for direct requires under the
// modules system. Indirect lines are skipped — OSV resolution costs
// scale with count and indirect deps are reachable via your direct
// dependency's own scan if needed.
func parseGoMod(data []byte) ([]types.Package, []string, error) {
	var pkgs []types.Package
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inRequireBlock := false
	requireLine := regexp.MustCompile(`^\s*([^\s]+)\s+([^\s]+)(?:\s+//.*)?$`)
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)
		if trim == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && trim == ")" {
			inRequireBlock = false
			continue
		}
		if strings.Contains(line, "// indirect") {
			continue
		}
		if inRequireBlock {
			if m := requireLine.FindStringSubmatch(line); len(m) == 3 {
				pkgs = append(pkgs, types.Package{Ecosystem: "Go", Name: m[1], Version: m[2]})
			}
			continue
		}
		if strings.HasPrefix(trim, "require ") {
			rest := strings.TrimPrefix(trim, "require ")
			parts := strings.Fields(rest)
			if len(parts) >= 2 {
				pkgs = append(pkgs, types.Package{Ecosystem: "Go", Name: parts[0], Version: parts[1]})
			}
		}
	}
	return pkgs, nil, scanner.Err()
}

// ---------- NuGet -------------------------------------------------

type nugetLock struct {
	Dependencies map[string]map[string]struct {
		Resolved string `json:"resolved"`
		Type     string `json:"type"`
	} `json:"dependencies"`
}

func parseNugetLock(data []byte) ([]types.Package, []string, error) {
	var lock nugetLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	var pkgs []types.Package
	for _, framework := range lock.Dependencies {
		for name, entry := range framework {
			if entry.Type == "Project" || entry.Resolved == "" {
				continue
			}
			pkgs = append(pkgs, types.Package{Ecosystem: "NuGet", Name: name, Version: entry.Resolved})
		}
	}
	return pkgs, nil, nil
}
