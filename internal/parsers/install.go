// Package parsers turns install-shaped Bash commands into Package
// targets and recognises Claude Code plugin slash-command prompts.
package parsers

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// EcosystemByCmd maps a package-manager binary name to its OSV
// ecosystem name. Mirror of the Python ECOSYSTEM_BY_CMD map.
var EcosystemByCmd = map[string]string{
	"npm":     "npm",
	"pnpm":    "npm",
	"yarn":    "npm",
	"pip":     "PyPI",
	"pip3":    "PyPI",
	"uv":      "PyPI",
	"uv-pip":  "PyPI",
	"poetry":  "PyPI",
	"cargo":   "crates.io",
	"gem":     "RubyGems",
	"composer": "Packagist",
}

// InstallSubcmds gates which subcommand counts as an install for each
// binary. Anything else (e.g. `npm test`) is ignored.
var InstallSubcmds = map[string]map[string]bool{
	"npm":     {"install": true, "i": true, "add": true},
	"pnpm":    {"add": true, "install": true, "i": true},
	"yarn":    {"add": true},
	"pip":     {"install": true},
	"pip3":    {"install": true},
	"uv":      {"add": true},
	"uv-pip":  {"install": true},
	"poetry":  {"add": true},
	"cargo":   {"add": true, "install": true},
	"gem":     {"install": true},
	"composer": {"require": true},
}

var shellBinaries = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
}

// flagsWithArg lists flags that consume the next token (e.g. `-r reqs.txt`).
var flagsWithArg = map[string]map[string]bool{
	"pip": {
		"-r": true, "--requirement": true, "-c": true, "--constraint": true,
		"-e": true, "--editable": true, "-t": true, "--target": true,
		"-i": true, "--index-url": true, "--extra-index-url": true,
		"-f": true, "--find-links": true, "--prefix": true, "--root": true, "--src": true,
	},
	"pip3": {
		"-r": true, "--requirement": true, "-c": true, "--constraint": true,
		"-e": true, "--editable": true, "-t": true, "--target": true,
		"-i": true, "--index-url": true, "--extra-index-url": true,
		"-f": true, "--find-links": true, "--prefix": true, "--root": true, "--src": true,
	},
	"uv-pip": {
		"-r": true, "--requirement": true, "-c": true, "--constraint": true,
		"-e": true, "--editable": true,
		"--index-url": true, "--extra-index-url": true, "--find-links": true,
	},
	"uv": {
		"--index-url": true, "--extra-index-url": true, "--find-links": true,
	},
	"poetry": {
		"--source": true, "--python": true, "-E": true, "--extras": true,
	},
	"npm": {
		"--registry": true, "--prefix": true, "--cache": true, "--userconfig": true,
		"--globalconfig": true, "--workspace": true, "-w": true,
	},
	"pnpm": {
		"--registry": true, "--prefix": true, "--cache": true,
		"--workspace": true, "-w": true, "--filter": true,
	},
	"yarn": {
		"--registry": true, "--cache-folder": true, "--modules-folder": true,
	},
	"cargo": {
		"--registry": true, "--index": true, "--path": true, "--git": true,
		"--branch": true, "--tag": true, "--rev": true, "--root": true,
		"--target": true, "--profile": true, "-Z": true,
	},
	"gem": {
		"--source": true, "--bindir": true, "--install-dir": true, "-i": true, "-n": true,
	},
	"composer": {
		"--working-dir": true, "-d": true, "--repository": true, "--repository-url": true,
	},
}

var urlPathPrefixes = []string{
	"./", "../", "/", "~/", "~", ".\\",
	"git+", "http://", "https://", "ftp://", "file://",
	"svn+", "hg+", "bzr+",
}

var archiveSuffixes = []string{
	".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2",
	".zip", ".whl", ".gem",
}

func isURLOrPath(tok string) bool {
	for _, p := range urlPathPrefixes {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	low := strings.ToLower(tok)
	for _, suf := range archiveSuffixes {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	return false
}

var (
	pipVersionRE = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*(?:==|@)\s*([A-Za-z0-9_.\-]+)$`)
	pipBareRE    = regexp.MustCompile(`[<>=!~]`)
)

// SplitNameVersion extracts (name, version) from a token per binary.
// Empty version means unpinned.
func SplitNameVersion(tok, binary string) (string, string) {
	switch binary {
	case "npm", "pnpm", "yarn":
		if strings.HasPrefix(tok, "@") {
			slash := strings.Index(tok, "/")
			if slash == -1 {
				return tok, ""
			}
			scope := tok[:slash]
			rest := tok[slash+1:]
			at := strings.Index(rest, "@")
			if at == -1 {
				return scope + "/" + rest, ""
			}
			return scope + "/" + rest[:at], rest[at+1:]
		}
		at := strings.Index(tok, "@")
		if at == -1 {
			return tok, ""
		}
		return tok[:at], tok[at+1:]
	case "pip", "pip3", "uv", "uv-pip", "poetry":
		if m := pipVersionRE.FindStringSubmatch(tok); m != nil {
			return m[1], m[2]
		}
		// Strip trailing PEP 440 specifier (>=, <, ~=, !=, ==).
		parts := pipBareRE.Split(tok, 2)
		if parts[0] == "" {
			return "", ""
		}
		return parts[0], ""
	case "cargo":
		at := strings.Index(tok, "@")
		if at == -1 {
			return tok, ""
		}
		return tok[:at], tok[at+1:]
	case "gem":
		return tok, ""
	case "composer":
		colon := strings.Index(tok, ":")
		if colon == -1 {
			return tok, ""
		}
		return tok[:colon], tok[colon+1:]
	}
	return tok, ""
}

// ParseInstall parses one install-shaped command segment. Returns the
// packages it found plus notes describing unsupported install forms
// (requirements files, editable installs, URLs, local paths) that
// should still trigger an "ask" decision at the adapter layer.
func ParseInstall(command string) ([]types.Package, []string) {
	tokens, err := Tokenize(strings.TrimSpace(command))
	if err != nil {
		return nil, []string{"malformed shell command: " + err.Error()}
	}
	if len(tokens) < 3 {
		return nil, nil
	}

	binary := lastPathSegment(tokens[0])
	var effectiveBinary, subcmd string
	var args []string
	if binary == "uv" && tokens[1] == "pip" {
		if len(tokens) < 4 {
			return nil, nil
		}
		effectiveBinary = "uv-pip"
		subcmd = tokens[2]
		args = tokens[3:]
	} else {
		effectiveBinary = binary
		subcmd = tokens[1]
		args = tokens[2:]
	}

	ecosystem, ok := EcosystemByCmd[effectiveBinary]
	if !ok {
		return nil, nil
	}
	if !InstallSubcmds[effectiveBinary][subcmd] {
		return nil, nil
	}

	flagArgs := flagsWithArg[effectiveBinary]
	var pkgs []types.Package
	var notes []string
	i := 0
	for i < len(args) {
		tok := args[i]
		if strings.HasPrefix(tok, "-") {
			flagName := tok
			inlineVal := ""
			if eq := strings.Index(tok, "="); eq != -1 {
				flagName = tok[:eq]
				inlineVal = tok[eq+1:]
			}
			if flagArgs[flagName] {
				consumed := inlineVal
				if consumed == "" && i+1 < len(args) {
					consumed = args[i+1]
				}
				switch flagName {
				case "-r", "--requirement":
					if consumed != "" {
						notes = append(notes, "requirements file: "+consumed)
					}
				case "-c", "--constraint":
					if consumed != "" {
						notes = append(notes, "constraints file: "+consumed)
					}
				case "-e", "--editable":
					if consumed != "" {
						notes = append(notes, "editable install: "+consumed)
					}
				}
				if inlineVal != "" {
					i++
				} else {
					i += 2
				}
				continue
			}
			i++
			continue
		}
		if isURLOrPath(tok) {
			notes = append(notes, "url/path install: "+tok)
			i++
			continue
		}
		name, version := SplitNameVersion(tok, effectiveBinary)
		if name == "" {
			i++
			continue
		}
		pkgs = append(pkgs, types.Package{Ecosystem: ecosystem, Name: name, Version: version})
		i++
	}
	return pkgs, notes
}

// ParsePackages is a convenience wrapper for callers that don't need notes.
func ParsePackages(command string) []types.Package {
	pkgs, _ := ParseInstall(command)
	return pkgs
}

// ExtractSubshells returns the inner commands of any `sh -c "..."`
// (or bash/zsh/etc.) invocations in the command.
func ExtractSubshells(command string) []string {
	tokens, err := Tokenize(strings.TrimSpace(command))
	if err != nil || len(tokens) == 0 {
		return nil
	}
	binary := lastPathSegment(tokens[0])
	if !shellBinaries[binary] {
		return nil
	}
	var out []string
	for i, tok := range tokens {
		if tok == "-c" && i+1 < len(tokens) {
			out = append(out, tokens[i+1])
		}
	}
	return out
}

// ResolveVersionFn lets callers inject the OSV version resolver
// without dragging the osv package into parsers (avoiding a cycle).
type ResolveVersionFn func(types.Package) types.Package

// CollectPackages recursively walks a command: splits on shell
// operators, descends into `sh -c "..."` wrappers, parses each
// segment, and resolves unpinned versions in parallel via resolveFn.
//
// Pass a pure-parse resolveFn (identity) for tests that don't want
// network calls.
func CollectPackages(command string, resolveFn ResolveVersionFn) ([]types.Package, []string) {
	var rawPkgs []types.Package
	var notes []string
	seen := map[string]bool{}

	var walk func(cmd string, depth int)
	walk = func(cmd string, depth int) {
		if depth > 3 {
			return
		}
		for _, inner := range ExtractSubshells(cmd) {
			walk(inner, depth+1)
		}
		for _, seg := range SplitOnOperators(cmd) {
			seg = strings.TrimSpace(seg)
			if seg == "" || seen[seg] {
				continue
			}
			seen[seg] = true
			segPkgs, segNotes := ParseInstall(seg)
			rawPkgs = append(rawPkgs, segPkgs...)
			notes = append(notes, segNotes...)
			for _, inner := range ExtractSubshells(seg) {
				walk(inner, depth+1)
			}
		}
	}
	walk(command, 0)

	if len(rawPkgs) == 0 {
		return nil, notes
	}
	if resolveFn == nil {
		return rawPkgs, notes
	}
	if len(rawPkgs) == 1 {
		return []types.Package{resolveFn(rawPkgs[0])}, notes
	}
	resolved := make([]types.Package, len(rawPkgs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for idx, pkg := range rawPkgs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p types.Package) {
			defer wg.Done()
			defer func() { <-sem }()
			resolved[i] = resolveFn(p)
		}(idx, pkg)
	}
	wg.Wait()
	return resolved, notes
}

func lastPathSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i != -1 {
		return s[i+1:]
	}
	return s
}

// ---------- plugin-prompt parser ---------------------------------

var (
	pluginInstallRE     = regexp.MustCompile(`(?i)^/plugin\s+install\s+(\S+)`)
	pluginMarketplaceRE = regexp.MustCompile(`(?i)^/plugin\s+marketplace\s+add\s+(\S+)`)
	gitURLRE            = regexp.MustCompile(`^(https?://|git@|ssh://).+`)
)

// ClassifyPluginTarget classifies a /plugin install argument into
// (ecosystem, name, version). Ecosystem is always "plugin".
func ClassifyPluginTarget(target string) (ecosystem, name, version string) {
	if gitURLRE.MatchString(target) || strings.HasSuffix(target, ".git") {
		return "plugin", target, ""
	}
	if strings.Contains(target, "@") && !strings.HasPrefix(target, "@") {
		at := strings.Index(target, "@")
		return "plugin", target[:at], target[at+1:]
	}
	return "plugin", target, ""
}

// ExtractPluginTargets returns /plugin install or /plugin marketplace
// add targets found at the start of the prompt.
func ExtractPluginTargets(prompt string) []string {
	prompt = strings.TrimSpace(prompt)
	var out []string
	if m := pluginInstallRE.FindStringSubmatch(prompt); m != nil {
		out = append(out, m[1])
	}
	if m := pluginMarketplaceRE.FindStringSubmatch(prompt); m != nil {
		out = append(out, m[1])
	}
	return out
}
