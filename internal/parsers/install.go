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
// ecosystem name. Mirror of the Python ECOSYSTEM_BY_CMD map. The
// exec-style runners (npx, bunx, pnpx, uvx) download and execute a
// package in one step; they are listed so the shim can opt into them
// via WATCHDOG_SHIMMED_TOOLS_ADD.
var EcosystemByCmd = map[string]string{
	"npm":      "npm",
	"pnpm":     "npm",
	"yarn":     "npm",
	"bun":      "npm",
	"npx":      "npm",
	"pnpx":     "npm",
	"bunx":     "npm",
	"pip":      "PyPI",
	"pip3":     "PyPI",
	"pipx":     "PyPI",
	"uv":       "PyPI",
	"uv-pip":   "PyPI",
	"uv-tool":  "PyPI",
	"uvx":      "PyPI",
	"poetry":   "PyPI",
	"cargo":    "crates.io",
	"gem":      "RubyGems",
	"composer": "Packagist",
	"brew":     "Homebrew",
	"go":       "Go",
	"dotnet":   "NuGet",
}

// InstallSubcmds gates which subcommand counts as an install for each
// binary. Anything else (e.g. `npm test`) is ignored. The `dotnet` key
// uses the synthetic verb "package", emitted by the multi-word
// dispatch when it sees `dotnet add [<project>] package`.
//
// npm accepts abbreviations and typo aliases for install (`npm in`,
// `npm isntall`); all of them are listed because an agent can use any.
var InstallSubcmds = map[string]map[string]bool{
	"npm": {
		"install": true, "i": true, "add": true, "in": true, "ins": true,
		"inst": true, "insta": true, "instal": true, "isnt": true, "isnta": true,
		"isntal": true, "isntall": true, "it": true, "install-test": true,
		"cit": true, "install-ci-test": true,
	},
	"pnpm":     {"add": true, "install": true, "i": true},
	"yarn":     {"add": true},
	"bun":      {"add": true, "a": true, "install": true, "i": true},
	"pip":      {"install": true, "download": true},
	"pip3":     {"install": true, "download": true},
	"pipx":     {"install": true, "inject": true},
	"uv":       {"add": true},
	"uv-pip":   {"install": true},
	"uv-tool":  {"install": true},
	"poetry":   {"add": true},
	"cargo":    {"add": true, "install": true},
	"gem":      {"install": true},
	"composer": {"require": true},
	"brew":     {"install": true, "reinstall": true},
	"go":       {"install": true, "get": true},
	"dotnet":   {"package": true},
}

// execSubcmds are subcommands that fetch and immediately execute a
// package (`npm exec foo`, `pnpm dlx foo`). They map to the exec-style
// family whose flag tables apply.
var execSubcmds = map[string]map[string]string{
	"npm":  {"exec": "npx", "x": "npx"},
	"pnpm": {"dlx": "pnpm-dlx"},
	"yarn": {"dlx": "yarn-dlx"},
	"bun":  {"x": "bunx"},
	"pipx": {"run": "pipx-run"},
	"uv":   {"run": "uv-run"},
	"go":   {"run": "go-run"},
}

// execBinaries run a package directly from the binary name.
var execBinaries = map[string]string{
	"npx": "npx", "pnpx": "pnpm-dlx", "bunx": "bunx", "uvx": "uvx",
}

// globalPrefixes: `yarn global add x`, `composer global require x`.
var globalPrefixes = map[string]bool{"yarn": true, "composer": true}

// familyOf maps an effective binary to the name SplitNameVersion and
// the ecosystem table understand.
var familyOf = map[string]string{
	"npx": "npm", "pnpm-dlx": "npm", "yarn-dlx": "npm", "bunx": "npm",
	"uvx": "uv", "uv-tool": "uv", "uv-run": "uv", "pipx-run": "pipx",
	"go-run": "go",
}

func family(eff string) string {
	if f, ok := familyOf[eff]; ok {
		return f
	}
	return eff
}

var shellBinaries = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ash": true, "ksh": true,
	"fish": true, "mksh": true, "busybox": true,
}

var npmFlagArgs = map[string]bool{
	"--registry": true, "--prefix": true, "--cache": true, "--userconfig": true,
	"--globalconfig": true, "--workspace": true, "-w": true, "--tag": true,
	"--omit": true, "--include": true, "--install-strategy": true, "--loglevel": true,
	"--save-prefix": true, "--before": true, "--node-options": true, "--script-shell": true,
}

var uvFlagArgs = map[string]bool{
	"--index": true, "--index-url": true, "--extra-index-url": true, "--default-index": true,
	"-i": true, "-f": true, "--find-links": true, "--python": true, "-p": true,
	"--from": true, "--with": true, "--with-requirements": true, "--with-editable": true,
	"-r": true, "--requirement": true, "-c": true, "--constraint": true,
	"-e": true, "--editable": true, "--directory": true, "--project": true,
	"--cache-dir": true, "--config-file": true, "--group": true, "--optional": true,
	"--extra": true, "--package": true, "--index-strategy": true, "--keyring-provider": true,
}

// flagsWithArg lists flags that consume the next token (e.g. `-r reqs.txt`).
// pip3 aliases pip in init() — single source of truth; updating one
// can't silently leave the other behind.
var flagsWithArg = map[string]map[string]bool{
	"pip": {
		"-r": true, "--requirement": true, "-c": true, "--constraint": true,
		"-e": true, "--editable": true, "-t": true, "--target": true,
		"-i": true, "--index-url": true, "--extra-index-url": true,
		"-f": true, "--find-links": true, "--prefix": true, "--root": true, "--src": true,
		"--trusted-host": true, "--platform": true, "--python-version": true,
		"--implementation": true, "--abi": true, "--upgrade-strategy": true,
		"--progress-bar": true, "--log": true, "--cache-dir": true, "--proxy": true,
		"--retries": true, "--timeout": true, "--exists-action": true, "--cert": true,
		"--client-cert": true, "--only-binary": true, "--no-binary": true,
		"--global-option": true, "--config-settings": true, "-C": true, "--report": true,
		"-d": true, "--dest": true, "--python": true,
	},
	"uv-pip":  uvFlagArgs,
	"uv":      uvFlagArgs,
	"uv-tool": uvFlagArgs,
	"uv-run":  uvFlagArgs,
	"uvx":     uvFlagArgs,
	"poetry": {
		"--source": true, "--python": true, "-E": true, "--extras": true,
		"-G": true, "--group": true, "-C": true, "--directory": true, "-P": true, "--project": true,
	},
	"npm":      npmFlagArgs,
	"npx":      mergeFlags(npmFlagArgs, map[string]bool{"-p": true, "--package": true, "-c": true, "--call": true}),
	"pnpm-dlx": mergeFlags(npmFlagArgs, map[string]bool{"--package": true}),
	"yarn-dlx": map[string]bool{"-p": true, "--package": true},
	"bunx":     map[string]bool{"-p": true, "--package": true, "--registry": true},
	"pnpm": {
		"--registry": true, "--prefix": true, "--cache": true,
		"--workspace": true, "-w": true, "--filter": true, "-C": true, "--dir": true,
	},
	"yarn": {
		"--registry": true, "--cache-folder": true, "--modules-folder": true, "--cwd": true,
	},
	"bun": {
		"--registry": true, "--cwd": true, "--config": true, "-c": true,
	},
	"cargo": {
		"--registry": true, "--index": true, "--path": true, "--git": true,
		"--branch": true, "--tag": true, "--rev": true, "--root": true,
		"--target": true, "--profile": true, "-Z": true, "--features": true, "-F": true,
		"--manifest-path": true, "--package": true, "-p": true, "--config": true,
		"--bin": true, "--example": true, "-j": true, "--jobs": true, "--rename": true,
	},
	"gem": {
		"--source": true, "-s": true, "--bindir": true, "--install-dir": true, "-i": true, "-n": true,
		"-v": true, "--version": true, "--platform": true, "-g": true, "--file": true,
	},
	"composer": {
		"--working-dir": true, "-d": true, "--repository": true, "--repository-url": true,
	},
	"pipx": {
		"--python": true, "--pip-args": true, "--index-url": true, "--spec": true,
		"--suffix": true,
	},
	"pipx-run": {
		"--python": true, "--pip-args": true, "--index-url": true, "--spec": true,
	},
	"go": {
		"-modfile": true, "-ldflags": true, "-tags": true, "-mod": true,
		"-pkgdir": true, "-buildmode": true, "-gcflags": true, "-asmflags": true,
		"-C": true, "-o": true, "-p": true, "-overlay": true, "-pgo": true, "-toolexec": true,
		"-exec": true,
	},
	"go-run": nil, // set in init: same as go
	"dotnet": {
		"--version": true, "--framework": true, "-f": true,
		"--source": true, "-s": true, "--package-directory": true,
		"--add-source": true, "--configfile": true, "--tool-path": true, "-v": true,
	},
	// brew has no flag-with-arg verbs we care about for `brew install`.
	// --cask / --formula / --HEAD / -q etc. are all boolean and the
	// default no-flag-arg branch already skips them.
}

// sourceFlags redirect where the package is resolved from. Watchdog
// scans the public registry artifact; with one of these flags the
// package manager may install something else entirely (dependency
// confusion, attacker registry), so each occurrence becomes a note
// that forces `ask`.
var sourceFlags = map[string]bool{
	"--registry": true, "--userconfig": true, "--globalconfig": true,
	"--index": true, "--index-url": true, "--extra-index-url": true,
	"--default-index": true, "--find-links": true, "--pip-args": true,
	"--git": true, "--source": true, "--add-source": true, "--configfile": true,
	"--repository": true, "--repository-url": true, "--config": true,
	"--trusted-host": true, "--config-file": true,
}

// sourceShortFlags are single-letter source flags, only meaningful
// for the listed families.
var sourceShortFlags = map[string]map[string]bool{
	"pip":     {"-i": true, "-f": true},
	"pip3":    {"-i": true, "-f": true},
	"uv":      {"-i": true, "-f": true},
	"uv-pip":  {"-i": true, "-f": true},
	"uv-tool": {"-i": true, "-f": true},
	"uv-run":  {"-i": true, "-f": true},
	"uvx":     {"-i": true, "-f": true},
	"gem":     {"-s": true},
	"dotnet":  {"-s": true},
}

// pipLike families accept pip's requirement/constraint flags.
var pipLike = map[string]bool{
	"pip": true, "pip3": true, "uv": true, "uv-pip": true, "uv-tool": true, "uv-run": true, "uvx": true,
}

// packageFlags carry a package spec as their value (`npx -p foo`,
// `uvx --from foo`, `pipx install --spec foo`).
var packageFlags = map[string]map[string]bool{
	"npx":      {"-p": true, "--package": true},
	"pnpm-dlx": {"--package": true},
	"yarn-dlx": {"-p": true, "--package": true},
	"bunx":     {"-p": true, "--package": true},
	"uvx":      {"--from": true, "--with": true},
	"uv-tool":  {"--with": true},
	"uv-run":   {"--with": true},
	"pipx":     {"--spec": true},
	"pipx-run": {"--spec": true},
}

func mergeFlags(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func init() {
	flagsWithArg["pip3"] = flagsWithArg["pip"]
	flagsWithArg["go-run"] = flagsWithArg["go"]
}

var urlPathPrefixes = []string{
	"./", "../", "/", "~/", "~", ".\\",
	"git+", "http://", "https://", "ftp://", "file://",
	"svn+", "hg+", "bzr+", "git://", "ssh://", "git@",
}

var archiveSuffixes = []string{
	".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2",
	".zip", ".whl", ".gem", ".nupkg",
}

func isURLOrPath(tok string) bool {
	for _, p := range urlPathPrefixes {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	// `name @ https://…` (PEP 508 direct reference) and npm
	// `alias@npm:other` / `name@github:user/repo` / `user/repo`.
	if strings.Contains(tok, "://") || strings.Contains(tok, "@npm:") ||
		strings.Contains(tok, "@github:") || strings.Contains(tok, "@git+") ||
		strings.Contains(tok, "@file:") || strings.HasPrefix(tok, "github:") ||
		strings.HasPrefix(tok, "npm:") || strings.HasPrefix(tok, "file:") {
		return true
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
	pipVersionRE = regexp.MustCompile(`^([A-Za-z0-9_.\-\[\],]+)\s*(?:==|@)\s*([A-Za-z0-9_.\-+!]+)$`)
	pipBareRE    = regexp.MustCompile(`[<>=!~;\[ ]`)
	pipBinaryRE  = regexp.MustCompile(`^pip[0-9.]*$`)
	pythonRE     = regexp.MustCompile(`^(python[0-9.]*|py|pypy[0-9.]*)$`)
)

// SplitNameVersion extracts (name, version) from a token per binary.
// Empty version means unpinned.
func SplitNameVersion(tok, binary string) (string, string) {
	switch family(binary) {
	case "npm", "pnpm", "yarn", "bun":
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
	case "pip", "pip3", "pipx", "uv", "uv-pip", "poetry":
		if m := pipVersionRE.FindStringSubmatch(tok); m != nil {
			return stripExtras(m[1]), m[2]
		}
		// Strip trailing PEP 440 specifier (>=, <, ~=, !=, ==), extras
		// and environment markers.
		parts := pipBareRE.Split(tok, 2)
		if parts[0] == "" {
			return "", ""
		}
		return parts[0], ""
	case "cargo", "go":
		at := strings.Index(tok, "@")
		if at == -1 {
			return tok, ""
		}
		return tok[:at], tok[at+1:]
	case "gem", "brew", "dotnet":
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

func stripExtras(name string) string {
	if i := strings.Index(name, "["); i != -1 {
		return name[:i]
	}
	return name
}

// normalizeBinary folds platform suffixes and versioned names onto
// the canonical binary (`pip3.12` → pip, `npm.cmd` → npm).
func normalizeBinary(b string) string {
	b = lastPathSegment(strings.ReplaceAll(b, "\\", "/"))
	low := strings.ToLower(b)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		if strings.HasSuffix(low, ext) {
			b = b[:len(b)-len(ext)]
			break
		}
	}
	if pipBinaryRE.MatchString(b) {
		return "pip"
	}
	return b
}

// invocation is a resolved install/exec call.
type invocation struct {
	eff  string   // effective binary key into the flag tables
	args []string // flags + positionals after the subcommand (global flags first)
	exec bool     // exec-style: first positional is the package, rest is its argv
}

// resolveInvocation finds the install (or exec) subcommand after the
// binary, skipping global flags (`npm --loglevel silent -g install x`).
// Returns ok=false when the command is not install-shaped.
func resolveInvocation(binary string, rest []string) (invocation, bool) {
	if eff, ok := execBinaries[binary]; ok {
		return invocation{eff: eff, args: rest, exec: true}, true
	}
	if _, ok := EcosystemByCmd[binary]; !ok {
		return invocation{}, false
	}
	argTable := flagsWithArg[binary]
	var global []string
	i := 0
	for i < len(rest) {
		t := rest[i]
		if !strings.HasPrefix(t, "-") || t == "-" {
			break
		}
		global = append(global, t)
		if !strings.Contains(t, "=") && argTable[t] && i+1 < len(rest) {
			global = append(global, rest[i+1])
			i += 2
			continue
		}
		i++
	}
	if i >= len(rest) {
		return invocation{}, false
	}
	sub := rest[i]
	// `npm --loglevel silent install x`: an unknown bare flag ate a
	// value that sits where the subcommand should be.
	if !isKnownSubcmd(binary, sub) && len(global) > 0 && !strings.Contains(global[len(global)-1], "=") &&
		i+1 < len(rest) && isKnownSubcmd(binary, rest[i+1]) {
		global = append(global, sub)
		i++
		sub = rest[i]
	}
	after := rest[i+1:]

	switch {
	case globalPrefixes[binary] && sub == "global" && len(after) > 0:
		sub, after = after[0], after[1:]
	case binary == "uv" && sub == "pip" && len(after) > 0:
		return invocation{eff: "uv-pip", args: append(global, after[1:]...)}, InstallSubcmds["uv-pip"][after[0]]
	case binary == "uv" && sub == "tool" && len(after) > 0:
		if after[0] == "run" {
			return invocation{eff: "uvx", args: append(global, after[1:]...), exec: true}, true
		}
		return invocation{eff: "uv-tool", args: append(global, after[1:]...)}, InstallSubcmds["uv-tool"][after[0]]
	case binary == "dotnet" && sub == "tool" && len(after) > 0:
		if after[0] == "install" || after[0] == "update" || after[0] == "run" || after[0] == "exec" {
			return invocation{eff: "dotnet", args: append(global, after[1:]...)}, true
		}
		return invocation{}, false
	case binary == "dotnet" && sub == "add":
		// `dotnet add package <Name>` or `dotnet add <project> package <Name>`.
		for j := 0; j < 2 && j < len(after); j++ {
			if after[j] == "package" {
				return invocation{eff: "dotnet", args: append(global, after[j+1:]...)}, j+1 < len(after)
			}
		}
		return invocation{}, false
	}
	if eff, ok := execSubcmds[binary][sub]; ok {
		return invocation{eff: eff, args: append(global, after...), exec: true}, true
	}
	if !InstallSubcmds[binary][sub] {
		return invocation{}, false
	}
	return invocation{eff: binary, args: append(global, after...)}, true
}

func isKnownSubcmd(binary, sub string) bool {
	if InstallSubcmds[binary][sub] {
		return true
	}
	if _, ok := execSubcmds[binary][sub]; ok {
		return true
	}
	return (binary == "uv" && (sub == "pip" || sub == "tool")) ||
		(binary == "dotnet" && (sub == "add" || sub == "tool")) ||
		(globalPrefixes[binary] && sub == "global")
}

// ParseInstall parses one install-shaped command segment. Returns the
// packages it found plus notes describing install forms Watchdog
// cannot fully vet (requirements files, editable installs, URLs,
// local paths, custom registries, runtime-supplied arguments). Any
// note forces at least an `ask` at the preflight layer.
func ParseInstall(command string) ([]types.Package, []string) {
	tokens, err := Tokenize(strings.TrimSpace(command))
	if err != nil {
		return nil, []string{"malformed shell command: " + err.Error()}
	}
	s := stripCommandPrefixes(tokens)
	inv, _, ok := detectInstall(s.tokens)
	if !ok {
		return nil, nil
	}
	pkgs, notes := parseArgs(inv)
	if s.viaArgs != "" {
		notes = append(notes, "install arguments supplied at runtime via "+s.viaArgs)
	}
	notes = append(notes, registryEnvNotes(s.envs)...)
	return pkgs, notes
}

// detectInstall classifies prefix-stripped tokens. viaPython reports
// that the package manager was reached through `python -m`, i.e. the
// binary in tokens[0] is the interpreter, not the package manager.
func detectInstall(tokens []string) (inv invocation, viaPython bool, ok bool) {
	if len(tokens) < 2 {
		return invocation{}, false, false
	}
	binary := normalizeBinary(tokens[0])
	rest := tokens[1:]
	// `python -m pip install x`, `python3 -m pipx run x`, `py -m uv …`.
	if pythonRE.MatchString(binary) {
		mod := -1
		for j, t := range rest {
			if t == "-m" && j+1 < len(rest) {
				mod = j + 1
				break
			}
			if !strings.HasPrefix(t, "-") {
				break
			}
		}
		if mod == -1 {
			return invocation{}, false, false
		}
		binary = normalizeBinary(rest[mod])
		rest = rest[mod+1:]
		viaPython = true
	}
	inv, ok = resolveInvocation(binary, rest)
	return inv, viaPython, ok
}

func parseArgs(inv invocation) ([]types.Package, []string) {
	eff := inv.eff
	fam := family(eff)
	ecosystem := EcosystemByCmd[fam]
	if ecosystem == "" {
		ecosystem = EcosystemByCmd[eff]
	}
	flagArgs := flagsWithArg[eff]
	pkgFlags := packageFlags[eff]
	var pkgs []types.Package
	var notes []string
	var dotnetVersion string
	sawPackageFlag := false

	addPackage := func(tok string) {
		if isURLOrPath(tok) {
			notes = append(notes, "url/path install: "+tok)
			return
		}
		name, version := SplitNameVersion(tok, eff)
		if name == "" {
			return
		}
		pkgs = append(pkgs, types.Package{Ecosystem: ecosystem, Name: name, Version: version})
	}

	args := inv.args
	afterDashDash := false
	i := 0
	for i < len(args) {
		tok := args[i]
		if tok == "--" && !afterDashDash {
			afterDashDash = true
			i++
			continue
		}
		if !afterDashDash && strings.HasPrefix(tok, "-") && tok != "-" {
			flagName := tok
			inlineVal := ""
			hasInline := false
			if eq := strings.Index(tok, "="); eq != -1 {
				flagName = tok[:eq]
				inlineVal = tok[eq+1:]
				hasInline = true
			}
			consumes := flagArgs[flagName]
			value := inlineVal
			if consumes && !hasInline && i+1 < len(args) {
				value = args[i+1]
			}
			if sourceFlags[flagName] || sourceShortFlags[eff][flagName] {
				notes = append(notes, "custom registry/source: "+flagName+" "+value)
			}
			if pkgFlags[flagName] && value != "" {
				sawPackageFlag = true
				addPackage(value)
			}
			if consumes {
				switch flagName {
				case "-r", "--requirement", "--with-requirements":
					if value != "" {
						notes = append(notes, "requirements file: "+value)
					}
				case "-c", "--constraint":
					if value != "" && pipLike[eff] {
						notes = append(notes, "constraints file: "+value)
					}
				case "-e", "--editable", "--with-editable":
					if value != "" {
						notes = append(notes, "editable install: "+value)
					}
				case "--path":
					if value != "" && fam == "cargo" {
						notes = append(notes, "url/path install: "+value)
					}
				case "--version":
					if eff == "dotnet" && value != "" {
						dotnetVersion = value
					}
				}
				if hasInline {
					i++
				} else {
					i += 2
				}
				continue
			}
			i++
			continue
		}
		// Positional.
		if inv.exec {
			// The first positional is the package to run — unless a
			// package flag already named it, in which case it is the
			// binary inside that package. Everything after belongs to
			// the executed program, not to the package manager.
			if !sawPackageFlag && eff != "uv-run" {
				if eff == "go-run" {
					if strings.Contains(tok, "@") {
						addPackage(tok)
					}
				} else {
					addPackage(tok)
				}
			}
			break
		}
		addPackage(tok)
		i++
	}
	if eff == "dotnet" && dotnetVersion != "" {
		for j := range pkgs {
			if pkgs[j].Version == "" {
				pkgs[j].Version = dotnetVersion
			}
		}
	}
	return pkgs, notes
}

// ParsePackages is a convenience wrapper for callers that don't need notes.
func ParsePackages(command string) []types.Package {
	pkgs, _ := ParseInstall(command)
	return pkgs
}

// ExtractSubshells returns the inner commands a command will execute
// as a nested shell script: `sh -c "..."` (including combined flags
// such as `bash -lc`), `eval ...`, and every `$(...)`, backtick and
// process substitution. Wrapper prefixes (`env`, `sudo`, ...) are
// peeled first so `sudo bash -c "..."` is also unwrapped.
func ExtractSubshells(command string) []string {
	out := ExtractSubstitutions(command)
	tokens, err := Tokenize(strings.TrimSpace(command))
	if err != nil || len(tokens) == 0 {
		return out
	}
	tokens = stripCommandPrefixes(tokens).tokens
	if len(tokens) == 0 {
		return out
	}
	binary := normalizeBinary(tokens[0])
	if binary == "eval" && len(tokens) > 1 {
		return append(out, strings.Join(tokens[1:], " "))
	}
	if !shellBinaries[binary] {
		return out
	}
	for i := 1; i < len(tokens)-1; i++ {
		tok := tokens[i]
		// `-c`, `-lc`, `-ec`, `-xec`: any short-flag cluster with c.
		if len(tok) > 1 && tok[0] == '-' && tok[1] != '-' && strings.ContainsRune(tok[1:], 'c') {
			out = append(out, tokens[i+1])
			i++
		}
	}
	return out
}

// ExtractSubstitutions returns the bodies of `$(...)`, `<(...)`,
// `>(...)` and backtick substitutions outside single quotes. These run
// before (or alongside) the outer command, so an install hidden inside
// one executes even when the outer command is harmless (`echo $(npm i x)`).
func ExtractSubstitutions(command string) []string {
	var out []string
	runes := []rune(command)
	inSingle := false
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '\\' && !inSingle:
			i++
		case c == '\'':
			inSingle = !inSingle
		case inSingle:
		case c == '`':
			j := i + 1
			for j < len(runes) && runes[j] != '`' {
				if runes[j] == '\\' {
					j++
				}
				j++
			}
			if j > len(runes) {
				j = len(runes)
			}
			out = append(out, string(runes[i+1:j]))
			i = j
		case (c == '$' || c == '<' || c == '>') && i+1 < len(runes) && runes[i+1] == '(':
			depth := 0
			j := i + 1
			for ; j < len(runes); j++ {
				if runes[j] == '(' {
					depth++
				} else if runes[j] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			end := min(j, len(runes))
			body := string(runes[i+2 : end])
			// `$((1+2))` is arithmetic, not a command.
			if !(c == '$' && strings.HasPrefix(body, "(")) {
				out = append(out, body)
			}
			i = end
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
