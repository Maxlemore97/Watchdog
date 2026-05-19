package parsers

import (
	"reflect"
	"testing"
)

func TestTamperPatterns_Detection(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"clean install", "npm install lodash", nil},
		{"clean ls", "ls -la", nil},
		{"unset path", "unset PATH; npm install evil", []string{TamperUnsetPath}},
		{"unset -v path", "unset -v PATH", []string{TamperUnsetPath}},
		{"env -u path", "env -u PATH npm install evil", []string{TamperUnsetPath}},
		{"path= inline", "PATH=/tmp:/usr/bin npm install evil",
			[]string{TamperPathOverride}},
		{"path= inline + abs path", "PATH=/tmp /usr/bin/npm install evil",
			[]string{TamperAbsPathInstall, TamperPathOverride}},
		{"export path", "export PATH=/tmp", []string{TamperPathOverride}},
		{"abs path install", "/opt/homebrew/bin/npm install lodash", []string{TamperAbsPathInstall}},
		{"abs path non-install", "/opt/homebrew/bin/npm test", nil},
		{"settings.json write", "echo {} > ~/.claude/settings.json",
			[]string{TamperSettingsJSONEdit}},
		{"settings.local.json sed -i", "sed -i 's/x/y/' ~/.claude/settings.local.json",
			[]string{TamperSettingsJSONEdit}},
		{"settings.json read", "cat ~/.claude/settings.json", nil},
		{"pkill watchdog", "pkill watchdog-pretool", []string{TamperWatchdogKill}},
		{"killall watchdog", "killall watchdog-mcp", []string{TamperWatchdogKill}},
		{"pkill -f watchdog", "pkill -f watchdog-pretool", []string{TamperWatchdogKill}},
		{"rm watchdog dir", "rm -rf ~/.watchdog/bin", []string{TamperWatchdogRemove}},
		{"rm manifest", "rm ~/.watchdog/manifest.json",
			[]string{TamperManifestTamper, TamperWatchdogRemove}},
		{"chmod -x shim", "chmod -x ~/.watchdog/bin/npm", []string{TamperWatchdogRemove}},
		{"bash -c subshell unset", `bash -c "unset PATH; npm install evil"`,
			[]string{TamperUnsetPath}},
		{"sh -c subshell abspath", `sh -c "/usr/bin/pip install evil"`,
			[]string{TamperAbsPathInstall}},
		{"abs path brew", "/opt/homebrew/bin/brew install lodash",
			[]string{TamperAbsPathInstall}},
		{"abs path pipx", "/usr/local/bin/pipx install ruff",
			[]string{TamperAbsPathInstall}},
		{"abs path go install", "/usr/local/go/bin/go install golang.org/x/tools/cmd/godoc@v0.20.0",
			[]string{TamperAbsPathInstall}},
		{"abs path dotnet add package", "/usr/local/share/dotnet/dotnet add package Newtonsoft.Json",
			[]string{TamperAbsPathInstall}},
		{"abs path dotnet add with project", "/usr/local/share/dotnet/dotnet add MyProj.csproj package Newtonsoft.Json",
			[]string{TamperAbsPathInstall}},
		{"abs path dotnet build (non-install)", "/usr/local/share/dotnet/dotnet build", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TamperPatterns(tc.cmd)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("TamperPatterns(%q)\n  got: %v\n  want: %v", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestTamperPatterns_AbsPathInstallVariants(t *testing.T) {
	// Each ecosystem we recognise should match when the binary is
	// invoked by absolute path with an install subcmd. This is a
	// regression guard so adding a new ecosystem to EcosystemByCmd
	// without updating tamper.go doesn't silently leak.
	for binary, subcmds := range InstallSubcmds {
		for sub := range subcmds {
			cmd := "/usr/local/bin/" + binary + " " + sub + " foo"
			got := TamperPatterns(cmd)
			if len(got) == 0 || got[0] != TamperAbsPathInstall {
				t.Errorf("abs-path %s %s not flagged: %v", binary, sub, got)
			}
		}
	}
}

func TestTamperPatterns_NoFalsePositiveOnPathInSubstring(t *testing.T) {
	// "PATH" inside a string literal that isn't an env var should not
	// trip PATH_OVERRIDE.
	cmd := `echo "the PATH variable is not set"`
	got := TamperPatterns(cmd)
	for _, c := range got {
		if c == TamperPathOverride || c == TamperUnsetPath {
			t.Errorf("false positive: %v on %q", got, cmd)
		}
	}
}
