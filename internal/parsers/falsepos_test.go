package parsers

import (
	"slices"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// Commands that previously tripped the tamper/install checks although
// they assign nothing and install nothing. Each one was blocked in a
// real session.
func TestTamperPatterns_NoFalsePositives(t *testing.T) {
	for _, cmd := range []string{
		`grep -n 'PATH=\|WATCHDOG' internal/parsers/tamper.go`,
		`echo WATCHDOG_MODE=osv`,
		`rg "PATH=/usr/bin" docs/`,
		`git commit -m "doc: explain WATCHDOG_DISABLE=1"`,
		"python3 - <<'EOF'\nprint('npm install evil; PATH=/x')\nEOF",
		`python3 -c 'import json; print(json.load(open(".claude/settings.json")))'`,
		`cat ~/.claude/settings.json`,
	} {
		if got := TamperPatterns(cmd); len(got) != 0 {
			t.Errorf("TamperPatterns(%q) = %v, want none", cmd, got)
		}
	}
}

func TestTamperPatterns_AssignmentPositions(t *testing.T) {
	for cmd, want := range map[string]string{
		"PATH=/evil npm i x":                          TamperPathOverride,
		"export PATH=/evil:$PATH":                     TamperPathOverride,
		"sudo PATH=/evil npm i x":                     TamperPathOverride,
		"env -i PATH=/evil npm i x":                   TamperPathOverride,
		"launchctl setenv PATH /evil":                 TamperPathOverride,
		"readonly WATCHDOG_MODE=osv":                  TamperWatchdogEnv,
		"bash <<EOF\nWATCHDOG_DISABLE=1 npm i x\nEOF": TamperWatchdogEnv,
	} {
		if got := TamperPatterns(cmd); !slices.Contains(got, want) {
			t.Errorf("TamperPatterns(%q) = %v, want %s", cmd, got, want)
		}
	}
}

func TestTamperPatterns_HostConfigWrites(t *testing.T) {
	for _, cmd := range []string{
		`python3 -c "open('/Users/x/.claude/settings.json','w').write('{}')"`,
		`node -e "require('fs').writeFileSync(process.env.HOME+'/.cursor/mcp.json','{}')"`,
		`echo '{}' > ~/Library/Application\ Support/Claude/claude_desktop_config.json`,
		`dd if=/dev/null of=~/.codeium/windsurf/mcp_config.json`,
		`truncate -s0 ~/.gemini/settings.json`,
		"python3 - <<'EOF'\nimport os\nos.remove(os.path.expanduser('~/.watchdog/manifest.json'))\nEOF",
	} {
		got := TamperPatterns(cmd)
		if !slices.Contains(got, TamperSettingsJSONEdit) && !slices.Contains(got, TamperManifestTamper) {
			t.Errorf("TamperPatterns(%q) = %v, want a config/manifest write hit", cmd, got)
		}
	}
}

func TestCollectPackages_Heredocs(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"bash <<EOF\nnpm install evil\nEOF", true},
		{"cat <<'EOF' | sh\nnpm install evil\nEOF", true},
		{"cat > notes.txt <<EOF\n$(npm install evil)\nEOF", true}, // unquoted: substitution runs
		{"cat > notes.txt <<'EOF'\n$(npm install evil)\nEOF", false},
		{"python3 - <<'EOF'\nprint('npm install evil')\nEOF", false},
		{"git commit -F - <<EOF\nfix: npm install evil no longer works\nEOF", false},
	}
	for _, tc := range cases {
		pkgs, _ := CollectPackages(tc.cmd, nil)
		got := slices.ContainsFunc(pkgs, func(p types.Package) bool { return p.Name == "evil" })
		if got != tc.want {
			t.Errorf("CollectPackages(%q) detected=%v, want %v (pkgs=%v)", tc.cmd, got, tc.want, pkgs)
		}
	}
}
