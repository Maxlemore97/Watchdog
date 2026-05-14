package parsers

import (
	"reflect"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// identityResolve keeps tests pure (no network).
func identityResolve(p types.Package) types.Package { return p }

// ---------- ParseInstall — npm/pnpm/yarn -------------------------

func TestParseInstall_NPMBasic(t *testing.T) {
	pkgs, notes := ParseInstall("npm install lodash")
	want := []types.Package{{Ecosystem: "npm", Name: "lodash"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %v", notes)
	}
}

func TestParseInstall_NPMVersioned(t *testing.T) {
	pkgs, _ := ParseInstall("npm install lodash@4.17.21")
	want := []types.Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_ScopedNPM(t *testing.T) {
	pkgs, _ := ParseInstall("npm install @scope/pkg@1.2.3")
	want := []types.Package{{Ecosystem: "npm", Name: "@scope/pkg", Version: "1.2.3"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_ScopedNoVersion(t *testing.T) {
	pkgs, _ := ParseInstall("npm install @scope/pkg")
	want := []types.Package{{Ecosystem: "npm", Name: "@scope/pkg"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_PnpmAdd(t *testing.T) {
	pkgs, _ := ParseInstall("pnpm add react@18")
	want := []types.Package{{Ecosystem: "npm", Name: "react", Version: "18"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_YarnOnlyAdd(t *testing.T) {
	if pkgs, _ := ParseInstall("yarn install"); len(pkgs) != 0 {
		t.Errorf("yarn install should not register packages: %v", pkgs)
	}
}

// ---------- ParseInstall — pip/uv/poetry ------------------------

func TestParseInstall_PipBasic(t *testing.T) {
	pkgs, _ := ParseInstall("pip install requests")
	want := []types.Package{{Ecosystem: "PyPI", Name: "requests"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_PipPinned(t *testing.T) {
	pkgs, _ := ParseInstall("pip install requests==2.31.0")
	want := []types.Package{{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_PipSpecifierStrippedToName(t *testing.T) {
	pkgs, _ := ParseInstall("pip install requests>=2.0")
	want := []types.Package{{Ecosystem: "PyPI", Name: "requests"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_PipRequirementsNote(t *testing.T) {
	pkgs, notes := ParseInstall("pip install -r reqs.txt")
	if len(pkgs) != 0 {
		t.Errorf("expected no packages, got %v", pkgs)
	}
	if len(notes) == 0 || notes[0] != "requirements file: reqs.txt" {
		t.Errorf("notes = %v", notes)
	}
}

func TestParseInstall_PipEditableNote(t *testing.T) {
	_, notes := ParseInstall("pip install -e ./local")
	if len(notes) == 0 || notes[0] != "editable install: ./local" {
		t.Errorf("notes = %v", notes)
	}
}

func TestParseInstall_UVPip(t *testing.T) {
	pkgs, _ := ParseInstall("uv pip install httpx==0.27.0")
	want := []types.Package{{Ecosystem: "PyPI", Name: "httpx", Version: "0.27.0"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_UVAdd(t *testing.T) {
	pkgs, _ := ParseInstall("uv add ruff")
	want := []types.Package{{Ecosystem: "PyPI", Name: "ruff"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_PoetryAdd(t *testing.T) {
	pkgs, _ := ParseInstall("poetry add pydantic@2.5.0")
	want := []types.Package{{Ecosystem: "PyPI", Name: "pydantic", Version: "2.5.0"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

// ---------- cargo/gem/composer ------------------------------------

func TestParseInstall_CargoVersioned(t *testing.T) {
	pkgs, _ := ParseInstall("cargo add serde@1.0.0")
	want := []types.Package{{Ecosystem: "crates.io", Name: "serde", Version: "1.0.0"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_GemBasic(t *testing.T) {
	pkgs, _ := ParseInstall("gem install rake")
	want := []types.Package{{Ecosystem: "RubyGems", Name: "rake"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

func TestParseInstall_ComposerVersioned(t *testing.T) {
	pkgs, _ := ParseInstall("composer require monolog/monolog:2.9.0")
	want := []types.Package{{Ecosystem: "Packagist", Name: "monolog/monolog", Version: "2.9.0"}}
	if !reflect.DeepEqual(pkgs, want) {
		t.Errorf("pkgs = %v, want %v", pkgs, want)
	}
}

// ---------- guards: non-install, malformed --------------------

func TestParseInstall_NonInstallSubcmd(t *testing.T) {
	pkgs, _ := ParseInstall("npm test")
	if len(pkgs) != 0 {
		t.Errorf("npm test should yield no packages: %v", pkgs)
	}
}

func TestParseInstall_UnknownBinary(t *testing.T) {
	pkgs, _ := ParseInstall("ls install foo")
	if len(pkgs) != 0 {
		t.Errorf("unknown binary should yield no packages: %v", pkgs)
	}
}

func TestParseInstall_MalformedShellNotes(t *testing.T) {
	pkgs, notes := ParseInstall(`npm install "unterminated`)
	if len(pkgs) != 0 {
		t.Errorf("malformed shell: expected no pkgs, got %v", pkgs)
	}
	if len(notes) == 0 {
		t.Errorf("malformed shell should produce a note")
	}
}

func TestParseInstall_URLBecomesNote(t *testing.T) {
	_, notes := ParseInstall("pip install https://example.com/x.whl")
	if len(notes) == 0 {
		t.Errorf("URL install should produce a note")
	}
}

func TestParseInstall_LocalPathBecomesNote(t *testing.T) {
	_, notes := ParseInstall("pip install ./local-pkg")
	if len(notes) == 0 {
		t.Errorf("local path install should produce a note")
	}
}

// ---------- SplitOnOperators ----------------------------------

func TestSplitOnOperators_AmpersandAmpersand(t *testing.T) {
	got := SplitOnOperators("npm i a && pip install b")
	if len(got) != 2 {
		t.Fatalf("want 2 segments, got %v", got)
	}
}

func TestSplitOnOperators_PreservesVersionSpecifiers(t *testing.T) {
	// `>=` must not split.
	got := SplitOnOperators("pip install requests>=2.0")
	if len(got) != 1 {
		t.Errorf("want 1 segment, got %v", got)
	}
}

func TestSplitOnOperators_Semicolon(t *testing.T) {
	got := SplitOnOperators("npm i a; pip install b")
	if len(got) != 2 {
		t.Errorf("want 2 segments, got %v", got)
	}
}

// ---------- CollectPackages ----------------------------------

func TestCollectPackages_Chained(t *testing.T) {
	pkgs, _ := CollectPackages("npm install a && pip install b", identityResolve)
	if len(pkgs) != 2 {
		t.Fatalf("want 2 pkgs, got %v", pkgs)
	}
	if pkgs[0].Name != "a" || pkgs[1].Name != "b" {
		t.Errorf("unexpected pkgs: %v", pkgs)
	}
}

func TestCollectPackages_Subshell(t *testing.T) {
	pkgs, _ := CollectPackages(`bash -c "npm install foo"`, identityResolve)
	if len(pkgs) != 1 || pkgs[0].Name != "foo" {
		t.Errorf("subshell pkgs = %v", pkgs)
	}
}

func TestCollectPackages_DepthCap(t *testing.T) {
	// 4 nested levels — must not recurse forever.
	pkgs, _ := CollectPackages(`bash -c "bash -c \"bash -c \\\"bash -c 'npm install x'\\\" \" "`, identityResolve)
	// We don't assert specific pkg list (escaping makes that flaky);
	// just that it returns without timing out.
	_ = pkgs
}

func TestCollectPackages_ResolverApplied(t *testing.T) {
	resolver := func(p types.Package) types.Package {
		if p.Version == "" {
			p.Version = "RESOLVED"
		}
		return p
	}
	pkgs, _ := CollectPackages("npm install foo", resolver)
	if len(pkgs) != 1 || pkgs[0].Version != "RESOLVED" {
		t.Errorf("resolver not applied: %v", pkgs)
	}
}

// ---------- plugin prompt -------------------------------------

func TestClassifyPluginTarget_GitURL(t *testing.T) {
	eco, name, ver := ClassifyPluginTarget("https://github.com/foo/bar.git")
	if eco != "plugin" || name != "https://github.com/foo/bar.git" || ver != "" {
		t.Errorf("got (%s,%s,%s)", eco, name, ver)
	}
}

func TestClassifyPluginTarget_NameAtVersion(t *testing.T) {
	eco, name, ver := ClassifyPluginTarget("foo@1.2.3")
	if eco != "plugin" || name != "foo" || ver != "1.2.3" {
		t.Errorf("got (%s,%s,%s)", eco, name, ver)
	}
}

func TestClassifyPluginTarget_LeadingAtIsName(t *testing.T) {
	eco, name, ver := ClassifyPluginTarget("@scope/pkg")
	if eco != "plugin" || name != "@scope/pkg" || ver != "" {
		t.Errorf("got (%s,%s,%s)", eco, name, ver)
	}
}

func TestExtractPluginTargets_Install(t *testing.T) {
	got := ExtractPluginTargets("/plugin install foo@1.0")
	if len(got) != 1 || got[0] != "foo@1.0" {
		t.Errorf("got %v", got)
	}
}

func TestExtractPluginTargets_MarketplaceAdd(t *testing.T) {
	got := ExtractPluginTargets("/plugin marketplace add https://example.com/x")
	if len(got) != 1 || got[0] != "https://example.com/x" {
		t.Errorf("got %v", got)
	}
}

func TestExtractPluginTargets_None(t *testing.T) {
	if got := ExtractPluginTargets("hello world"); len(got) != 0 {
		t.Errorf("expected no targets, got %v", got)
	}
}

// ---------- Tokenizer round-trip ------------------------------

func TestTokenize_QuotedString(t *testing.T) {
	got, err := Tokenize(`npm install "foo bar"`)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := []string{"npm", "install", "foo bar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestTokenize_UnbalancedReturnsError(t *testing.T) {
	if _, err := Tokenize(`npm install "x`); err == nil {
		t.Error("expected error for unbalanced quote")
	}
}

func TestTokenize_BackslashEscape(t *testing.T) {
	got, _ := Tokenize(`echo hi\ there`)
	if len(got) != 2 || got[1] != "hi there" {
		t.Errorf("got %v", got)
	}
}

// ---------- shell-quote exported API -------------------------------

func TestShellQuote_Roundtrip(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "''"},
		{"plain", "plain"},
		{"@scope/pkg", "@scope/pkg"},
		{"with space", "'with space'"},
		{"a'b", `'a'"'"'b'`},
		{"$(evil)", `'$(evil)'`},
		{"a;b", `'a;b'`},
	}
	for _, tc := range cases {
		got := ShellQuote(tc.in)
		if got != tc.want {
			t.Errorf("ShellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
		// Round-trip property: re-tokenize matches single-element input.
		rt, err := Tokenize(got)
		if err != nil {
			t.Errorf("re-tokenize %q: %v", got, err)
			continue
		}
		if tc.in == "" {
			if len(rt) != 1 || rt[0] != "" {
				t.Errorf("empty round-trip: %v", rt)
			}
		} else if len(rt) != 1 || rt[0] != tc.in {
			t.Errorf("round-trip diverged: in=%q quoted=%q re=%v", tc.in, got, rt)
		}
	}
}

func TestIsShellSafe(t *testing.T) {
	if !IsShellSafe("foo-bar_baz.tar.gz") {
		t.Error("plain identifier rejected")
	}
	if IsShellSafe("with space") {
		t.Error("space accepted")
	}
	if IsShellSafe("$(evil)") {
		t.Error("substitution accepted")
	}
}
