package parsers

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// identityResolve keeps tests pure (no network).
func identityResolve(p types.Package) types.Package { return p }

// Basic positive cases (npm/pip/cargo/gem/composer/uv/poetry plain
// install lines) live in parity_test.go's table. Tests below cover
// shapes the parity table doesn't: scoped-no-version, pnpm/yarn,
// note text contents, malformed shell, url/path notes, specifier
// strip.

// ---------- ParseInstall — npm/pnpm/yarn -------------------------

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

// ---------- guards: malformed shell ----------------------------

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

// TestCollectPackages_DepthCap pins the recursion guard: subshell
// nesting beyond depth 3 must not parse further packages. A hostile
// install could otherwise wrap an install N levels deep to dodge
// detection or burn CPU.
func TestCollectPackages_DepthCap(t *testing.T) {
	// 5 levels deep — install hides at level 5. Depth cap = 3 means
	// we should NOT see it. (Walk starts at depth 0; the install is
	// reachable only via four ExtractSubshells calls from the root.)
	deep := `bash -c 'bash -c "bash -c \"bash -c \\\"bash -c '\''npm install pwned'\'' \\\"\" "'`
	pkgs, _ := CollectPackages(deep, identityResolve)
	for _, p := range pkgs {
		if p.Name == "pwned" {
			t.Errorf("depth cap leaked: parsed pkg %q from level >3", p.Name)
		}
	}
}

// TestSplitOnOperators_NaiveFallbackOnMalformed pins the fail-closed
// behavior on unbalanced quotes. tokenizeWithOps returns an error,
// SplitOnOperators falls back to a naive `&& || ;` split. The
// segment must still surface so the top-level parser can emit an
// "ask" rather than silently dropping the command.
func TestSplitOnOperators_NaiveFallbackOnMalformed(t *testing.T) {
	// Unbalanced single quote → tokenizeWithOps errors out, naive
	// split takes over. We just need at least one non-empty segment.
	got := SplitOnOperators(`pip install 'unterminated && npm install foo`)
	if len(got) == 0 {
		t.Fatalf("naive fallback produced no segments")
	}
}

// TestCollectPackages_MalformedShellYieldsNotes ensures malformed
// shell (unbalanced quote) reaches ParseInstall which emits a
// "malformed shell command" note. Preflight then returns "ask"
// rather than fail-open "allow".
func TestCollectPackages_MalformedShellYieldsNotes(t *testing.T) {
	_, notes := CollectPackages(`npm install "unterminated`, identityResolve)
	found := false
	for _, n := range notes {
		if strings.Contains(n, "malformed shell") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected malformed-shell note, got %v", notes)
	}
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
