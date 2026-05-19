package projectscan

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTmp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseNpmLock(t *testing.T) {
	body := `{
  "packages": {
    "": {"name": "root"},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/@scope/foo": {"version": "1.2.3"},
    "node_modules/empty": {}
  }
}`
	pkgs, _, err := parseLockfile(writeTmp(t, "package-lock.json", body))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"lodash": "4.17.21", "@scope/foo": "1.2.3"}
	got := map[string]string{}
	for _, p := range pkgs {
		if p.Ecosystem != "npm" {
			t.Errorf("expected npm ecosystem, got %q", p.Ecosystem)
		}
		got[p.Name] = p.Version
	}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s: want %q got %q", n, v, got[n])
		}
	}
}

func TestParseCargoLock(t *testing.T) {
	body := `
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-app"
version = "0.1.0"
`
	pkgs, _, err := parseLockfile(writeTmp(t, "Cargo.lock", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("want 1 registry package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "serde" || pkgs[0].Version != "1.0.200" || pkgs[0].Ecosystem != "crates.io" {
		t.Errorf("unexpected entry: %+v", pkgs[0])
	}
}

func TestParseGemfileLock(t *testing.T) {
	body := `GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.3)
      activesupport (= 7.1.3)
    nokogiri (1.16.0)

PLATFORMS
  ruby
`
	pkgs, _, err := parseLockfile(writeTmp(t, "Gemfile.lock", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 gems, got %d: %+v", len(pkgs), pkgs)
	}
}

func TestParseComposerLock(t *testing.T) {
	body := `{
  "packages": [
    {"name": "monolog/monolog", "version": "2.9.1"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.0.0"}
  ]
}`
	pkgs, _, err := parseLockfile(writeTmp(t, "composer.lock", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 packages, got %d", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Ecosystem != "Packagist" {
			t.Errorf("ecosystem: %+v", p)
		}
	}
}

func TestParsePoetryLock(t *testing.T) {
	body := `
[[package]]
name = "requests"
version = "2.32.0"

[[package]]
name = "urllib3"
version = "2.2.0"
`
	pkgs, _, err := parseLockfile(writeTmp(t, "poetry.lock", body))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].Ecosystem != "PyPI" {
		t.Errorf("unexpected: %+v", pkgs)
	}
}

func TestParseGoMod(t *testing.T) {
	body := `module example.com/x

go 1.22

require (
	github.com/foo/bar v1.2.3
	github.com/baz/qux v0.5.0 // indirect
)

require github.com/single/dep v2.0.0
`
	pkgs, _, err := parseLockfile(writeTmp(t, "go.mod", body))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"github.com/foo/bar":    "v1.2.3",
		"github.com/single/dep": "v2.0.0",
	}
	got := map[string]string{}
	for _, p := range pkgs {
		if p.Ecosystem != "Go" {
			t.Errorf("ecosystem: %+v", p)
		}
		got[p.Name] = p.Version
	}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s: want %q got %q", n, v, got[n])
		}
	}
	if _, ok := got["github.com/baz/qux"]; ok {
		t.Error("indirect dep should have been skipped")
	}
}

func TestParseUnknown(t *testing.T) {
	pkgs, _, err := parseLockfile(writeTmp(t, "unknown.txt", "garbage"))
	if err != nil || pkgs != nil {
		t.Errorf("unknown lockfile should return (nil,nil): %+v %v", pkgs, err)
	}
}
