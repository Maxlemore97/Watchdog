package parsers

import (
	"reflect"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// ParityCases captures install strings whose Python-parser output is
// the canonical truth. Each case was hand-validated against the
// reference Python implementation. Drift here = port regression.
var ParityCases = []struct {
	name  string
	cmd   string
	want  []types.Package
	notes int // count of notes; exact text validated case-by-case where it matters
}{
	{"npm-basic", "npm install lodash",
		[]types.Package{{Ecosystem: "npm", Name: "lodash"}}, 0},
	{"npm-versioned", "npm install lodash@4.17.21",
		[]types.Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}, 0},
	{"npm-scoped", "npm install @types/node@20.0.0",
		[]types.Package{{Ecosystem: "npm", Name: "@types/node", Version: "20.0.0"}}, 0},
	{"npm-multi", "npm install a b c",
		[]types.Package{
			{Ecosystem: "npm", Name: "a"},
			{Ecosystem: "npm", Name: "b"},
			{Ecosystem: "npm", Name: "c"},
		}, 0},
	{"npm-with-flag-arg", "npm install --registry https://r foo",
		[]types.Package{{Ecosystem: "npm", Name: "foo"}}, 0},
	{"npm-with-inline-flag-arg", "npm install --registry=https://r foo",
		[]types.Package{{Ecosystem: "npm", Name: "foo"}}, 0},

	{"pip-basic", "pip install requests",
		[]types.Package{{Ecosystem: "PyPI", Name: "requests"}}, 0},
	{"pip-pinned", "pip install requests==2.31.0",
		[]types.Package{{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0"}}, 0},
	{"pip-pep440-specifier", "pip install requests>=2.0",
		[]types.Package{{Ecosystem: "PyPI", Name: "requests"}}, 0},
	{"pip-requirements", "pip install -r reqs.txt", nil, 1},
	{"pip-editable", "pip install -e ./local", nil, 1},
	{"pip-url", "pip install https://example.com/x.whl", nil, 1},

	{"uv-pip", "uv pip install httpx==0.27",
		[]types.Package{{Ecosystem: "PyPI", Name: "httpx", Version: "0.27"}}, 0},
	{"uv-add", "uv add ruff",
		[]types.Package{{Ecosystem: "PyPI", Name: "ruff"}}, 0},
	{"poetry-add-version", "poetry add pydantic@2.5.0",
		[]types.Package{{Ecosystem: "PyPI", Name: "pydantic", Version: "2.5.0"}}, 0},

	{"cargo-add", "cargo add serde@1.0.0",
		[]types.Package{{Ecosystem: "crates.io", Name: "serde", Version: "1.0.0"}}, 0},
	{"cargo-install", "cargo install ripgrep",
		[]types.Package{{Ecosystem: "crates.io", Name: "ripgrep"}}, 0},

	{"gem", "gem install rake",
		[]types.Package{{Ecosystem: "RubyGems", Name: "rake"}}, 0},
	{"composer", "composer require monolog/monolog:2.9.0",
		[]types.Package{{Ecosystem: "Packagist", Name: "monolog/monolog", Version: "2.9.0"}}, 0},

	{"unknown-binary", "ls install foo", nil, 0},
	{"non-install-subcmd", "npm test", nil, 0},

	{"absolute-path-binary", "/usr/local/bin/npm install lodash",
		[]types.Package{{Ecosystem: "npm", Name: "lodash"}}, 0},
}

func TestParseInstall_Parity(t *testing.T) {
	for _, c := range ParityCases {
		t.Run(c.name, func(t *testing.T) {
			pkgs, notes := ParseInstall(c.cmd)
			if !reflect.DeepEqual(pkgs, c.want) {
				t.Errorf("packages: got %v, want %v", pkgs, c.want)
			}
			if len(notes) != c.notes {
				t.Errorf("notes: got %d (%v), want %d", len(notes), notes, c.notes)
			}
		})
	}
}

// CollectPackages chained-segment parity.
var CollectParityCases = []struct {
	name string
	cmd  string
	want []types.Package
}{
	{"chained-and",
		"npm install a && pip install b",
		[]types.Package{
			{Ecosystem: "npm", Name: "a"},
			{Ecosystem: "PyPI", Name: "b"},
		},
	},
	{"chained-semicolon",
		"npm i a; pip install b",
		[]types.Package{
			{Ecosystem: "npm", Name: "a"},
			{Ecosystem: "PyPI", Name: "b"},
		},
	},
	{"chained-or",
		"npm i a || npm i b",
		[]types.Package{
			{Ecosystem: "npm", Name: "a"},
			{Ecosystem: "npm", Name: "b"},
		},
	},
	{"subshell",
		`bash -c "npm install foo"`,
		[]types.Package{{Ecosystem: "npm", Name: "foo"}},
	},
}

func TestCollectPackages_Parity(t *testing.T) {
	for _, c := range CollectParityCases {
		t.Run(c.name, func(t *testing.T) {
			pkgs, _ := CollectPackages(c.cmd, identityResolve)
			if !reflect.DeepEqual(pkgs, c.want) {
				t.Errorf("pkgs = %v, want %v", pkgs, c.want)
			}
		})
	}
}
