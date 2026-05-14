package ghaction

import (
	"reflect"
	"testing"
)

func TestIsPluginAsset_Rules(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{".claude-plugin/plugin.json", true},
		{"plugins/foo/.claude-plugin/plugin.json", true},
		{"hooks/pretool.py", true},
		{"plugins/foo/hooks/pretool.sh", true},
		{"commands/build.md", true},
		{"commands/build.py", false}, // wrong extension
		{"skills/secret/SKILL.md", true},
		{"skills/secret/README.md", false}, // wrong filename
		{"src/main.go", false},
		{".claude-plugin", false}, // dir entry alone, no rest
		{"hooks", false},
	}
	for _, c := range cases {
		if got := IsPluginAsset(c.path); got != c.want {
			t.Errorf("IsPluginAsset(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestPluginRootFor(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{".claude-plugin/plugin.json", ""},
		{"plugins/foo/.claude-plugin/plugin.json", "plugins/foo"},
		{"plugins/foo/hooks/x.sh", "plugins/foo"},
		{"src/main.go", ""},
	}
	for _, c := range cases {
		if got := PluginRootFor(c.path); got != c.want {
			t.Errorf("PluginRootFor(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestGroupByPlugin(t *testing.T) {
	got := GroupByPlugin([]string{
		"plugins/a/.claude-plugin/plugin.json",
		"plugins/a/hooks/x.sh",
		"plugins/b/commands/run.md",
		"src/main.go", // dropped
	})
	want := map[string][]string{
		"plugins/a": {
			"plugins/a/.claude-plugin/plugin.json",
			"plugins/a/hooks/x.sh",
		},
		"plugins/b": {"plugins/b/commands/run.md"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
