package mcpconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_HostFormats(t *testing.T) {
	cases := []struct {
		name, file, body string
		want             map[string]string // server → commandline
	}{
		{"claude/cursor mcpServers", ".mcp.json",
			`{"mcpServers":{"gh":{"command":"npx","args":["-y","@modelcontextprotocol/server-github@1.2.3"]}}}`,
			map[string]string{"gh": "npx -y @modelcontextprotocol/server-github@1.2.3"}},
		{"vscode servers with comments", "mcp.json", `{
  // VS Code allows comments
  "servers": {
    "fs": {"type": "stdio", "command": "npx", "args": ["-y", "fs-mcp"], },  /* trailing comma */
    "url-with-slashes": {"type": "http", "url": "https://example.com//x"}
  }
}`, map[string]string{"fs": "npx -y fs-mcp", "url-with-slashes": ""}},
		{"zed context_servers", "settings.json",
			`{"context_servers":{"z":{"source":"custom","command":{"path":"uvx","args":["zed-mcp"]}}}}`,
			map[string]string{"z": "uvx zed-mcp"}},
		{"codex toml", "config.toml", "model = \"x\"\n\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"-y\", \"docs-mcp@2.0.0\"]\n",
			map[string]string{"docs": "npx -y docs-mcp@2.0.0"}},
		{"opencode argv", "opencode.json",
			`{"mcp":{"o":{"type":"local","command":["bunx","oc-mcp"]}}}`,
			map[string]string{"o": "bunx oc-mcp"}},
		{"continue yaml", "config.yaml", "mcpServers:\n  y:\n    command: uvx\n    args: [\"y-mcp==1.0\"]\n",
			map[string]string{"y": "uvx y-mcp==1.0"}},
	}
	for _, tc := range cases {
		servers, err := Load(write(t, tc.file, tc.body))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		got := map[string]string{}
		for _, s := range servers {
			got[s.Name] = s.Commandline()
		}
		for name, want := range tc.want {
			if got[name] != want {
				t.Errorf("%s: server %q commandline %q, want %q (all=%v)", tc.name, name, got[name], want, got)
			}
		}
	}
}

func TestLoad_ClaudeJSONProjects(t *testing.T) {
	p := write(t, ".claude.json", `{"mcpServers":{"g":{"command":"uvx","args":["g@1.0"]}},
	  "projects":{"/work/app":{"mcpServers":{"p":{"command":"npx","args":["-y","p-mcp"]}}}}}`)
	servers, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("want global + project server, got %v", servers)
	}
	var proj Server
	for _, s := range servers {
		if s.Name == "p" {
			proj = s
		}
	}
	if !strings.Contains(proj.Source, "/work/app") {
		t.Errorf("project server source %q should name the project", proj.Source)
	}
}

func TestCheck(t *testing.T) {
	cases := []struct {
		name   string
		s      Server
		reason string // "" = no findings
	}{
		{"pinned npx", Server{Name: "a", Command: "npx", Args: []string{"-y", "pkg@1.2.3"}}, ""},
		{"pinned uvx", Server{Name: "a", Command: "uvx", Args: []string{"pkg==1.2.3"}}, ""},
		{"local binary", Server{Name: "a", Command: "/usr/local/bin/my-mcp"}, ""},
		{"unpinned npx", Server{Name: "a", Command: "npx", Args: []string{"-y", "postmark-mcp"}}, "unpinned package postmark-mcp"},
		{"npx latest", Server{Name: "a", Command: "npx", Args: []string{"-y", "pkg@latest"}}, "unpinned"},
		{"unpinned uvx", Server{Name: "a", Command: "uvx", Args: []string{"mcp-server-fetch"}}, "unpinned"},
		{"plain http remote", Server{Name: "a", URL: "http://mcp.example.com/sse"}, "plain HTTP"},
		{"http loopback ok", Server{Name: "a", URL: "http://127.0.0.1:3000/mcp"}, ""},
		{"literal token", Server{Name: "a", URL: "https://x", Headers: map[string]string{"Authorization": "Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}, "literal credential"},
		{"env reference ok", Server{Name: "a", URL: "https://x", Env: map[string]string{"TOKEN": "${GITHUB_TOKEN}"}}, ""},
	}
	for _, tc := range cases {
		got := Check(tc.s)
		if tc.reason == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected findings %v", tc.name, got)
			}
			continue
		}
		found := false
		for _, f := range got {
			if strings.Contains(f.Reason, tc.reason) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: findings %v lack %q", tc.name, got, tc.reason)
		}
	}
}

func TestStripJSONC_KeepsStrings(t *testing.T) {
	in := `{"a": "http://x//y", /* c */ "b": "/* not a comment */", "c": [1,2,], // tail
}`
	out := string(StripJSONC([]byte(in)))
	for _, want := range []string{`"http://x//y"`, `"/* not a comment */"`, `[1,2]`} {
		if !strings.Contains(out, want) {
			t.Errorf("StripJSONC lost %s: %s", want, out)
		}
	}
}
