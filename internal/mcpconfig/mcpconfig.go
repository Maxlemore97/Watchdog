// Package mcpconfig reads MCP server definitions from any agent host's
// config file (read-only) and flags risky ones.
//
// An MCP server is code the host launches on its own, with the user's
// privileges, and whose tool descriptions are fed straight into the
// model. The checks here are deterministic:
//
//   - unpinned package runners (`npx -y pkg`, `uvx pkg`): every launch
//     may fetch a new release, so a once-reviewed server can silently
//     turn malicious (postmark-mcp, 2025)
//   - plain-HTTP remote servers on non-loopback hosts
//   - literal credentials in env/headers committed to the config
//
// Installing what the server runs is vetted separately: Commandline()
// renders the launch command so the install parser and preflight can
// scan the package it pulls.
package mcpconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/Maxlemore97/watchdog/internal/parsers"
)

// Server is one configured MCP server.
type Server struct {
	Source  string            `json:"source"` // config file it came from
	Name    string            `json:"name"`
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	URL     string            `json:"url,omitempty"`
	Env     map[string]string `json:"-"`
	Headers map[string]string `json:"-"`
}

// Finding is one risk on one server.
type Finding struct {
	Source  string `json:"source"`
	Server  string `json:"server"`
	Verdict string `json:"verdict"` // ask | deny
	Reason  string `json:"reason"`
}

// serverKeys are the top-level keys hosts use for their server map:
// mcpServers (Claude, Cursor, Windsurf, Gemini, Cline), servers
// (VS Code), context_servers (Zed), mcp_servers (Codex), mcp
// (OpenCode).
var serverKeys = []string{"mcpServers", "servers", "context_servers", "mcp_servers", "mcp"}

// maxConfigBytes bounds reads; ~/.claude.json can grow but never this big.
const maxConfigBytes = 8 << 20

// Load parses path and returns its servers, sorted by name. Claude
// Code's ~/.claude.json also carries per-project server maps under
// projects.<dir>.mcpServers; those are included with the project dir
// in Source.
func Load(path string) ([]Server, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxConfigBytes {
		return nil, fmt.Errorf("%s: config larger than %d bytes", path, maxConfigBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := decode(path, data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	servers := serversFrom(path, cfg)
	if projects, ok := cfg["projects"].(map[string]any); ok {
		for dir, p := range projects {
			if pm, ok := p.(map[string]any); ok {
				servers = append(servers, serversFrom(path+" (project "+dir+")", pm)...)
			}
		}
	}
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Source != servers[j].Source {
			return servers[i].Source < servers[j].Source
		}
		return servers[i].Name < servers[j].Name
	})
	return servers, nil
}

func decode(path string, data []byte) (map[string]any, error) {
	var cfg map[string]any
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		if _, err := toml.Decode(string(data), &cfg); err != nil {
			return nil, err
		}
	case ".yaml", ".yml":
		var raw any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		cfg, _ = normalize(raw).(map[string]any)
	default:
		// VS Code and Zed accept JSON with comments and trailing commas.
		if err := json.Unmarshal(StripJSONC(data), &cfg); err != nil {
			return nil, err
		}
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

func serversFrom(source string, cfg map[string]any) []Server {
	var out []Server
	for _, key := range serverKeys {
		m, ok := cfg[key].(map[string]any)
		if !ok {
			continue
		}
		for name, raw := range m {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, parseEntry(source, name, entry))
		}
	}
	return out
}

func parseEntry(source, name string, e map[string]any) Server {
	s := Server{Source: source, Name: name}
	switch c := e["command"].(type) {
	case string:
		s.Command = c
	case []any: // OpenCode: command is an argv array
		for i, a := range c {
			if str, ok := a.(string); ok {
				if i == 0 {
					s.Command = str
				} else {
					s.Args = append(s.Args, str)
				}
			}
		}
	case map[string]any: // Zed: {path, args}
		s.Command, _ = c["path"].(string)
		s.Args = append(s.Args, stringList(c["args"])...)
	}
	s.Args = append(s.Args, stringList(e["args"])...)
	for _, k := range []string{"url", "serverUrl", "httpUrl"} {
		if u, ok := e[k].(string); ok && u != "" {
			s.URL = u
			break
		}
	}
	s.Env = stringMap(e["env"])
	if s.Env == nil {
		s.Env = stringMap(e["environment"])
	}
	s.Headers = stringMap(e["headers"])
	return s
}

func stringList(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, a := range list {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func stringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

// Commandline renders the launch command as a shell line for the
// install parser (`npx -y some-mcp` → npm package some-mcp).
func (s Server) Commandline() string {
	if s.Command == "" {
		return ""
	}
	return parsers.JoinShell(append([]string{s.Command}, s.Args...))
}

// literalSecretRE matches credential-shaped literals (not ${VAR}
// references): provider key prefixes or long opaque tokens.
var literalSecretRE = regexp.MustCompile(`^(Bearer\s+)?(sk-|ghp_|github_pat_|xox[bpoa]-|AKIA|glpat-|npm_)[A-Za-z0-9_\-]{8,}|^(Bearer\s+)?[A-Za-z0-9_\-]{40,}$`)

// Check returns the deterministic findings for s.
func Check(s Server) []Finding {
	var out []Finding
	add := func(verdict, reason string) {
		out = append(out, Finding{Source: s.Source, Server: s.Name, Verdict: verdict, Reason: reason})
	}
	if line := s.Commandline(); line != "" {
		pkgs, notes := parsers.CollectPackages(line, nil)
		for _, p := range pkgs {
			if p.Version == "" || p.Version == "latest" {
				add("ask", fmt.Sprintf("unpinned package %s (%s): every launch may fetch a new, unreviewed release — pin a version", p.Name, p.Ecosystem))
			}
		}
		for _, n := range notes {
			add("ask", "launch command: "+n)
		}
	}
	if s.URL != "" {
		if u, err := url.Parse(s.URL); err == nil && u.Scheme == "http" && !isLoopback(u.Hostname()) {
			add("ask", "remote server over plain HTTP: "+u.Host+" (traffic and tokens readable in transit)")
		}
	}
	for _, kv := range []map[string]string{s.Env, s.Headers} {
		keys := make([]string, 0, len(kv))
		for k := range kv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if literalSecretRE.MatchString(kv[k]) {
				add("ask", "literal credential in config ("+k+"): use an environment reference instead")
			}
		}
	}
	return out
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// StripJSONC removes // and /* */ comments and trailing commas outside
// strings, turning JSON-with-comments into JSON.
func StripJSONC(data []byte) []byte {
	var out bytes.Buffer
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out.WriteByte(c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out.WriteByte('\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			// Drop a trailing comma before } or ].
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			x[k] = normalize(val)
		}
		return x
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if ks, ok := k.(string); ok {
				out[ks] = normalize(val)
			}
		}
		return out
	case []any:
		for i := range x {
			x[i] = normalize(x[i])
		}
		return x
	}
	return v
}
