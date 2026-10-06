package fetchers

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// pluginInterestingDirs are walked recursively. Executable surfaces
// come first so they win the bundle-cap ordering tie-break; markdown
// surfaces (commands, agents, skills, output styles) follow.
var pluginInterestingDirs = []string{
	".claude-plugin", "hooks", "bin", "scripts", "monitors",
	"commands", "agents", "skills", "output-styles",
}

// pluginRootFiles are single files at the plugin root that Claude Code
// (or the agent) loads: MCP and LSP server definitions run commands,
// settings can register hooks, CLAUDE.md/AGENTS.md steer the agent.
var pluginRootFiles = []string{
	"plugin.json", ".mcp.json", ".lsp.json", "settings.json", "hooks.json",
	"CLAUDE.md", "AGENTS.md",
}

// pluginRootRefRE finds files a hook/MCP config points at via
// ${CLAUDE_PLUGIN_ROOT}/path — e.g. a harmless-looking hooks.json
// whose command is `${CLAUDE_PLUGIN_ROOT}/lib/payload.sh`.
var pluginRootRefRE = regexp.MustCompile(`\$\{?CLAUDE_PLUGIN_ROOT\}?[/\\]([A-Za-z0-9._\-/\\]+)`)

// collectPluginFiles curates a plugin directory into an ordered file
// set: the interesting dirs, root files, and any file referenced via
// ${CLAUDE_PLUGIN_ROOT}. Symlinks, non-regular files and paths that
// escape root are skipped.
func collectPluginFiles(root string) *orderedFiles {
	files := newOrderedFiles()
	// add stores p and returns its bundle key ("" when skipped).
	add := func(p string) string {
		lst, err := os.Lstat(p)
		if err != nil || lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
			return ""
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ""
		}
		key := filepath.ToSlash(rel)
		if _, seen := files.data[key]; seen {
			return key
		}
		content, err := readSmallFile(p)
		if err != nil {
			return ""
		}
		files.set(key, content)
		return key
	}
	for _, sub := range pluginInterestingDirs {
		dir := filepath.Join(root, sub)
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			_ = add(p)
			return nil
		})
	}
	for _, name := range pluginRootFiles {
		_ = add(filepath.Join(root, name))
	}
	// Resolve ${CLAUDE_PLUGIN_ROOT} references transitively: files
	// added here are appended to files.order and scanned in turn.
	// Bounded so a reference cycle or a huge tree cannot spin.
	for i := 0; i < len(files.order) && i < 512; i++ {
		for _, m := range pluginRootRefRE.FindAllStringSubmatch(files.data[files.order[i]], -1) {
			ref := filepath.Clean(filepath.FromSlash(strings.ReplaceAll(m[1], "\\", "/")))
			if key := add(filepath.Join(root, ref)); key != "" && files.tier(files.order[i]) == tierAutoExec {
				// Referenced from a hook/MCP/bin surface → runs
				// automatically too.
				files.autoExec[key] = true
			}
		}
	}
	return files
}

var gitURLRE = regexp.MustCompile(`^(https://|git@|ssh://)`)

// safeGitArg rejects strings that could be reinterpreted as git/ssh
// options when passed positionally. Defense in depth against
// historical CVE-2017-1000117-class attacks (`ssh://-oProxyCommand=…`,
// `--upload-pack=…` smuggled through a URL or branch ref).
//
// Modern git itself rejects these patterns; we still validate before
// invocation so a future regression in git can't reach the
// subprocess.
func safeGitArg(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "-") {
		return false
	}
	// URL host component check: ssh://host/path or https://host/path.
	// If the host starts with '-', reject (ssh interprets it as option).
	for _, scheme := range []string{"https://", "ssh://"} {
		if strings.HasPrefix(s, scheme) {
			rest := s[len(scheme):]
			if strings.HasPrefix(rest, "-") {
				return false
			}
		}
	}
	// scp-like syntax: user@host:path. Host portion likewise must not
	// start with '-'.
	if strings.HasPrefix(s, "git@") {
		rest := s[len("git@"):]
		if strings.HasPrefix(rest, "-") {
			return false
		}
	}
	return true
}

func gitEnv() []string {
	env := os.Environ()
	env = append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/true",
		"GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new",
	)
	return env
}

// FetchPluginGit clones a public plugin repo into a tempdir and
// curates files from `hooks`, `commands`, `skills`, and
// `.claude-plugin`. Symlinks and out-of-tree files are rejected.
func FetchPluginGit(gitURL, ref string) *types.ArtifactBundle {
	if !gitURLRE.MatchString(gitURL) {
		return nil
	}
	if !safeGitArg(gitURL) {
		return nil
	}
	if ref != "" && !safeGitArg(ref) {
		return nil
	}
	tmp, err := os.MkdirTemp("", "watchdog-clone-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)

	notes := []string{}

	args := []string{"clone", "--depth=1", "--filter=blob:none"}
	if ref != "" {
		// `--branch=ref` (not `--branch ref`) forces git to treat ref
		// as the option value, never as a follow-on option.
		args = append(args, "--branch="+ref)
	}
	args = append(args, "--", gitURL, tmp)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitEnv()
	if err := cmd.Run(); err != nil {
		notes = append(notes, "git clone failed: "+err.Error())
		return finalize(&types.ArtifactBundle{
			Ecosystem: "plugin",
			Name:      gitURL,
			Version:   ref,
			Files:     map[string]string{},
			Metadata:  map[string]any{},
			Notes:     notes,
		})
	}

	files := collectPluginFiles(tmp)

	metadata := map[string]any{}
	for _, key := range []string{"plugin.json", ".claude-plugin/plugin.json"} {
		if content, ok := files.data[key]; ok {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(content), &parsed); err != nil {
				notes = append(notes, key+" not valid JSON")
			} else {
				metadata = parsed
			}
			break
		}
	}

	return finalizeFrom(files, &types.ArtifactBundle{
		Ecosystem: "plugin",
		Name:      gitURL,
		Version:   ref,
		Metadata:  metadata,
		Notes:     notes,
	})
}

// FetchPluginLocal bundles a plugin already on disk (no clone, no
// network). Symlinks are rejected at every read.
func FetchPluginLocal(name, dir string) *types.ArtifactBundle {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}
	notes := []string{}
	files := collectPluginFiles(dir)

	metadata := map[string]any{"local": true, "path": dir}
	for _, key := range []string{".claude-plugin/plugin.json", "plugin.json"} {
		if content, ok := files.data[key]; ok {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(content), &parsed); err == nil {
				for k, v := range parsed {
					metadata[k] = v
				}
				break
			}
			notes = append(notes, key+" not valid JSON")
		}
	}
	version := ""
	if v, ok := metadata["version"].(string); ok {
		version = v
	}
	return finalizeFrom(files, &types.ArtifactBundle{
		Ecosystem: "plugin",
		Name:      name,
		Version:   version,
		Metadata:  metadata,
		Notes:     notes,
	})
}

func readSmallFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, int64(MaxFileBytes*2)))
	if err != nil {
		return "", err
	}
	return string(buf), nil
}
