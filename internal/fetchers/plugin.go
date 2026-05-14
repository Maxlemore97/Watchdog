package fetchers

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Maxlemore97/watchdog/internal/types"
)

var pluginInterestingDirs = []string{"hooks", "commands", "skills", ".claude-plugin"}

var gitURLRE = regexp.MustCompile(`^(https://|git@|ssh://)`)

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
	tmp, err := os.MkdirTemp("", "watchdog-clone-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmp)

	notes := []string{}
	files := map[string]string{}

	args := []string{"clone", "--depth=1", "--filter=blob:none"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, "--", gitURL, tmp)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitEnv()
	if err := cmd.Run(); err != nil {
		notes = append(notes, "git clone failed: "+err.Error())
		return &types.ArtifactBundle{
			Ecosystem: "plugin",
			Name:      gitURL,
			Version:   ref,
			Files:     map[string]string{},
			Metadata:  map[string]any{},
			Notes:     notes,
		}
	}

	for _, sub := range pluginInterestingDirs {
		root := filepath.Join(tmp, sub)
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			st, err := os.Lstat(p)
			if err != nil {
				return nil
			}
			if st.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			if !st.Mode().IsRegular() {
				return nil
			}
			content, err := readSmallFile(p)
			if err != nil {
				return nil
			}
			rel, err := filepath.Rel(tmp, p)
			if err != nil {
				return nil
			}
			files[filepath.ToSlash(rel)] = content
			return nil
		})
	}

	// Root-level plugin.json — must not be a symlink.
	rootManifest := filepath.Join(tmp, "plugin.json")
	if st, err := os.Lstat(rootManifest); err == nil &&
		st.Mode().IsRegular() && st.Mode()&os.ModeSymlink == 0 {
		if content, err := readSmallFile(rootManifest); err == nil {
			files["plugin.json"] = content
		}
	}

	metadata := map[string]any{}
	for _, key := range []string{"plugin.json", ".claude-plugin/plugin.json"} {
		if content, ok := files[key]; ok {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(content), &parsed); err != nil {
				notes = append(notes, key+" not valid JSON")
			} else {
				metadata = parsed
			}
			break
		}
	}

	return &types.ArtifactBundle{
		Ecosystem: "plugin",
		Name:      gitURL,
		Version:   ref,
		Files:     fitBundle(files),
		Metadata:  metadata,
		Notes:     notes,
	}
}

// FetchPluginLocal bundles a plugin already on disk (no clone, no
// network). Symlinks are rejected at every read.
func FetchPluginLocal(name, dir string) *types.ArtifactBundle {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}
	files := map[string]string{}
	notes := []string{}

	for _, sub := range pluginInterestingDirs {
		root := filepath.Join(dir, sub)
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			lst, err := os.Lstat(p)
			if err != nil {
				return nil
			}
			if lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
				return nil
			}
			content, err := readSmallFile(p)
			if err != nil {
				return nil
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return nil
			}
			files[filepath.ToSlash(rel)] = content
			return nil
		})
	}

	for _, candidate := range []string{"plugin.json", ".claude-plugin/plugin.json"} {
		path := filepath.Join(dir, candidate)
		lst, err := os.Lstat(path)
		if err != nil || lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
			continue
		}
		if content, err := readSmallFile(path); err == nil {
			files[candidate] = content
		}
	}

	metadata := map[string]any{"local": true, "path": dir}
	for _, key := range []string{".claude-plugin/plugin.json", "plugin.json"} {
		if content, ok := files[key]; ok {
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
	return &types.ArtifactBundle{
		Ecosystem: "plugin",
		Name:      name,
		Version:   version,
		Files:     fitBundle(files),
		Metadata:  metadata,
		Notes:     notes,
	}
}

func readSmallFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, MaxFileBytes*2)
	n, err := f.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", err
	}
	return string(buf[:n]), nil
}
