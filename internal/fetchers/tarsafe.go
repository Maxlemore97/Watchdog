package fetchers

import (
	"archive/tar"
	"errors"
	"io"
	"path"
	"strings"
)

// safeTarMember accepts only regular files within an archive. Reject:
//   - symlinks / hardlinks / device nodes / fifos
//   - absolute paths
//   - paths containing `..` components
//   - empty paths
//
// This is the Go equivalent of Python's tarfile.data_filter (3.12+).
// Members that fail any check are skipped silently — the caller sees
// the curated subset without the hostile entries.
func safeTarMember(h *tar.Header) bool {
	if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
		return false
	}
	name := h.Name
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "/") {
		return false
	}
	// path.Clean normalises `./a//b` → `a/b` and leaves `..` visible.
	clean := path.Clean(name)
	if clean == "." || clean == ".." {
		return false
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// walkTar invokes fn for every safe regular-file member, passing the
// already-decoded content (truncated to MaxFileBytes*2). Members that
// fail safeTarMember or fail to decode are skipped.
//
// keyFn lets callers choose the dict key shape (e.g. strip leading
// "package/" prefix for npm, keep full path for PyPI sdists).
// predicate runs after path cleaning and lets callers keep or drop a
// member by its parts (split on "/"). When stripPackagePrefix is
// true, a leading "package" segment is removed before predicate runs
// (mirrors the Python `_extract_tar` behaviour for npm).
func walkTar(
	r io.Reader,
	stripPackagePrefix bool,
	predicate func(name string, parts []string) bool,
	keyFn func(name string, parts []string) string,
) (map[string]string, error) {
	tr := tar.NewReader(r)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, err
		}
		if !safeTarMember(h) {
			continue
		}
		parts := strings.Split(path.Clean(h.Name), "/")
		if stripPackagePrefix && len(parts) > 0 && parts[0] == "package" {
			parts = parts[1:]
		}
		if len(parts) == 0 {
			continue
		}
		if !predicate(h.Name, parts) {
			continue
		}
		buf, err := io.ReadAll(io.LimitReader(tr, int64(MaxFileBytes*2)))
		if err != nil {
			continue
		}
		key := keyFn(h.Name, parts)
		out[key] = string(buf)
	}
	return out, nil
}
