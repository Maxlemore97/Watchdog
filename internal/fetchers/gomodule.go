package fetchers

import (
	"fmt"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/types"
)

var goModuleInterestingNames = map[string]bool{
	"go.mod": true, "go.sum": true,
	"readme.md": true, "readme": true,
}

// FetchGoModule fetches a Go module zip from proxy.golang.org and
// curates `go.mod`, top-level `*.go` files, and any READMEs. The
// proxy spec requires escaping uppercase runes as `!` + lowercase
// (e.g. `github.com/Foo/Bar` → `github.com/!foo/!bar`) and applies
// to both the module path and the version.
func FetchGoModule(name, version string) *types.ArtifactBundle {
	if version == "" {
		version = "latest"
	}
	// Resolve `latest` via the @latest info endpoint.
	if version == "latest" {
		info := httpGetJSON(fmt.Sprintf("https://proxy.golang.org/%s/@latest", goProxyEscape(name)))
		if info != nil {
			if v, _ := info["Version"].(string); v != "" {
				version = v
			}
		}
		if version == "latest" {
			return &types.ArtifactBundle{
				Ecosystem: "Go",
				Name:      name,
				Files:     map[string]string{},
				Metadata:  map[string]any{},
				Notes:     []string{"could not resolve @latest for " + name},
			}
		}
	}

	zipURL := fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.zip",
		goProxyEscape(name), goProxyEscape(version))
	raw := httpGet(zipURL)
	if raw == nil {
		return nil
	}
	extracted, order, err := readZipMembers(raw, func(memberName string) bool {
		// Zip entries are prefixed with `<module>@<version>/`. Inspect
		// the path after that prefix.
		idx := strings.Index(memberName, "/")
		if idx < 0 {
			return false
		}
		rel := memberName[idx+1:]
		leaf := strings.ToLower(lastSegment(rel))
		if goModuleInterestingNames[leaf] {
			return true
		}
		// Top-level .go files (no `/` after stripping prefix).
		if !strings.Contains(rel, "/") && strings.HasSuffix(leaf, ".go") {
			return true
		}
		return false
	})
	files := newOrderedFiles()
	notes := []string{}
	if err != nil {
		notes = append(notes, "module zip read failed: "+err.Error())
	}
	files.merge(extracted, order)

	metaOut := map[string]any{
		"module":  name,
		"version": version,
	}
	return &types.ArtifactBundle{
		Ecosystem: "Go",
		Name:      name,
		Version:   version,
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	}
}

// goProxyEscape converts uppercase ASCII letters to `!<lower>` per
// https://go.dev/ref/mod#module-proxy. Other characters pass through
// unchanged; the path is already URL-safe.
func goProxyEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r - 'A' + 'a')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
