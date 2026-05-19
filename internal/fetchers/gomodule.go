package fetchers

import (
	"fmt"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// Go modules have no install-time exec surface — `go install` only
// compiles. Bundle stays metadata-only; the analyzer short-circuits
// to allow when there are no install-hook files, deferring source
// review to OSV + Snyk-class tools.

// FetchGoModule fetches a Go module zip from proxy.golang.org. The
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

	return &types.ArtifactBundle{
		Ecosystem: "Go",
		Name:      name,
		Version:   version,
		Files:     map[string]string{},
		Metadata:  map[string]any{"module": name, "version": version},
		Notes:     nil,
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
