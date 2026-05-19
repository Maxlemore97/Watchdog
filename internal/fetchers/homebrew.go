package fetchers

import (
	"encoding/json"
	"fmt"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// FetchHomebrew pulls formula or cask metadata from formulae.brew.sh.
// Homebrew has no source-archive registry — the LLM stage sees only
// the JSON payload (source URL, sha256, deps, caveats). Pattern
// mirrors the wheel-only PyPI path: empty/curated Files, populated
// Metadata, marker note explaining the missing archive.
//
// Tries the formula endpoint first; falls back to cask when formula
// 404s. Version is ignored — Homebrew doesn't expose historic
// versions through this API, only current.
func FetchHomebrew(name, version string) *types.ArtifactBundle {
	safe := escape(name, "")
	endpoints := []struct {
		url  string
		kind string
	}{
		{fmt.Sprintf("https://formulae.brew.sh/api/formula/%s.json", safe), "formula"},
		{fmt.Sprintf("https://formulae.brew.sh/api/cask/%s.json", safe), "cask"},
	}
	var meta map[string]any
	var kind string
	for _, ep := range endpoints {
		meta = httpGetJSON(ep.url)
		if meta != nil {
			kind = ep.kind
			break
		}
	}
	if meta == nil {
		return nil
	}

	files := newOrderedFiles()
	notes := []string{"no archive (homebrew " + kind + " metadata only)"}

	// Surface the JSON itself as a pseudo-file so the LLM can read
	// source URL, sha256, deps, caveats, install scriptlets, etc.
	if raw, err := json.MarshalIndent(meta, "", "  "); err == nil {
		files.set(kind+".json", string(raw))
	}

	chosenVersion := version
	if chosenVersion == "" {
		if versions, ok := meta["versions"].(map[string]any); ok {
			chosenVersion = asString(versions["stable"])
		}
		if chosenVersion == "" {
			chosenVersion = asString(meta["version"])
		}
	}

	metaOut := map[string]any{
		"kind":         kind,
		"version":      chosenVersion,
		"desc":         meta["desc"],
		"homepage":     meta["homepage"],
		"license":      meta["license"],
		"urls":         meta["urls"],
		"dependencies": meta["dependencies"],
		"caveats":      meta["caveats"],
	}
	return &types.ArtifactBundle{
		Ecosystem: "Homebrew",
		Name:      name,
		Version:   chosenVersion,
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	}
}
