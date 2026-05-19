package fetchers

import (
	"fmt"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// Modern NuGet (PackageReference) does not execute install.ps1 /
// uninstall.ps1 at install time — those only ever ran under the
// legacy packages.config flow. Bundle stays metadata-only; the
// analyzer short-circuits when no install-hook files are present.
var nugetInterestingExt = map[string]bool{}
var nugetInterestingNames = map[string]bool{}

// FetchNuGet pulls a .nupkg (zip) from api.nuget.org's v3
// flatcontainer and curates the .nuspec manifest plus README files.
// API rules: id and version are both lowercased; the zip is named
// `<id>.<version>.nupkg`. Without an explicit version, hits the
// registration endpoint to discover the latest stable.
func FetchNuGet(name, version string) *types.ArtifactBundle {
	id := strings.ToLower(name)
	chosen := version
	if chosen == "" {
		idx := httpGetJSON(fmt.Sprintf("https://api.nuget.org/v3-flatcontainer/%s/index.json", escape(id, "")))
		if idx != nil {
			if versions, ok := idx["versions"].([]any); ok && len(versions) > 0 {
				if v, ok := versions[len(versions)-1].(string); ok {
					chosen = v
				}
			}
		}
	}
	if chosen == "" {
		return finalize(&types.ArtifactBundle{
			Ecosystem: "NuGet",
			Name:      name,
			Files:     map[string]string{},
			Metadata:  map[string]any{},
			Notes:     []string{"no resolvable version for " + name},
		})
	}

	zipURL := fmt.Sprintf("https://api.nuget.org/v3-flatcontainer/%s/%s/%s.%s.nupkg",
		escape(id, ""), escape(chosen, ""), escape(id, ""), escape(chosen, ""))
	raw := httpGet(zipURL)
	files := newOrderedFiles()
	notes := []string{}
	if raw == nil {
		notes = append(notes, "nupkg download failed")
	} else {
		extracted, order, err := readZipMembers(raw, func(memberName string) bool {
			leaf := strings.ToLower(lastSegment(memberName))
			if nugetInterestingNames[leaf] {
				return true
			}
			for ext := range nugetInterestingExt {
				if strings.HasSuffix(leaf, ext) {
					return true
				}
			}
			return false
		})
		if err != nil {
			notes = append(notes, "nupkg read failed: "+err.Error())
		}
		files.merge(extracted, order)
	}

	metaOut := map[string]any{
		"id":      id,
		"version": chosen,
	}
	return finalize(&types.ArtifactBundle{
		Ecosystem: "NuGet",
		Name:      name,
		Version:   chosen,
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	})
}
