package fetchers

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// ---------- ecosystem dispatch ------------------------------------

// Fetch dispatches by ecosystem.
func Fetch(ecosystem, name, version string) *types.ArtifactBundle {
	switch ecosystem {
	case "npm":
		return FetchNPM(name, version)
	case "PyPI":
		return FetchPyPI(name, version)
	case "crates.io":
		return FetchCrates(name, version)
	case "RubyGems":
		return FetchRubyGems(name, version)
	case "Packagist":
		return FetchPackagist(name, version)
	case "plugin":
		return FetchPluginGit(name, version)
	case "Homebrew":
		return FetchHomebrew(name, version)
	case "Go":
		return FetchGoModule(name, version)
	case "NuGet":
		return FetchNuGet(name, version)
	}
	return nil
}

// ---------- known interesting names per ecosystem ----------------

var npmInterestingNames = map[string]bool{
	"package.json": true, "readme": true, "readme.md": true,
	"index.js": true, "index.mjs": true, "index.cjs": true,
}
var npmScriptKeys = map[string]bool{
	"preinstall": true, "install": true, "postinstall": true,
	"prepare": true, "preuninstall": true,
}

var pypiInterestingNames = map[string]bool{
	"setup.py": true, "setup.cfg": true, "pyproject.toml": true,
	"readme": true, "readme.md": true, "readme.rst": true, "__init__.py": true,
}

var cargoInterestingNames = map[string]bool{
	"cargo.toml": true, "build.rs": true, "readme.md": true, "readme": true,
	"lib.rs": true, "main.rs": true,
}
var cargoScriptFiles = map[string]bool{"build.rs": true}

var gemInterestingExtNames = map[string]bool{
	"extconf.rb": true, "rakefile": true, "rakefile.rb": true,
}
var gemInterestingNames = map[string]bool{
	"readme.md": true, "readme": true, "readme.rdoc": true,
}

var composerInterestingNames = map[string]bool{
	"composer.json": true, "readme.md": true, "readme": true,
}
var composerScriptKeys = map[string]bool{
	"pre-install-cmd": true, "post-install-cmd": true,
	"pre-update-cmd": true, "post-update-cmd": true,
	"pre-autoload-dump": true, "post-autoload-dump": true,
	"pre-package-install": true, "post-package-install": true,
}

// ---------- npm ---------------------------------------------------

func FetchNPM(name, version string) *types.ArtifactBundle {
	safe := escape(name, "@/")
	var metaURL string
	if version != "" {
		metaURL = fmt.Sprintf("https://registry.npmjs.org/%s/%s", safe, escape(version, ""))
	} else {
		metaURL = fmt.Sprintf("https://registry.npmjs.org/%s/latest", safe)
	}
	meta := httpGetJSON(metaURL)
	if meta == nil {
		return nil
	}
	files := newOrderedFiles()
	notes := []string{}

	// Insert risky-script entries FIRST so they survive the bundle
	// cap even when the archive ships many large interesting files.
	if scripts, ok := meta["scripts"].(map[string]any); ok {
		risky := map[string]any{}
		for k, v := range scripts {
			if npmScriptKeys[strings.ToLower(k)] {
				risky[k] = v
			}
		}
		if len(risky) > 0 {
			data, _ := json.MarshalIndent(risky, "", "  ")
			files.set("package.json#scripts", string(data))
		}
	}

	dist, _ := meta["dist"].(map[string]any)
	tarball, _ := dist["tarball"].(string)
	if tarball != "" {
		raw := httpGet(tarball)
		if raw != nil {
			extracted, order, err := readTarGzMembers(raw, true,
				func(name string, parts []string) bool {
					leaf := strings.ToLower(parts[len(parts)-1])
					return npmInterestingNames[leaf]
				},
				func(name string, parts []string) string {
					return strings.Join(parts, "/")
				})
			if err != nil {
				notes = append(notes, "tarball read failed: "+err.Error())
			}
			files.merge(extracted, order)
		} else {
			notes = append(notes, "tarball download failed")
		}
	}

	metaOut := assembleNPMMetadata(meta, version)
	return &types.ArtifactBundle{
		Ecosystem: "npm",
		Name:      name,
		Version:   asString(metaOut["version"]),
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	}
}

// assembleNPMMetadata builds the curated metadata view from the raw
// registry response. Extracted so the assembly logic is unit-testable
// without standing up the full network fetch.
func assembleNPMMetadata(meta map[string]any, version string) map[string]any {
	return map[string]any{
		"version":             firstString(meta["version"], version),
		"author":              firstNonNil(meta["author"], meta["maintainers"]),
		"license":             meta["license"],
		"repository":          meta["repository"],
		"homepage":            meta["homepage"],
		"dependencies_count":  countDeps(meta["dependencies"]),
		"description":         meta["description"],
	}
}

// ---------- PyPI --------------------------------------------------

func FetchPyPI(name, version string) *types.ArtifactBundle {
	safe := escape(name, "")
	var url string
	if version != "" {
		url = fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", safe, escape(version, ""))
	} else {
		url = fmt.Sprintf("https://pypi.org/pypi/%s/json", safe)
	}
	meta := httpGetJSON(url)
	if meta == nil {
		return nil
	}
	info, _ := meta["info"].(map[string]any)
	urls, _ := meta["urls"].([]any)
	files := newOrderedFiles()
	notes := []string{}

	var sdistURL string
	for _, raw := range urls {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if entry["packagetype"] == "sdist" {
			sdistURL, _ = entry["url"].(string)
			break
		}
	}
	if sdistURL != "" {
		raw := httpGet(sdistURL)
		if raw != nil {
			var extracted map[string]string
			var order []string
			var err error
			if strings.HasSuffix(sdistURL, ".zip") {
				extracted, order, err = readZipMembers(raw, func(name string) bool {
					leaf := strings.ToLower(lastSegment(name))
					return pypiInterestingNames[leaf]
				})
			} else {
				extracted, order, err = readTarAnyMembers(raw, false,
					func(_ string, parts []string) bool {
						leaf := strings.ToLower(parts[len(parts)-1])
						return pypiInterestingNames[leaf]
					},
					func(name string, _ []string) string { return name })
			}
			if err != nil {
				notes = append(notes, "sdist read failed: "+err.Error())
			}
			files.merge(extracted, order)
		} else {
			notes = append(notes, "sdist download failed")
		}
	} else {
		notes = append(notes, "no sdist available (wheel-only)")
	}

	metaOut := map[string]any{
		"version":       firstString(info["version"], version),
		"author":        info["author"],
		"author_email":  info["author_email"],
		"license":       info["license"],
		"summary":       info["summary"],
		"home_page":     info["home_page"],
		"project_urls":  info["project_urls"],
	}
	return &types.ArtifactBundle{
		Ecosystem: "PyPI",
		Name:      name,
		Version:   asString(metaOut["version"]),
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	}
}

// ---------- crates.io ---------------------------------------------

func FetchCrates(name, version string) *types.ArtifactBundle {
	safe := escape(name, "")
	var meta map[string]any
	var versionInfo map[string]any
	if version != "" {
		meta = httpGetJSON(fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", safe, escape(version, "")))
		if meta != nil {
			versionInfo, _ = meta["version"].(map[string]any)
		}
	} else {
		meta = httpGetJSON(fmt.Sprintf("https://crates.io/api/v1/crates/%s", safe))
		if meta != nil {
			crate, _ := meta["crate"].(map[string]any)
			v := firstString(crate["max_stable_version"], asString(crate["newest_version"]))
			versionInfo = map[string]any{"num": v}
		}
	}
	if meta == nil {
		return nil
	}
	crateInfo, _ := meta["crate"].(map[string]any)
	chosen, _ := versionInfo["num"].(string)
	if chosen == "" {
		chosen = firstString(crateInfo["max_stable_version"], asString(crateInfo["newest_version"]))
	}

	files := newOrderedFiles()
	notes := []string{}

	if chosen != "" {
		dl := fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s/download", safe, escape(chosen, ""))
		raw := httpGet(dl)
		if raw != nil {
			extracted, order, err := readTarGzMembers(raw, false,
				func(name string, parts []string) bool {
					leaf := strings.ToLower(parts[len(parts)-1])
					isSrc := len(parts) >= 2 && parts[len(parts)-2] == "src" &&
						(leaf == "lib.rs" || leaf == "main.rs")
					return cargoInterestingNames[leaf] || isSrc
				},
				func(name string, _ []string) string { return name })
			if err != nil {
				notes = append(notes, "crate tarball read failed: "+err.Error())
			}
			files.merge(extracted, order)
		} else {
			notes = append(notes, "crate download failed")
		}
	} else {
		notes = append(notes, "no resolvable version")
	}

	hasBuild := false
	for _, p := range files.order {
		if cargoScriptFiles[strings.ToLower(path.Base(p))] {
			hasBuild = true
			break
		}
	}
	metaOut := map[string]any{
		"version":            chosen,
		"description":        crateInfo["description"],
		"homepage":           crateInfo["homepage"],
		"repository":         crateInfo["repository"],
		"documentation":      crateInfo["documentation"],
		"downloads":          crateInfo["downloads"],
		"created_at":         crateInfo["created_at"],
		"has_build_script":   hasBuild,
	}
	return &types.ArtifactBundle{
		Ecosystem: "crates.io",
		Name:      name,
		Version:   chosen,
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	}
}

// ---------- RubyGems ----------------------------------------------

func FetchRubyGems(name, version string) *types.ArtifactBundle {
	safe := escape(name, "")
	meta := httpGetJSON(fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", safe))
	if meta == nil {
		return nil
	}
	chosen := version
	if chosen == "" {
		chosen, _ = meta["version"].(string)
	}
	if chosen == "" {
		// Surface the failure mode as a bundle with notes rather than
		// nil; the analyzer renders "no resolvable version" in the
		// verdict reason instead of a generic "could not fetch".
		return &types.ArtifactBundle{
			Ecosystem: "RubyGems",
			Name:      name,
			Files:     map[string]string{},
			Metadata:  map[string]any{},
			Notes:     []string{"no resolvable version for " + name},
		}
	}
	files := newOrderedFiles()
	notes := []string{}

	gemURL := fmt.Sprintf("https://rubygems.org/downloads/%s-%s.gem", safe, escape(chosen, ""))
	raw := httpGet(gemURL)
	if raw != nil {
		// .gem = uncompressed tar containing data.tar.gz + metadata.gz
		inner, err := readGemDataTarGz(raw)
		if err != nil {
			notes = append(notes, err.Error())
		} else if inner != nil {
			extracted, order, err := readTarGzMembers(inner, false,
				func(memberName string, parts []string) bool {
					leaf := strings.ToLower(parts[len(parts)-1])
					isExt := strings.Contains("/"+memberName, "/ext/") && gemInterestingExtNames[leaf]
					isLibEntry := strings.HasSuffix(memberName, "lib/"+name+".rb")
					isGemspec := strings.HasSuffix(leaf, ".gemspec")
					return gemInterestingNames[leaf] || gemInterestingExtNames[leaf] ||
						isExt || isLibEntry || isGemspec
				},
				func(memberName string, _ []string) string { return memberName })
			if err != nil {
				notes = append(notes, "inner gem tarball failed: "+err.Error())
			}
			files.merge(extracted, order)
		}
	} else {
		notes = append(notes, "gem download failed")
	}

	hasNative := false
	for _, p := range files.order {
		if strings.Contains("/"+p, "/ext/") {
			hasNative = true
			break
		}
	}
	metaOut := map[string]any{
		"version":              chosen,
		"authors":              meta["authors"],
		"info":                 meta["info"],
		"licenses":             meta["licenses"],
		"homepage_uri":         meta["homepage_uri"],
		"source_code_uri":      meta["source_code_uri"],
		"downloads":            meta["downloads"],
		"has_native_extension": hasNative,
	}
	return &types.ArtifactBundle{
		Ecosystem: "RubyGems",
		Name:      name,
		Version:   chosen,
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	}
}

// ---------- Packagist ---------------------------------------------

func FetchPackagist(name, version string) *types.ArtifactBundle {
	safe := escape(name, "/")
	meta := httpGetJSON(fmt.Sprintf("https://repo.packagist.org/p2/%s.json", safe))
	if meta == nil {
		return nil
	}
	packages, _ := meta["packages"].(map[string]any)
	var entriesRaw any
	if v, ok := packages[name]; ok {
		entriesRaw = v
	} else {
		for _, v := range packages {
			entriesRaw = v
			break
		}
	}
	entries, _ := entriesRaw.([]any)
	if len(entries) == 0 {
		return nil
	}

	var chosen map[string]any
	if version != "" {
		for _, raw := range entries {
			e, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if v, _ := e["version"].(string); v == version {
				chosen = e
				break
			}
		}
	}
	if chosen == nil {
		for _, raw := range entries {
			e, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			v, _ := e["version"].(string)
			if v != "" && !strings.HasPrefix(v, "dev-") {
				chosen = e
				break
			}
		}
	}
	if chosen == nil {
		if e, ok := entries[0].(map[string]any); ok {
			chosen = e
		}
	}
	if chosen == nil {
		return nil
	}

	chosenVersion, _ := chosen["version"].(string)
	dist, _ := chosen["dist"].(map[string]any)
	distURL, _ := dist["url"].(string)

	files := newOrderedFiles()
	notes := []string{}

	// Risky scripts FIRST so they survive the bundle cap.
	hasInstallScripts := false
	if scripts, ok := chosen["scripts"].(map[string]any); ok {
		risky := map[string]any{}
		for k, v := range scripts {
			if composerScriptKeys[k] {
				risky[k] = v
			}
		}
		if len(risky) > 0 {
			data, _ := json.MarshalIndent(risky, "", "  ")
			files.set("composer.json#scripts", string(data))
			hasInstallScripts = true
		}
	}

	if distURL != "" {
		raw := httpGet(distURL)
		if raw != nil {
			extracted, order, err := readZipMembers(raw, func(memberName string) bool {
				return composerInterestingNames[strings.ToLower(lastSegment(memberName))]
			})
			if err != nil {
				notes = append(notes, "zip read failed: "+err.Error())
			}
			files.merge(extracted, order)
		} else {
			notes = append(notes, "zip download failed")
		}
	} else {
		notes = append(notes, "no dist url")
	}

	metaOut := map[string]any{
		"version":             chosenVersion,
		"type":                chosen["type"],
		"description":         chosen["description"],
		"authors":             chosen["authors"],
		"license":             chosen["license"],
		"require":             chosen["require"],
		"has_install_scripts": hasInstallScripts,
	}
	return &types.ArtifactBundle{
		Ecosystem: "Packagist",
		Name:      name,
		Version:   chosenVersion,
		Files:     fitBundle(files),
		Metadata:  metaOut,
		Notes:     notes,
	}
}

// ---------- archive readers ---------------------------------------

func readTarGzMembers(raw []byte, stripPackagePrefix bool,
	predicate func(name string, parts []string) bool,
	keyFn func(name string, parts []string) string,
) (map[string]string, []string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()
	return walkTar(gz, stripPackagePrefix, predicate, keyFn)
}

func readTarAnyMembers(raw []byte, stripPackagePrefix bool,
	predicate func(name string, parts []string) bool,
	keyFn func(name string, parts []string) string,
) (map[string]string, []string, error) {
	// Try gzip first; on failure assume uncompressed tar.
	if gz, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
		defer gz.Close()
		return walkTar(gz, stripPackagePrefix, predicate, keyFn)
	}
	return walkTar(bytes.NewReader(raw), stripPackagePrefix, predicate, keyFn)
}

func readGemDataTarGz(raw []byte) ([]byte, error) {
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("gem missing data.tar.gz")
		}
		if err != nil {
			return nil, fmt.Errorf("outer gem read failed: %w", err)
		}
		if h.Name == "data.tar.gz" {
			data, err := io.ReadAll(io.LimitReader(tr, int64(MaxDownloadBytes)))
			if err != nil {
				return nil, fmt.Errorf("could not read data.tar.gz: %w", err)
			}
			return data, nil
		}
	}
}

func readZipMembers(raw []byte, predicate func(name string) bool) (map[string]string, []string, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, nil, err
	}
	out := map[string]string{}
	var order []string
	for _, f := range zr.File {
		if !predicate(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		buf, err := io.ReadAll(io.LimitReader(rc, int64(MaxFileBytes*2)))
		rc.Close()
		if err != nil {
			continue
		}
		if _, exists := out[f.Name]; !exists {
			order = append(order, f.Name)
		}
		out[f.Name] = string(buf)
	}
	return out, order, nil
}

// ---------- helpers ----------------------------------------------

func firstString(values ...any) string {
	for _, v := range values {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func firstNonNil(values ...any) any {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func countDeps(v any) int {
	deps, ok := v.(map[string]any)
	if !ok {
		return 0
	}
	return len(deps)
}

func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i != -1 {
		return s[i+1:]
	}
	return s
}
