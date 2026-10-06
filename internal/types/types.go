// Package types holds the shared data structures passed between the
// parser, fetcher, analyzer, and adapter layers. Kept in its own
// package to avoid import cycles.
package types

// Package is an install target as detected by the install-command parser.
type Package struct {
	Ecosystem string
	Name      string
	Version   string // empty when unresolved
}

// ArtifactBundle is a curated, size-capped slice of a package or
// plugin's source files plus its metadata. Returned by fetchers,
// consumed by the analyzer.
//
// UpstreamDigest is a deterministic sha256 over the curated file
// contents as fetched (before size caps trim them). It drives
// content-addressed verdict caching: if the fetched bytes are
// unchanged, the cached verdict applies regardless of wall-clock TTL;
// if bytes differ (republished name@version, fetcher-curation change,
// an edit past the truncation point), the cache misses and the
// analyzer re-runs. Empty Files yields a constant digest, which is
// correct for short-circuited "no install hooks" bundles.
//
// TruncatedExecutable names executable surfaces (install scripts,
// hook configs, plugin bin/ and scripts/) that the size caps cut or
// dropped. The analyzer never returns `allow` for such a bundle: the
// LLM did not see the whole thing that will run.
type ArtifactBundle struct {
	Ecosystem           string
	Name                string
	Version             string
	Files               map[string]string
	Metadata            map[string]any
	Notes               []string
	UpstreamDigest      string
	TruncatedExecutable []string
}
