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
// UpstreamDigest is a deterministic sha256 over the curated Files
// contents (after fitBundle, before the analyzer touches them). It
// drives content-addressed verdict caching: if the bytes the LLM
// would see are unchanged, the cached verdict applies regardless of
// wall-clock TTL; if bytes differ (republished name@version,
// fetcher-curation change), the cache misses and the analyzer
// re-runs. Empty Files yields a constant digest, which is correct
// for short-circuited "no install hooks" bundles.
type ArtifactBundle struct {
	Ecosystem      string
	Name           string
	Version        string
	Files          map[string]string
	Metadata       map[string]any
	Notes          []string
	UpstreamDigest string
}
