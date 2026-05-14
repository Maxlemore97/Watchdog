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
type ArtifactBundle struct {
	Ecosystem string
	Name      string
	Version   string
	Files     map[string]string
	Metadata  map[string]any
	Notes     []string
}
