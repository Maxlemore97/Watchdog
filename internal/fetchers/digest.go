package fetchers

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/Maxlemore97/watchdog/internal/types"
)

// digestBundle returns a deterministic sha256 over the curated file
// set. Keys are sorted so map-iteration order does not perturb the
// hash; each (key, value) pair is null-terminated so a key-suffix and
// the next entry's value cannot collide.
//
// This is the analyzer's content-address: identical bundle bytes →
// identical digest → cached verdict applies regardless of TTL. An
// empty map yields the sha256 of "" (a constant), which is the
// correct degenerate case for short-circuited "no install hooks"
// bundles.
func digestBundle(files map[string]string) string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(files[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// finalize stamps UpstreamDigest from the bundle's Files. Fetchers
// call this at every return site so the analyzer can content-address
// against the exact byte set the LLM would see.
func finalize(b *types.ArtifactBundle) *types.ArtifactBundle {
	if b != nil {
		b.UpstreamDigest = digestBundle(b.Files)
	}
	return b
}
