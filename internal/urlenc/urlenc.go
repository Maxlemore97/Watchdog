// Package urlenc implements path-style URL escaping with a caller-
// supplied list of characters left unescaped. Mirrors Python's
// urllib.parse.quote(s, safe=safe) for parity with the reference
// implementation.
//
// Used by both osv and fetchers to build registry URLs that must
// preserve `@` and `/` literally (e.g. `@scope/pkg`, Packagist
// vendor/package paths) while still escaping spaces and other
// reserved characters.
package urlenc

import (
	"net/url"
	"strings"
)

// Escape returns url.PathEscape(s) with every rune in `safe`
// re-substituted to its literal form.
func Escape(s, safe string) string {
	enc := url.PathEscape(s)
	for _, r := range safe {
		old := url.PathEscape(string(r))
		if old != string(r) {
			enc = strings.ReplaceAll(enc, old, string(r))
		}
	}
	return enc
}
