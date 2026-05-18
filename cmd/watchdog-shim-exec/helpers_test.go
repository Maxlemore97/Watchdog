//go:build !windows

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newCleanOSVServer returns a test server that always replies with
// an empty vulns list — the OSV-clean case.
func newCleanOSVServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
}

// newClosedServer spins up a listener, immediately closes it, and
// returns the URL. Any request hits "connection refused" — the
// fail-closed path.
func newClosedServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}
