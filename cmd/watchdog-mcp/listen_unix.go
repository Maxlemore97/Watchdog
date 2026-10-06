//go:build !windows

package main

import (
	"net"
	"syscall"
)

// listenUnixPrivate creates the socket with a 0077 umask so it starts
// out owner-only. The umask is process-wide; the daemon calls this
// once at startup before serving, so no other goroutine creates files
// concurrently.
func listenUnixPrivate(path string) (net.Listener, error) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}
