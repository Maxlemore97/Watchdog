//go:build windows

package main

import "net"

// listenUnixPrivate: Windows has no umask; AF_UNIX sockets inherit the
// parent directory's ACL, which MkdirAll created under the user
// profile.
func listenUnixPrivate(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}
