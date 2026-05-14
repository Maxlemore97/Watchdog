//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// execReal replaces this process with real via syscall.Exec, so the
// real binary receives argv[0]=toolname (matters for tools that
// dispatch on argv[0] like busybox-style binaries).
func execReal(real, toolname string, args []string) int {
	argv := append([]string{toolname}, args...)
	if err := syscall.Exec(real, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog-shim: failed to exec %s: %v\n", real, err)
		return 127
	}
	return 0 // unreachable on success
}
