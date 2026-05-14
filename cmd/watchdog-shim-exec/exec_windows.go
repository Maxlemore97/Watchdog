//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// execReal spawns the real binary as a child, wires stdio through,
// waits for completion, and exits with the child's status. Windows
// lacks an exec-in-place primitive equivalent to syscall.Exec, so the
// shim stays in memory for the duration of the install (~seconds).
func execReal(real, toolname string, args []string) int {
	_ = toolname // child receives os.Args[0]=real; toolname dispatch on Windows is rare
	cmd := exec.Command(real, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	fmt.Fprintf(os.Stderr, "watchdog-shim: failed to exec %s: %v\n", real, err)
	return 127
}
