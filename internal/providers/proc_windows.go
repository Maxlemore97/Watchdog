//go:build windows

package providers

import "os/exec"

// isolateProcessGroup is a no-op on Windows: exec.CommandContext's
// default Cancel kills the child, and cmd.WaitDelay bounds how long
// Wait blocks on pipes a surviving grandchild still holds.
func isolateProcessGroup(cmd *exec.Cmd) {}
