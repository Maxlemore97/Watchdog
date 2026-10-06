//go:build !windows

package providers

import (
	"os/exec"
	"syscall"
)

// isolateProcessGroup starts the provider in its own process group
// and makes context cancellation kill the whole group. LLM CLIs
// (node-based `claude`, `gemini`) spawn helpers; killing only the
// direct child leaves grandchildren holding the output pipes, so
// Wait — and the hook — would hang past the timeout.
func isolateProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid signals the whole group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
