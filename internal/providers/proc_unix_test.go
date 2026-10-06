//go:build !windows

package providers

import (
	"context"
	"testing"
	"time"
)

// A provider whose grandchild keeps stdout open must not hold the
// hook past its timeout: the whole process group is killed and Wait
// gives up on the pipes after waitDelay.
func TestRunCmd_TimeoutKillsProcessGroup(t *testing.T) {
	orig := waitDelay
	waitDelay = 500 * time.Millisecond
	t.Cleanup(func() { waitDelay = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := runCmd(ctx, "sh", []string{"-c", "sleep 30 & sleep 30"}, "")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error from the timed-out provider")
	}
	if elapsed > 5*time.Second {
		t.Errorf("runCmd returned after %v; grandchild kept it alive", elapsed)
	}
}
