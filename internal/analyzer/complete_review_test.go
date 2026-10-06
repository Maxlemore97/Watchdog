package analyzer

import (
	"strings"
	"testing"

	"github.com/Maxlemore97/watchdog/internal/types"
)

func TestRequireCompleteReview(t *testing.T) {
	truncated := &types.ArtifactBundle{TruncatedExecutable: []string{"hooks/run.sh"}}
	complete := &types.ArtifactBundle{}

	got := requireCompleteReview(truncated, map[string]any{"verdict": "allow", "reason": "looks fine"})
	if got["verdict"] != "ask" {
		t.Errorf("allow on truncated executable = %v, want ask", got["verdict"])
	}
	if r, _ := got["reason"].(string); !strings.Contains(r, "hooks/run.sh") {
		t.Errorf("reason should name the truncated surface: %q", r)
	}

	in := map[string]any{"verdict": "allow"}
	_ = requireCompleteReview(truncated, in)
	if in["verdict"] != "allow" {
		t.Error("input map mutated; cached verdict objects must stay intact")
	}

	for _, v := range []string{"deny", "ask"} {
		if got := requireCompleteReview(truncated, map[string]any{"verdict": v}); got["verdict"] != v {
			t.Errorf("%s changed to %v", v, got["verdict"])
		}
	}
	if got := requireCompleteReview(complete, map[string]any{"verdict": "allow"}); got["verdict"] != "allow" {
		t.Errorf("complete bundle allow changed to %v", got["verdict"])
	}
	if got := requireCompleteReview(nil, map[string]any{"verdict": "allow"}); got["verdict"] != "allow" {
		t.Errorf("nil bundle allow changed to %v", got["verdict"])
	}
}
