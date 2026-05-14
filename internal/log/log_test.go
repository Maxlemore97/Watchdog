package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvent_DisabledByDefault(t *testing.T) {
	t.Setenv("WATCHDOG_LOG", "")
	// Should not panic, should not create any file.
	Event("noop", map[string]any{"k": "v"})
}

func TestEvent_WritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	t.Setenv("WATCHDOG_LOG", path)

	Event("hello", map[string]any{"foo": "bar", "n": 42})
	Event("again", map[string]any{"x": "y"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), data)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 not JSON: %v (%q)", err, lines[0])
	}
	if first["event"] != "hello" || first["foo"] != "bar" {
		t.Errorf("unexpected first record: %v", first)
	}
	if _, ok := first["ts"]; !ok {
		t.Errorf("missing ts field")
	}
	if _, ok := first["pid"]; !ok {
		t.Errorf("missing pid field")
	}
}

func TestEvent_SwallowsWriteErrors(t *testing.T) {
	t.Setenv("WATCHDOG_LOG", "/nonexistent/dir/that/does/not/exist/log")
	// Must not panic or raise.
	Event("safe", nil)
}
