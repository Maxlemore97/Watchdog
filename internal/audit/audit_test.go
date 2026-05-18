package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRecord_AppendsOneJSONLineWithAutoFields(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.jsonl")
	t.Setenv("WATCHDOG_AUDIT_LOG", logPath)

	Record("integrity.deny", map[string]any{
		"tool":   "Bash",
		"reason": "tamper",
	})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("audit log is empty")
	}
	if data[len(data)-1] != '\n' {
		t.Fatal("expected trailing newline")
	}
	var rec map[string]any
	if err := json.Unmarshal(data[:len(data)-1], &rec); err != nil {
		t.Fatalf("not valid JSON: %v\nraw: %q", err, string(data))
	}
	if rec["event"] != "integrity.deny" {
		t.Errorf("event = %v", rec["event"])
	}
	if rec["tool"] != "Bash" {
		t.Errorf("tool = %v", rec["tool"])
	}
	if rec["reason"] != "tamper" {
		t.Errorf("reason = %v", rec["reason"])
	}
	if _, ok := rec["ts"]; !ok {
		t.Error("missing ts")
	}
	if _, ok := rec["pid"]; !ok {
		t.Error("missing pid")
	}
}

func TestRecord_ConcurrentAppendsAreLineAtomic(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.jsonl")
	t.Setenv("WATCHDOG_AUDIT_LOG", logPath)

	const goroutines = 16
	const perGoroutine = 50
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				Record("test", map[string]any{
					"goroutine": id,
					"iter":      j,
					// Padding to keep line size above the typical 4 KB
					// PIPE_BUF — this is where torn writes show up.
					"pad": "0123456789abcdefghijklmnopqrstuvwxyz" +
						"0123456789abcdefghijklmnopqrstuvwxyz" +
						"0123456789abcdefghijklmnopqrstuvwxyz" +
						"0123456789abcdefghijklmnopqrstuvwxyz",
				})
			}
		}(i)
	}
	wg.Wait()

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	lines := 0
	for scanner.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("torn line at row %d: %v\nraw: %q", lines, err, scanner.Text())
		}
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if lines != goroutines*perGoroutine {
		t.Errorf("got %d lines, want %d", lines, goroutines*perGoroutine)
	}
}

func TestRecord_NoCrashOnUnwritablePath(t *testing.T) {
	t.Setenv("WATCHDOG_AUDIT_LOG", "/this/path/cannot/exist/audit.jsonl")
	// Must not panic or block. Caller (hook) keeps running.
	Record("noop", nil)
}
