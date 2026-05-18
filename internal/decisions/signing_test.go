package decisions

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWrite_ProducesSignedToken(t *testing.T) {
	withTempDir(t)
	Write("npm install lodash", "allow", "ok")

	entries, err := os.ReadDir(filepath.Join(t.TempDir(), "..", filepath.Base(t.TempDir())))
	_ = err
	_ = entries
	// Simpler: read the single token file via Read and check
	// signature is non-empty by inspecting the JSON directly.
	files, _ := os.ReadDir(Dir())
	if len(files) != 1 {
		t.Fatalf("expected 1 token file, got %d", len(files))
	}
	data, err := os.ReadFile(filepath.Join(Dir(), files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	sig, _ := raw["signature"].(string)
	if sig == "" {
		t.Errorf("token written without signature: %s", data)
	}
}

func TestRead_RejectsUnsignedToken(t *testing.T) {
	withTempDir(t)
	// Hand-write an unsigned token by emulating the v1 shape.
	cmd := "npm install lodash"
	// Use Write first to ensure the directory exists and we have the
	// right key file.
	Write("npm install other", "allow", "ok")

	// Now overwrite the path with an unsigned token at the canonical
	// key for our target command.
	key := Key(cmd)
	path := filepath.Join(Dir(), key+".json")
	unsigned := []byte(`{
  "verdict": "allow",
  "reason": "forged",
  "command": "npm install lodash",
  "written_at": "` + nowISO() + `"
}`)
	if err := os.WriteFile(path, unsigned, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Read(cmd)
	if !errors.Is(err, ErrUnsignedToken) {
		t.Errorf("Read returned %v, want ErrUnsignedToken", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Read should have removed the unsigned token")
	}
}

func TestRead_RejectsTamperedToken(t *testing.T) {
	withTempDir(t)
	Write("npm install lodash", "allow", "approved")

	// Read raw, change the verdict, write back (signature now stale).
	key := Key("npm install lodash")
	path := filepath.Join(Dir(), key+".json")
	data, _ := os.ReadFile(path)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	raw["verdict"] = "deny" // tamper
	out, _ := json.Marshal(raw)
	_ = os.WriteFile(path, out, 0o644)

	_, err := Read("npm install lodash")
	if !errors.Is(err, ErrUnsignedToken) {
		t.Errorf("expected ErrUnsignedToken for tamper, got %v", err)
	}
}

func nowISO() string {
	return "2099-01-01T00:00:00Z"
}
