// internal/feedback/config_test.go
package feedback

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_DefaultsToOff(t *testing.T) {
	c := LoadConfig(filepath.Join(t.TempDir(), "nope.json")) // missing file
	if c.Share != ShareOff || c.Detail != DetailPublic {
		t.Fatalf("missing config must default to off/public, got %+v", c)
	}
}

func TestLoadConfig_ParsesAndFailsSafe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	_ = os.WriteFile(p, []byte(`{"share":"always","detail":"full","endpoint":"https://x"}`), 0o600)
	c := LoadConfig(p)
	if c.Share != ShareAlways || c.Detail != DetailFull || c.Endpoint != "https://x" {
		t.Fatalf("bad parse: %+v", c)
	}
	// An unknown share value fails safe to off.
	_ = os.WriteFile(p, []byte(`{"share":"bogus"}`), 0o600)
	if LoadConfig(p).Share != ShareOff {
		t.Fatal("unknown share must fail safe to off")
	}
}
