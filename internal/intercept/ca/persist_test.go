package ca

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrCreate_RoundTrips: first call mints + persists; second call loads the SAME CA (same cert
// PEM) so trust installed once is reused across runs.
func TestLoadOrCreate_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	c1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, keyFile)); err != nil {
		t.Fatalf("key not persisted: %v", err)
	}
	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1.CertPEM()) != string(c2.CertPEM()) {
		t.Fatal("second LoadOrCreate must reuse the persisted CA, not mint a new one")
	}
}

// TestLoadOrCreate_PartialIsFatal: a cert present but key missing must fail loud (Rule 13) rather than
// silently regenerate; a silent regen would orphan the already-trusted root in the keychain.
func TestLoadOrCreate_PartialIsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, certFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("a half-present CA pair must be a hard error, not a silent regen")
	}
}
