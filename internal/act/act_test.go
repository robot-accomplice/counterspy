package act

import (
	"os"
	"path/filepath"
	"testing"

	"counterspy/internal/model"
)

// The core safety guarantee: quarantine → restore returns byte-identical content
// to the original location.
func TestQuarantineRestore_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	origDir := filepath.Join(tmp, "orig")
	qRoot := filepath.Join(tmp, "quarantine")
	os.MkdirAll(origDir, 0o755)
	orig := filepath.Join(origDir, "beacon")
	if err := os.WriteFile(orig, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := model.Finding{
		Subject: model.Subject{Path: orig, Label: "com.evil"},
		Actions: []model.Action{{Kind: model.ActionMove, From: orig}},
	}
	item, err := Quarantine(qRoot, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orig); !os.IsNotExist(err) {
		t.Fatal("original should have moved out")
	}
	mpath, err := WriteManifest(qRoot, model.Manifest{Timestamp: "t", Items: []model.ManifestItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(mpath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(orig)
	if err != nil || string(got) != "payload" {
		t.Fatalf("restore did not return original bytes: %v / %q", err, got)
	}
}

// Hard refusal (spec §9, success criterion #5): never move a protected system path.
func TestQuarantine_RefusesProtectedSystemPath(t *testing.T) {
	f := model.Finding{
		Subject: model.Subject{Path: "/System/Library/LaunchDaemons/com.apple.x.plist"},
		Actions: []model.Action{{Kind: model.ActionMove, From: "/System/Library/LaunchDaemons/com.apple.x.plist"}},
	}
	if _, err := Quarantine(t.TempDir(), f); err == nil {
		t.Fatal("expected refusal to move a /System path, got nil error")
	}
}
