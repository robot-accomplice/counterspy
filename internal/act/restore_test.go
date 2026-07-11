package act

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"counterspy/internal/model"
)

// readManifest/writeManifest let tests hand-craft or mutate a manifest.json
// directly, for scenarios (malformed actions, post-quarantine tampering) that
// Quarantine itself would never produce but Restore must still handle safely.
func readManifest(t *testing.T, p string) model.Manifest {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m model.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func writeManifest(t *testing.T, p string, m model.Manifest) {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// safeDest must refuse a restore destination that is itself a protected system
// path, even though it never has to touch the filesystem to know that (§9 hard
// refusal applies to restores, not just quarantines).
func TestSafeDest_RejectsProtectedRestoreDestination(t *testing.T) {
	tmp := tmpDir(t)
	qRoot := filepath.Join(tmp, "q")
	if err := os.MkdirAll(qRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	m := model.Manifest{Items: []model.ManifestItem{{
		Subject: model.Subject{Path: "/usr/bin/evil-restore-target"},
		Actions: []model.Action{{Kind: model.ActionMove, From: "/usr/bin/evil-restore-target", To: filepath.Join(qRoot, "usr", "bin", "evil-restore-target")}},
	}}}
	manifestPath := filepath.Join(qRoot, "manifest.json")
	writeManifest(t, manifestPath, m)

	err := Restore(manifestPath)
	if err == nil {
		t.Fatal("expected Restore to refuse a protected restore destination")
	}
	if !strings.Contains(err.Error(), "protected") {
		t.Fatalf("expected a protected-path refusal, got: %v", err)
	}
}

// safeDest must allow a restore whose original parent directory no longer
// exists (e.g. it was cleaned up after quarantine) — MkdirAll recreates it
// fresh rather than the restore being refused.
func TestRestore_RecreatesRemovedParentDir(t *testing.T) {
	tmp := tmpDir(t)
	orig := filepath.Join(tmp, "gonedir", "x")
	write(t, orig, "payload")
	qRoot := filepath.Join(tmp, "q")

	if _, err := Quarantine(qRoot, "t", moveFinding(orig, "x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(tmp, "gonedir")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "gonedir")); !os.IsNotExist(err) {
		t.Fatal("parent dir should be gone before restore")
	}

	if err := Restore(filepath.Join(qRoot, "manifest.json")); err != nil {
		t.Fatalf("restore should recreate the missing parent dir, got: %v", err)
	}
	if got, err := os.ReadFile(orig); err != nil || string(got) != "payload" {
		t.Fatalf("restore into recreated dir failed: %v / %q", err, got)
	}
}

// safeDest must refuse a restore whose original parent directory has been
// replaced by a symlink since quarantine time — the same TOCTOU concern as the
// quarantine-side symlinked-parent check, but for the restore path.
func TestSafeDest_RejectsSymlinkedRestoreParent(t *testing.T) {
	tmp := tmpDir(t)
	orig := filepath.Join(tmp, "realdir", "x")
	write(t, orig, "secret")
	qRoot := filepath.Join(tmp, "q")

	if _, err := Quarantine(qRoot, "t", moveFinding(orig, "x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(tmp, "realdir")); err != nil {
		t.Fatal(err)
	}
	otherDir := filepath.Join(tmp, "otherdir")
	if err := os.MkdirAll(otherDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherDir, filepath.Join(tmp, "realdir")); err != nil {
		t.Skip("symlink unsupported")
	}

	err := Restore(filepath.Join(qRoot, "manifest.json"))
	if err == nil {
		t.Fatal("expected Restore to refuse a symlinked restore parent")
	}
	if _, statErr := os.Stat(filepath.Join(otherDir, "x")); !os.IsNotExist(statErr) {
		t.Fatal("restore must not have followed the symlink into otherdir")
	}
}

// Restore must process every manifest item even when one is unrestorable: the
// good item still comes back, and the bad one is surfaced as an aggregated
// error rather than silently dropped or aborting the whole restore.
func TestRestore_MissingQuarantinedFile_AggregatesAcrossItems(t *testing.T) {
	tmp := tmpDir(t)
	good := filepath.Join(tmp, "d", "good")
	bad := filepath.Join(tmp, "d", "bad")
	write(t, good, "keep-me")
	write(t, bad, "vanish")
	qRoot := filepath.Join(tmp, "q")

	if _, err := Quarantine(qRoot, "t", moveFinding(good, "good")); err != nil {
		t.Fatal(err)
	}
	if _, err := Quarantine(qRoot, "t", moveFinding(bad, "bad")); err != nil {
		t.Fatal(err)
	}
	// Simulate the quarantined copy of "bad" having vanished from quarantine
	// root (disk cleanup, manual tampering, etc).
	badQuarantined := filepath.Join(qRoot, strings.TrimPrefix(bad, "/"))
	if err := os.Remove(badQuarantined); err != nil {
		t.Fatal(err)
	}

	err := Restore(filepath.Join(qRoot, "manifest.json"))
	if err == nil {
		t.Fatal("expected an aggregated error for the missing quarantined file")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected a missing-quarantined-file error, got: %v", err)
	}
	if got, err := os.ReadFile(good); err != nil || string(got) != "keep-me" {
		t.Fatalf("good item must still be restored despite the bad one failing: %v / %q", err, got)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("bad item must not have been restored from a nonexistent quarantined file")
	}
}

// A hand-edited or corrupted manifest can contain a move action with no
// recorded destination. Restore must skip it defensively rather than crash or
// mis-restore, while still completing the rest of the manifest cleanly.
func TestRestore_SkipsActionWithoutDestination(t *testing.T) {
	tmp := tmpDir(t)
	orig := filepath.Join(tmp, "d", "good")
	write(t, orig, "data")
	qRoot := filepath.Join(tmp, "q")

	if _, err := Quarantine(qRoot, "t", moveFinding(orig, "good")); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(qRoot, "manifest.json")
	m := readManifest(t, manifestPath)
	m.Items = append(m.Items, model.ManifestItem{
		Subject: model.Subject{Path: "/tmp/malformed"},
		Actions: []model.Action{{Kind: model.ActionMove, From: "/tmp/malformed", To: ""}},
	})
	writeManifest(t, manifestPath, m)

	if err := Restore(manifestPath); err != nil {
		t.Fatalf("restore should skip the destination-less action, not fail: %v", err)
	}
	if got, err := os.ReadFile(orig); err != nil || string(got) != "data" {
		t.Fatalf("well-formed item must still be restored: %v / %q", err, got)
	}
}
