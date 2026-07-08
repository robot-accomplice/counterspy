package act

import (
	"os"
	"path/filepath"
	"testing"

	"counterspy/internal/model"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func moveFinding(path, label string) model.Assessment {
	return model.Assessment{Finding: model.Finding{
		Subject: model.Subject{Path: path, Label: label},
		Actions: []model.Action{{Kind: model.ActionMove, From: path}},
	}}
}

// Core guarantee (§9/#4): quarantine → restore is byte-identical.
func TestQuarantineRestore_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	orig := filepath.Join(tmp, "orig", "beacon")
	write(t, orig, "payload")
	qRoot := filepath.Join(tmp, "q")

	if _, err := Quarantine(qRoot, "2026-07-08T00:00:00Z", moveFinding(orig, "com.evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orig); !os.IsNotExist(err) {
		t.Fatal("original should have moved out")
	}
	if err := Restore(filepath.Join(qRoot, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(orig); err != nil || string(got) != "payload" {
		t.Fatalf("restore not byte-identical: %v / %q", err, got)
	}
}

// cp-11 F-1/F-2a: two subjects sharing a basename must both survive quarantine.
func TestQuarantine_NoBasenameClobber(t *testing.T) {
	tmp := t.TempDir()
	qRoot := filepath.Join(tmp, "q")
	a := filepath.Join(tmp, "dirA", "config.plist")
	b := filepath.Join(tmp, "dirB", "config.plist")
	write(t, a, "AAA")
	write(t, b, "BBB")

	if _, err := Quarantine(qRoot, "t", moveFinding(a, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := Quarantine(qRoot, "t", moveFinding(b, "b")); err != nil {
		t.Fatal(err)
	}
	if err := Restore(filepath.Join(qRoot, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(a)
	cb, _ := os.ReadFile(b)
	if string(ca) != "AAA" || string(cb) != "BBB" {
		t.Fatalf("basename collision lost data: a=%q b=%q", ca, cb)
	}
}

// cp-11 F-2b: restore must not overwrite a file that reappeared at the original path.
func TestRestore_RefusesOccupiedDestination(t *testing.T) {
	tmp := t.TempDir()
	qRoot := filepath.Join(tmp, "q")
	orig := filepath.Join(tmp, "d", "x")
	write(t, orig, "original")
	if _, err := Quarantine(qRoot, "t", moveFinding(orig, "x")); err != nil {
		t.Fatal(err)
	}
	write(t, orig, "REAPPEARED") // e.g. malware respawned, or user recreated it

	if err := Restore(filepath.Join(qRoot, "manifest.json")); err == nil {
		t.Fatal("restore should refuse to clobber an occupied destination")
	}
	if got, _ := os.ReadFile(orig); string(got) != "REAPPEARED" {
		t.Fatalf("restore clobbered the reappeared file: %q", got)
	}
}

// cp-11 F-1(Audit) / §9 second refusal clause: never quarantine an allowlisted subject.
func TestQuarantine_RefusesAllowlisted(t *testing.T) {
	tmp := t.TempDir()
	orig := filepath.Join(tmp, "app", "bin")
	write(t, orig, "apple")
	f := model.Finding{
		Subject: model.Subject{Path: orig},
		Evidence: []model.Evidence{{Kind: model.KindCodesign,
			Facts: map[string]string{"authority": "Software Signing"}}},
		Actions: []model.Action{{Kind: model.ActionMove, From: orig}},
	}
	if _, err := Quarantine(filepath.Join(tmp, "q"), "t", model.Assessment{Finding: f}); err == nil {
		t.Fatal("must refuse to quarantine an Apple-allowlisted subject")
	}
	if _, err := os.Stat(orig); err != nil {
		t.Fatal("allowlisted file must not have been moved")
	}
}

// Hard refusal (§9/#5): protected system paths, including via case / traversal.
func TestQuarantine_RefusesProtectedPaths(t *testing.T) {
	for _, p := range []string{
		"/System/Library/LaunchDaemons/com.apple.x.plist",
		"/system/library/x",        // macOS case-insensitive FS
		"/Users/me/../../System/x", // .. traversal resolved by Clean
	} {
		f := model.Finding{Subject: model.Subject{Path: p}, Actions: []model.Action{{Kind: model.ActionMove, From: p}}}
		if _, err := Quarantine(t.TempDir(), "t", model.Assessment{Finding: f}); err == nil {
			t.Errorf("expected refusal for %q", p)
		}
	}
}

// ABORT C1: refuse to move a symlink (closes the stat→rename TOCTOU).
func TestQuarantine_RefusesSymlink(t *testing.T) {
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real")
	write(t, real, "x")
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink unsupported")
	}
	f := model.Finding{Subject: model.Subject{Path: link}, Actions: []model.Action{{Kind: model.ActionMove, From: link}}}
	if _, err := Quarantine(filepath.Join(tmp, "q"), "t", model.Assessment{Finding: f}); err == nil {
		t.Fatal("must refuse to move a symlink (possible TOCTOU)")
	}
}

// ABORT C2: restoring a booted-out item re-registers it with launchd (not just files back).
func TestRestore_RebootstrapsBootedOutJob(t *testing.T) {
	tmp := t.TempDir()
	qRoot := filepath.Join(tmp, "q")
	plist := filepath.Join(tmp, "Library", "LaunchAgents", "com.evil.plist")
	write(t, plist, "<plist/>")
	f := model.Finding{Subject: model.Subject{Label: "com.evil"}, Actions: []model.Action{
		{Kind: model.ActionBootout, From: "gui/501/com.evil"},
		{Kind: model.ActionMove, From: plist},
	}}
	if _, err := Quarantine(qRoot, "t", model.Assessment{Finding: f}); err != nil {
		t.Fatal(err)
	}
	var called []string
	old := rebootstrap
	defer func() { rebootstrap = old }()
	rebootstrap = func(pl string) { called = append(called, pl) }
	if err := Restore(filepath.Join(qRoot, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if len(called) != 1 || called[0] != plist {
		t.Fatalf("restore should re-bootstrap the restored plist, got %v", called)
	}
}

// cp-11 F-3(Audit): a partial quarantine still writes a manifest so completed moves restore.
func TestQuarantine_PartialFailureIsRecoverable(t *testing.T) {
	tmp := t.TempDir()
	qRoot := filepath.Join(tmp, "q")
	ok := filepath.Join(tmp, "d", "ok")
	write(t, ok, "recoverable")
	f := model.Finding{
		Subject: model.Subject{Path: ok},
		Actions: []model.Action{
			{Kind: model.ActionMove, From: ok},
			{Kind: model.ActionMove, From: filepath.Join(tmp, "d", "missing")}, // will fail
		},
	}
	if _, err := Quarantine(qRoot, "t", model.Assessment{Finding: f}); err == nil {
		t.Fatal("expected an error on the missing second move")
	}
	// The first move must be recorded and restorable.
	if err := Restore(filepath.Join(qRoot, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(ok); err != nil || string(got) != "recoverable" {
		t.Fatalf("partial quarantine left move#1 orphaned: %v / %q", err, got)
	}
}
