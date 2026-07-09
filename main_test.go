package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"counterspy/internal/model"
)

func TestRun_ScanJSONDryEmitsArray(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"scan", "--json", "--dry"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "[") {
		t.Fatalf("expected JSON array, got: %s", buf.String())
	}
}

// A PID-only process finding has no on-disk artifact — no quarantine action (matches
// the actor: nothing to move, and we never offer an irreversible kill).
func TestPlannedActions_ProcessOnlyHasNone(t *testing.T) {
	f := model.Finding{Subject: model.Subject{PID: 8821}}
	if got := plannedActions(f); len(got) != 0 {
		t.Fatalf("process-only finding should have no actions, got %+v", got)
	}
}

func TestLoadSnapshot(t *testing.T) {
	as, err := loadSnapshot("testdata/tui_snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Subject.Label != "com.evil.updater" || as[0].Recommendation != model.RecQuarantine {
		t.Fatalf("snapshot decode wrong: %+v", as)
	}
}

func TestCliActor_Quarantine(t *testing.T) {
	tmp := t.TempDir()
	orig := filepath.Join(tmp, "beacon")
	os.WriteFile(orig, []byte("x"), 0o644)
	real, _ := filepath.EvalSymlinks(orig) // actor requires a canonical path (macOS /var symlink)
	a := model.Assessment{Finding: model.Finding{
		Subject:  model.Subject{Path: real, Label: "com.evil"},
		Evidence: []model.Evidence{{Kind: model.KindPersistence, Facts: map[string]string{"plist": real}}},
	}}
	realRoot, _ := filepath.EvalSymlinks(tmp)
	ca := &cliActor{root: filepath.Join(realRoot, "q"), ts: "t"}
	mp, err := ca.Quarantine(a)
	if err != nil {
		t.Fatalf("cliActor.Quarantine: %v", err)
	}
	if _, err := os.Stat(real); !os.IsNotExist(err) {
		t.Fatal("file should have moved to quarantine")
	}
	if mp == "" {
		t.Fatal("expected a manifest path")
	}
}

// ABORT-TUI Attacker/Domain #2: the actor boundary refuses a read-only (snapshot) actor,
// so read-only isn't a single UI conditional.
func TestCliActor_ReadOnlyRefuses(t *testing.T) {
	ca := &cliActor{root: t.TempDir(), ts: "t", readOnly: true}
	a := model.Assessment{Finding: model.Finding{
		Subject: model.Subject{Path: "/tmp/x", Label: "l"},
		Actions: []model.Action{{Kind: model.ActionMove, From: "/tmp/x"}},
	}}
	if _, err := ca.Quarantine(a); err == nil {
		t.Fatal("a read-only actor must refuse to quarantine")
	}
}

// The user allowlist suppresses a vetted known-good subject by label or path.
func TestFilterAllowed_SuppressesVetted(t *testing.T) {
	as := []model.Assessment{
		{Finding: model.Finding{Subject: model.Subject{Label: "com.jon.roboticus"}}},
		{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/evil"}}},
	}
	out := filterAllowed(as, map[string]bool{"com.jon.roboticus": true})
	if len(out) != 1 || out[0].Subject.Path != "/tmp/evil" {
		t.Fatalf("allowlist should drop only the vetted subject, got %+v", out)
	}
}

// A persistence finding plans a bootout (by label) plus a move of the plist and target.
func TestPlannedActions_PersistenceBootoutAndMoves(t *testing.T) {
	f := model.Finding{
		Subject:  model.Subject{Path: "/Users/me/Library/.hidden/beacon", Label: "com.evil"},
		Evidence: []model.Evidence{{Kind: model.KindPersistence, Facts: map[string]string{"plist": "/Users/me/Library/LaunchAgents/com.evil.plist"}}},
	}
	a := plannedActions(f)
	var boot, moves int
	for _, x := range a {
		if x.Kind == model.ActionBootout {
			boot++
		}
		if x.Kind == model.ActionMove {
			moves++
		}
	}
	if boot != 1 || moves != 2 {
		t.Fatalf("want 1 bootout + 2 moves, got %d/%d (%+v)", boot, moves, a)
	}
}
