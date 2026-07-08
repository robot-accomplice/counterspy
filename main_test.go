package main

import (
	"bytes"
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
