package tui

import (
	"errors"
	"testing"

	"counterspy/internal/model"
)

type fakeActor struct {
	quarantined []string
	restored    int
	acked       []string
	unacked     []string
}

func (f *fakeActor) Quarantine(a model.Assessment) (string, error) {
	f.quarantined = append(f.quarantined, a.Subject.Label)
	return "/tmp/manifest.json", nil
}
func (f *fakeActor) RestoreItem(string, model.Assessment) error { f.restored++; return nil }
func (f *fakeActor) Label(model.Assessment, bool) error         { return nil }
func (f *fakeActor) Ack(a model.Assessment) error {
	f.acked = append(f.acked, a.Subject.Key())
	return nil
}
func (f *fakeActor) Unack(a model.Assessment) error {
	f.unacked = append(f.unacked, a.Subject.Key())
	return nil
}

// errActor lets each test configure exactly what Quarantine/Restore/Label/Ack return.
type errActor struct {
	quarantineManifest string
	quarantineErr      error
	restoreErr         error
	labelErr           error
	ackErr             error
}

func (e *errActor) Quarantine(model.Assessment) (string, error) {
	return e.quarantineManifest, e.quarantineErr
}
func (e *errActor) RestoreItem(string, model.Assessment) error { return e.restoreErr }
func (e *errActor) Label(model.Assessment, bool) error         { return e.labelErr }
func (e *errActor) Ack(model.Assessment) error                 { return e.ackErr }
func (e *errActor) Unack(model.Assessment) error               { return e.ackErr }

func applyOne(m Model, op string, a model.Assessment, actor Actor, lm *string) Model {
	return applyFindingsCmd(m, Cmd{Op: op, A: a}, actor, lm)
}

func TestApplyFindingsCmd_QuarantineSuccess(t *testing.T) {
	a := mk("evil", model.RecQuarantine, 14)
	var lm string
	m := New([]model.Assessment{a}, nil)
	m = applyOne(m, "quarantine", a, &fakeActor{}, &lm)
	if !m.Done[a.Subject.Key()] {
		t.Fatal("quarantined item should be marked Done")
	}
	if lm != "/tmp/manifest.json" {
		t.Fatalf("lastManifest not set: %q", lm)
	}
	if want := "quarantined "; m.Toast[:len(want)] != want {
		t.Fatalf("toast = %q", m.Toast)
	}
}

func TestApplyFindingsCmd_QuarantinePartialManifestOnError(t *testing.T) {
	a := mk("evil", model.RecQuarantine, 14)
	var lm string
	m := applyOne(New([]model.Assessment{a}, nil), "quarantine", a,
		&errActor{quarantineManifest: "/tmp/partial.json", quarantineErr: errors.New("boom")}, &lm)
	if lm != "/tmp/partial.json" {
		t.Fatalf("partial manifest must be recorded for undo, got %q", lm)
	}
	if m.Done[a.Subject.Key()] {
		t.Fatal("a failed quarantine must not mark Done")
	}
}

func TestApplyFindingsCmd_QuarantineErrorNoManifest(t *testing.T) {
	a := mk("evil", model.RecQuarantine, 14)
	var lm string
	m := applyOne(New([]model.Assessment{a}, nil), "quarantine", a,
		&errActor{quarantineErr: errors.New("boom")}, &lm)
	if lm != "" {
		t.Fatalf("no manifest → nothing to undo, got %q", lm)
	}
	if want := "quarantine failed"; m.Toast[:len(want)] != want {
		t.Fatalf("toast = %q", m.Toast)
	}
}

func TestApplyFindingsCmd_RestoreItemNothingYet(t *testing.T) {
	var lm string // no manifest yet → nothing quarantined this session
	m := applyOne(New(nil, nil), "restoreItem", mk("evil", model.RecQuarantine, 14), &fakeActor{}, &lm)
	if m.Toast != "nothing quarantined this session" {
		t.Fatalf("toast = %q", m.Toast)
	}
}

// #8: restoring the selected item clears only THAT item's Done, and drops lastManifest once the
// session has nothing left to undo.
func TestApplyFindingsCmd_RestoreItemClearsOnlyThatItem(t *testing.T) {
	a := mk("evil", model.RecQuarantine, 14)
	b := mk("other", model.RecQuarantine, 12)
	lm := "/tmp/manifest.json"
	m := New([]model.Assessment{a, b}, nil)
	m.Done = map[string]bool{a.Subject.Key(): true, b.Subject.Key(): true}
	m = applyOne(m, "restoreItem", a, &fakeActor{}, &lm)
	if m.Done[a.Subject.Key()] {
		t.Fatal("the restored item must be cleared from Done")
	}
	if !m.Done[b.Subject.Key()] {
		t.Fatal("a per-item restore must NOT clear other items' Done")
	}
	if lm == "" {
		t.Fatal("lastManifest must remain while other items are still quarantined")
	}
	m = applyOne(m, "restoreItem", b, &fakeActor{}, &lm)
	if len(m.Done) != 0 || lm != "" {
		t.Fatalf("restoring the last item should empty Done and clear lastManifest: done=%v lm=%q", m.Done, lm)
	}
}

func TestApplyFindingsCmd_RestoreItemErrorKeepsDone(t *testing.T) {
	a := mk("evil", model.RecQuarantine, 14)
	lm := "/tmp/manifest.json"
	m := New([]model.Assessment{a}, nil)
	m.Done = map[string]bool{a.Subject.Key(): true}
	m = applyOne(m, "restoreItem", a, &errActor{restoreErr: errors.New("nope")}, &lm)
	if !m.Done[a.Subject.Key()] {
		t.Fatal("a failed restore must keep the item marked done (containment may still hold)")
	}
	if want := "restore finished with issues"; m.Toast[:len(want)] != want {
		t.Fatalf("toast = %q", m.Toast)
	}
}

func TestApplyFindingsCmd_LabelErrorAndSuccess(t *testing.T) {
	a := mk("evil", model.RecQuarantine, 14)
	var lm string
	e := applyOne(New([]model.Assessment{a}, nil), "labelFP", a, &errActor{labelErr: errors.New("x")}, &lm)
	if want := "could not record label"; e.Toast[:len(want)] != want {
		t.Fatalf("error toast = %q", e.Toast)
	}
	ok := applyOne(New([]model.Assessment{a}, nil), "labelTP", a, &fakeActor{}, &lm)
	if want := "marked "; ok.Toast[:len(want)] != want {
		t.Fatalf("success toast = %q", ok.Toast)
	}
}

func TestWithDone_ClonesNotAliases(t *testing.T) {
	a := map[string]bool{"x": true}
	b := withDone(a, "y")
	if a["y"] {
		t.Fatal("withDone must not mutate the input map")
	}
	if !b["x"] || !b["y"] {
		t.Fatal("result should contain both old and new keys")
	}
}

// #4: applying ack marks the finding reviewed (map + actor) and unack clears it; an actor error
// surfaces as a toast and leaves the map unchanged (Rule 13: the decision isn't silently "recorded").
func TestApplyFindingsCmd_AckFlow(t *testing.T) {
	a := mk("x", model.RecMonitor, 3)
	key := a.Subject.Key()

	fa := &fakeActor{}
	var lm string
	m := New([]model.Assessment{a}, nil)
	m = applyOne(m, "ack", a, fa, &lm)
	if !m.Acked[key] || len(fa.acked) != 1 {
		t.Fatalf("ack should set the map and call actor.Ack: acked=%v calls=%v", m.Acked, fa.acked)
	}
	m = applyOne(m, "unack", a, fa, &lm)
	if m.Acked[key] || len(fa.unacked) != 1 {
		t.Fatalf("unack should clear the map and call actor.Unack: acked=%v calls=%v", m.Acked, fa.unacked)
	}

	ea := &errActor{ackErr: errors.New("disk full")}
	m2 := New([]model.Assessment{a}, nil)
	m2 = applyOne(m2, "ack", a, ea, &lm)
	if m2.Acked[key] {
		t.Fatal("a failed ack must NOT mark the finding reviewed")
	}
	if m2.Toast == "" {
		t.Fatal("a failed ack must surface a toast, not fail silently")
	}
}
