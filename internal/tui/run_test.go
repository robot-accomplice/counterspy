package tui

import (
	"errors"
	"testing"

	"counterspy/internal/model"
)

type fakeActor struct {
	quarantined []string
	restored    int
}

func (f *fakeActor) Quarantine(a model.Assessment) (string, error) {
	f.quarantined = append(f.quarantined, a.Subject.Label)
	return "/tmp/manifest.json", nil
}
func (f *fakeActor) Restore(string) error               { f.restored++; return nil }
func (f *fakeActor) Label(model.Assessment, bool) error { return nil }

// errActor lets each test configure exactly what Quarantine/Restore/Label return.
type errActor struct {
	quarantineManifest string
	quarantineErr      error
	restoreErr         error
	labelErr           error
}

func (e *errActor) Quarantine(model.Assessment) (string, error) {
	return e.quarantineManifest, e.quarantineErr
}
func (e *errActor) Restore(string) error               { return e.restoreErr }
func (e *errActor) Label(model.Assessment, bool) error { return e.labelErr }

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

func TestApplyFindingsCmd_RestoreNothingYet(t *testing.T) {
	var lm string
	m := applyOne(New(nil, nil), "restore", model.Assessment{}, &fakeActor{}, &lm)
	if m.Toast != "nothing quarantined this session" {
		t.Fatalf("toast = %q", m.Toast)
	}
}

func TestApplyFindingsCmd_RestoreSuccessClearsDone(t *testing.T) {
	a := mk("evil", model.RecQuarantine, 14)
	lm := "/tmp/manifest.json"
	m := New([]model.Assessment{a}, nil)
	m.Done = map[string]bool{a.Subject.Key(): true}
	m = applyOne(m, "restore", model.Assessment{}, &fakeActor{}, &lm)
	if len(m.Done) != 0 {
		t.Fatal("restore must clear Done (containment no longer holds)")
	}
}

func TestApplyFindingsCmd_RestoreError(t *testing.T) {
	lm := "/tmp/manifest.json"
	m := applyOne(New(nil, nil), "restore", model.Assessment{},
		&errActor{restoreErr: errors.New("nope")}, &lm)
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
