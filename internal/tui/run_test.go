package tui

import (
	"errors"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

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

func TestRun_QuarantineFlow(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &fakeActor{}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()

	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'q') // open modal
	inject(tcell.KeyEnter, 0)  // confirm
	inject(tcell.KeyRune, 'Q') // quit

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit on quit")
	}
	if len(fa.quarantined) != 1 || fa.quarantined[0] != "evil" {
		t.Fatalf("quarantine not called for 'evil': %v", fa.quarantined)
	}
}

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

func TestRun_NonKeyEventRedraws(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &fakeActor{}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()

	time.Sleep(15 * time.Millisecond)
	s.PostEvent(tcell.NewEventInterrupt(nil)) // a non-EventKey event → redraw-and-continue branch
	time.Sleep(15 * time.Millisecond)
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit on quit")
	}
}

func TestRun_QuarantinePartialManifestOnError(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &errActor{quarantineManifest: "/tmp/partial.json", quarantineErr: errors.New("bootout failed")}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()
	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'q')
	inject(tcell.KeyEnter, 0)
	time.Sleep(15 * time.Millisecond)
	if !simContains(s, "partial state recorded") {
		t.Fatalf("a quarantine error WITH a manifest should surface the partial-state toast:\n%s", screenText(s))
	}
	inject(tcell.KeyRune, 'Q')
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRun_QuarantineErrorNoManifest(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &errActor{quarantineErr: errors.New("permission denied")}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()
	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'q')
	inject(tcell.KeyEnter, 0)
	time.Sleep(15 * time.Millisecond)
	if !simContains(s, "quarantine failed (nothing changed)") {
		t.Fatalf("a quarantine error with no manifest should say nothing changed:\n%s", screenText(s))
	}
	inject(tcell.KeyRune, 'Q')
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRun_RestoreNothingQuarantinedYet(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &fakeActor{}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()
	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'u')
	time.Sleep(15 * time.Millisecond)
	if !simContains(s, "nothing quarantined this session") {
		t.Fatalf("restoring before any quarantine should say nothing to restore:\n%s", screenText(s))
	}
	inject(tcell.KeyRune, 'Q')
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRun_RestoreSuccessAfterQuarantine(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &fakeActor{}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()
	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'q')
	inject(tcell.KeyEnter, 0) // quarantine "evil" → sets lastManifest
	inject(tcell.KeyRune, 'u')
	time.Sleep(15 * time.Millisecond)
	if !simContains(s, "restored (reloads at next login)") {
		t.Fatalf("a successful restore should confirm reload:\n%s", screenText(s))
	}
	if fa.restored != 1 {
		t.Fatalf("Restore should have been called once, got %d", fa.restored)
	}
	inject(tcell.KeyRune, 'Q')
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRun_RestoreErrorAfterQuarantine(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &errActor{quarantineManifest: "/tmp/manifest.json", restoreErr: errors.New("disk full")}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()
	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'q')
	inject(tcell.KeyEnter, 0) // quarantine ok → sets lastManifest
	inject(tcell.KeyRune, 'u')
	time.Sleep(15 * time.Millisecond)
	if !simContains(s, "restore finished with issues") {
		t.Fatalf("a restore error should surface the issues toast:\n%s", screenText(s))
	}
	inject(tcell.KeyRune, 'Q')
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRun_LabelErrorBranch(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &errActor{labelErr: errors.New("disk full")}
	m := New([]model.Assessment{mk("beacon", model.RecInvestigate, 8)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()
	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'g')
	time.Sleep(15 * time.Millisecond)
	if !simContains(s, "could not record label") {
		t.Fatalf("a label error should surface a toast:\n%s", screenText(s))
	}
	inject(tcell.KeyRune, 'Q')
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The clone-on-write keeps two Model snapshots independent (Audit F-1).
func TestWithDone_ClonesNotAliases(t *testing.T) {
	a := map[string]bool{"x": true}
	b := withDone(a, "y")
	if a["y"] {
		t.Fatal("withDone must not mutate the input map")
	}
	if !b["x"] || !b["y"] {
		t.Fatal("withDone must carry old + new keys")
	}
}
