package tui

import (
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
func (f *fakeActor) Restore(string) error { f.restored++; return nil }

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
