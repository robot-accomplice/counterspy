package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type labelActor struct {
	lastFP  bool
	labeled model.Assessment
	calls   int
}

func (l *labelActor) Quarantine(a model.Assessment) (string, error) { return "", nil }
func (l *labelActor) Restore(string) error                          { return nil }
func (l *labelActor) Label(a model.Assessment, fp bool) error {
	l.calls++
	l.lastFP = fp
	l.labeled = a
	return nil
}

func TestUpdate_GBEmitLabelCmds(t *testing.T) {
	m := New([]model.Assessment{mk("beacon", model.RecInvestigate, 8)}, nil)
	_, cmds := update(m, tcell.KeyRune, 'g')
	if len(cmds) != 1 || cmds[0].Op != "labelFP" {
		t.Fatalf("g should emit labelFP, got %+v", cmds)
	}
	_, cmds = update(m, tcell.KeyRune, 'b')
	if len(cmds) != 1 || cmds[0].Op != "labelTP" {
		t.Fatalf("b should emit labelTP, got %+v", cmds)
	}
}

func TestRun_LabelReachesActorViaSimScreen(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.InjectKey(tcell.KeyRune, 'g', tcell.ModNone) // label FP
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone) // quit
	la := &labelActor{}
	m := New([]model.Assessment{mk("beacon", model.RecInvestigate, 8)}, nil)
	if err := RunConsole(s, m, la, fakeSampler{}, make(chan struct{}), nil); err != nil {
		t.Fatal(err)
	}
	if la.calls != 1 || la.lastFP != true || la.labeled.Subject.Label != "beacon" {
		t.Fatalf("label did not reach the actor: %+v", la)
	}
}
