package tui

import (
	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Actor performs the effects the pure loop requests (satisfied by internal/act +
// internal/feedback via a main adapter). Label records a TP/FP judgement locally.
type Actor interface {
	Quarantine(a model.Assessment) (string, error)
	Restore(manifest string) error
	Label(a model.Assessment, falsePositive bool) error
}

// Run drives the event loop until quit. The screen is injected so tests can pass a
// SimulationScreen; the caller Inits/Finis the screen.
func Run(s tcell.Screen, m Model, actor Actor) error {
	var lastManifest string
	view(m, s)
	s.Show()
	for {
		ev := s.PollEvent()
		ek, ok := ev.(*tcell.EventKey)
		if !ok {
			view(m, s) // resize / other → redraw
			s.Show()
			continue
		}
		next, cmds := update(m, ek.Key(), ek.Rune())
		m = next
		for _, c := range cmds {
			switch c.Op {
			case "quit":
				return nil
			case "quarantine":
				mp, err := actor.Quarantine(c.A)
				switch {
				case err != nil && mp != "": // a partial manifest exists — undo is possible
					lastManifest = mp
					m.Toast = "stopped — partial state recorded (u to undo): " + err.Error()
				case err != nil:
					m.Toast = "quarantine failed (nothing changed): " + err.Error()
				default:
					m.Done = withDone(m.Done, c.A.Subject.Key())
					lastManifest = mp
					m.Toast = "quarantined " + c.A.Subject.Display()
				}
			case "restore":
				if lastManifest == "" {
					m.Toast = "nothing quarantined this session"
					break
				}
				err := actor.Restore(lastManifest)
				// Clear Done on ANY result: a partial restore moved SOME items back, so
				// keeping them marked "✓ quarantined" would misreport containment. The
				// Actor gives no per-item outcome, so the safe default is to un-mark all
				// and tell the operator to rescan (ABORT-TUI Domain #1).
				m.Done = map[string]bool{}
				if err != nil {
					m.Toast = "restore finished with issues — rescan to confirm: " + err.Error()
				} else {
					m.Toast = "restored (reloads at next login)"
				}
			case "labelFP", "labelTP":
				fp := c.Op == "labelFP"
				if err := actor.Label(c.A, fp); err != nil {
					m.Toast = "could not record label: " + err.Error()
					break
				}
				verdict := "correctly flagged"
				if fp {
					verdict = "false positive"
				}
				m.Toast = "marked " + c.A.Subject.Display() + " as " + verdict
			}
		}
		view(m, s)
		s.Show()
	}
}

// withDone returns a NEW map with key added — clone-on-write so Model value-copies
// stay independent snapshots rather than sharing one map header (cp-tui-1 Audit F-1).
func withDone(done map[string]bool, key string) map[string]bool {
	nd := make(map[string]bool, len(done)+1)
	for k, v := range done {
		nd[k] = v
	}
	nd[key] = true
	return nd
}
