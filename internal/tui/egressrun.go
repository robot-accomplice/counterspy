// internal/tui/egressrun.go
package tui

import (
	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Sampler yields the current aggregated egress groups (satisfied by internal/egress.Monitor
// via a main adapter).
type Sampler interface {
	Sample() []model.EgressGroup
}

// RunEgress drives the live loop. Each receive on `tick` triggers a sample (unless paused);
// key events drive the pure egressUpdate. Screen is injected for tests; the caller
// Inits/Finis it. The caller closes `tick` (or lets the process exit) to stop.
func RunEgress(s tcell.Screen, sampler Sampler, tick <-chan struct{}) error {
	m := NewEgress()
	// Post tick signals as screen events so a single event loop serializes samples + keys.
	go func() {
		for range tick {
			s.PostEvent(tcell.NewEventInterrupt(nil))
		}
	}()
	m = m.withGroups(sampler.Sample())
	egressView(m, s)
	s.Show()
	for {
		switch ev := s.PollEvent().(type) {
		case *tcell.EventKey:
			next, quit := egressUpdate(m, ev.Key(), ev.Rune())
			m = next
			if quit {
				return nil
			}
		case *tcell.EventInterrupt:
			if !m.Paused {
				m = m.withGroups(sampler.Sample())
			}
		case nil:
			return nil // screen finished
		}
		egressView(m, s)
		s.Show()
	}
}
