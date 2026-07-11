// internal/tui/egressrun.go
package tui

import (
	"sync/atomic"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Sampler yields the current aggregated egress groups (satisfied by internal/egress.Monitor
// via a main adapter).
type Sampler interface {
	Sample() []model.EgressGroup
}

// RunEgress drives the live loop. Sampling happens off the UI thread: a background goroutine
// runs the (potentially slow, ~1s+) Sample() call and delivers the result to the loop as
// EventInterrupt data, so PollEvent is never blocked by the monitor and key presses (notably
// quit) are always handled immediately. Each receive on `tick` triggers a sample (unless
// paused); key events drive the pure egressUpdate. Screen is injected for tests; the caller
// Inits/Finis it. The caller closes `tick` (or lets the process exit) to stop.
func RunEgress(s tcell.Screen, sampler Sampler, tick <-chan struct{}) error {
	m := NewEgress()
	var paused atomic.Bool
	// Sample OFF the UI thread: the blocking Sample() runs here and posts its result as event
	// data, so key handling (esp. quit) is never blocked waiting on it.
	go func() {
		s.PostEvent(tcell.NewEventInterrupt(sampler.Sample())) // initial
		for range tick {
			if paused.Load() {
				continue // don't run the blocking sample while paused
			}
			s.PostEvent(tcell.NewEventInterrupt(sampler.Sample()))
		}
	}()
	egressView(m, s) // draw immediately; don't block on the first sample
	s.Show()
	for {
		switch ev := s.PollEvent().(type) {
		case *tcell.EventKey:
			next, quit := egressUpdate(m, ev.Key(), ev.Rune())
			m = next
			paused.Store(m.Paused)
			if quit {
				return nil
			}
		case *tcell.EventInterrupt:
			if groups, ok := ev.Data().([]model.EgressGroup); ok && !m.Paused {
				m = m.withGroups(groups)
			}
		case nil:
			return nil // screen finished
		}
		egressView(m, s)
		s.Show()
	}
}
