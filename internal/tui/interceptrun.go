package tui

import (
	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// RunIntercepted hosts the Intercepted viewer: a live, time-ordered master-detail over the flows the
// `intercept` daemon publishes. Flows arrive on `flows` (the caller owns the socket/log I/O and closes
// the channel when the stream ends — §12: no I/O in here). Screen is injected for tests; the caller
// Inits/Finis it.
//
// It is a DEDICATED loop rather than a third tab in RunConsole because `console --intercept` is a
// viewer: it runs as the ordinary user against a daemon's socket and must not trigger the sudo-gated
// evidence scan that Findings/Exfiltration need.
func RunIntercepted(s tcell.Screen, flows <-chan model.InterceptedFlow) error {
	m := NewIntercept()
	draw := func() { interceptView(m, s); s.Show() }
	draw()

	// Pump flows onto the UI thread as events, so the pure model is only ever touched here — the same
	// discipline RunConsole uses for sampler results.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for f := range flows {
			s.PostEvent(tcell.NewEventInterrupt(f))
		}
		s.PostEvent(tcell.NewEventInterrupt(streamEnded{}))
	}()

	for {
		switch ev := s.PollEvent().(type) {
		case *tcell.EventKey:
			next, quit := interceptUpdate(m, ev.Key(), ev.Rune())
			m = next
			if quit {
				return nil
			}
		case *tcell.EventInterrupt:
			switch d := ev.Data().(type) {
			case model.InterceptedFlow:
				m = m.withFlow(d)
			case streamEnded:
				// Say so rather than freezing a live view that will never update again (Rule 13).
				m.Status = "stream ended — the daemon stopped"
			}
		case nil:
			return nil // screen finished
		}
		draw()
	}
}

// streamEnded marks the flow source closing, so the viewer can say so instead of looking live.
type streamEnded struct{}
