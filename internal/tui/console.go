package tui

import (
	"sync/atomic"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type consoleMode int

const (
	modeFindings consoleMode = iota
	modeExfil
)

// RunConsole hosts both faces in one screen — Findings triage and the Exfiltration monitor —
// switched with Tab / Shift-Tab. It replaces the separate Run (findings) and RunEgress (egress)
// loops. The Exfiltration sampler runs LAZILY: the background sample goroutine only calls the
// (slow) Sample() while Exfiltration is the visible mode and not paused, so no nettop/lsof work
// happens while triaging findings. Screen is injected for tests; the caller Inits/Finis it and
// closes `tick` (or exits) to stop.
func RunConsole(s tcell.Screen, m Model, actor Actor, sampler Sampler, inspector Inspector, tick <-chan struct{}, clip func(string) error) error {
	mode := modeFindings
	em := NewEgress()
	var lastManifest string

	var sampling atomic.Bool
	sampleNow := make(chan struct{}, 1)
	// Sample OFF the UI thread and ONLY while Exfiltration is visible, delivering results as
	// EventInterrupt so key handling (esp. quit) never blocks on the sampler.
	go func() {
		do := func() { s.PostEvent(tcell.NewEventInterrupt(sampler.Sample())) }
		for {
			select {
			case _, ok := <-tick:
				if !ok {
					return
				}
				if sampling.Load() {
					do()
				}
			case <-sampleNow:
				do()
			}
		}
	}()
	setSampling := func() { sampling.Store(mode == modeExfil && !em.Paused) }

	draw := func() {
		switch {
		case em.Inspection != nil: // full-screen inspection pane replaces the tree
			drawInspect(s, em.Inspection, em.Reveal)
		case mode == modeFindings:
			view(m, s)
			drawConsoleTabs(s, mode, m.ReadOnly)
		default:
			egressView(em, s)
			drawConsoleTabs(s, mode, m.ReadOnly)
			if em.ConsentFor != nil { // consent gate over the tree
				drawConsentPrompt(s, em.ConsentFor)
			}
		}
		s.Show()
	}
	draw()

	for {
		switch ev := s.PollEvent().(type) {
		case *tcell.EventKey:
			// Tab switches faces only when no exfil overlay owns the screen (an open
			// inspection/consent modal must not be left dangling behind the other face).
			overlayOpen := em.Inspection != nil || em.ConsentFor != nil
			if !overlayOpen && (ev.Key() == tcell.KeyTab || ev.Key() == tcell.KeyBacktab) {
				if mode == modeFindings {
					mode = modeExfil
					setSampling()
					if !em.Paused { // warm the view with one immediate sample (unless paused)
						select {
						case sampleNow <- struct{}{}:
						default:
						}
					}
				} else {
					mode = modeFindings
					setSampling()
				}
				draw()
				continue
			}
			if mode == modeFindings {
				var cmds []Cmd
				m, cmds = update(m, ev.Key(), ev.Rune())
				for _, c := range cmds {
					if c.Op == "quit" {
						return nil
					}
					m = applyFindingsCmd(m, c, actor, &lastManifest)
				}
			} else {
				next, quit := egressUpdate(em, ev.Key(), ev.Rune())
				if next.CopyReq != "" { // clipboard I/O off the pure update
					path := next.CopyReq
					next.CopyReq = ""
					if clip != nil && clip(path) == nil {
						next.Status = "copied path to clipboard"
					} else {
						next.Status = "copy unavailable"
					}
				}
				if next.InspectReq != nil { // capture+inspect I/O off the pure update (§4)
					target := *next.InspectReq
					next.InspectReq = nil
					view := model.InspectView{Verdict: "inspection disabled (--no-inspect)"}
					if inspector != nil {
						view = inspector.Inspect(target.conn)
					}
					next.Inspection = &inspection{target: target, view: view}
					next.Reveal = false
				}
				em = next
				setSampling()
				if quit {
					return nil
				}
			}
		case *tcell.EventInterrupt:
			if groups, ok := ev.Data().([]model.EgressGroup); ok && !em.Paused {
				em = em.withGroups(groups)
			}
		case nil:
			return nil // screen finished
		}
		draw()
	}
}

// applyFindingsCmd performs one findings-view effect (quarantine / restore / label) via the
// Actor and returns the updated Model. "quit" is handled by the caller. lastManifest threads the
// session's undo target across quarantine/restore.
func applyFindingsCmd(m Model, c Cmd, actor Actor, lastManifest *string) Model {
	switch c.Op {
	case "quarantine":
		mp, err := actor.Quarantine(c.A)
		switch {
		case err != nil && mp != "": // a partial manifest exists — undo is possible
			*lastManifest = mp
			m.Toast = "stopped — partial state recorded (u to undo): " + err.Error()
		case err != nil:
			m.Toast = "quarantine failed (nothing changed): " + err.Error()
		default:
			m.Done = withDone(m.Done, c.A.Subject.Key())
			*lastManifest = mp
			m.Toast = "quarantined " + c.A.Subject.Display()
		}
	case "restore":
		if *lastManifest == "" {
			m.Toast = "nothing quarantined this session"
			break
		}
		err := actor.Restore(*lastManifest)
		// Clear Done on ANY result: a partial restore moved SOME items back, so keeping them
		// marked "✓ quarantined" would misreport containment (ABORT-TUI Domain #1).
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
	return m
}

// drawConsoleTabs overlays the unified mode header on row 0 (both sub-views draw their own title
// there; this replaces the left portion with the Findings ⇄ Exfiltration switcher, leaving the
// right side — e.g. the Exfiltration status — intact).
func drawConsoleTabs(s tcell.Screen, mode consoleMode, readOnly bool) {
	w, _ := s.Size()
	// Clear the left region we own on row 0. In Exfiltration mode the sub-view draws its status
	// line on the RIGHT of row 0, so reserve ~26 columns for it; Findings has no right-side
	// row-0 content, so clear the full width (covers the read-only badge).
	clearTo := w
	if mode == modeExfil {
		clearTo = w - 26
	}
	if clearTo < 0 {
		clearTo = 0
	}
	if clearTo > w {
		clearTo = w
	}
	for x := 0; x < clearTo; x++ {
		s.SetContent(x, 0, ' ', nil, tcell.StyleDefault)
	}
	def := tcell.StyleDefault
	x := drawText(s, 2, 0, def.Foreground(colAccent).Bold(true), "CounterSpy")
	x += 2
	tab := func(x int, label string, active bool) int {
		st := def.Foreground(colDim)
		if active {
			st = def.Foreground(colAccent).Bold(true)
		}
		return drawText(s, x, 0, st, label)
	}
	x = tab(x, "Findings", mode == modeFindings)
	x = drawText(s, x, 0, def.Foreground(colDivider), " ⇄ ")
	x = tab(x, "Exfiltration", mode == modeExfil)
	x = drawText(s, x+1, 0, def.Foreground(colDim), "⇥")
	if readOnly && mode == modeFindings {
		drawText(s, x+2, 0, def.Foreground(colWarn), "· read-only")
	}
}
