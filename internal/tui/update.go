package tui

import (
	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Cmd is an effect the event loop must perform (Run executes it). update stays pure.
type Cmd struct {
	Op string // "quarantine" | "restoreItem" | "labelFP" | "labelTP" | "ack" | "unack" | "quit"
	A  model.Assessment
}

// update is the pure state transition: a key event → new Model + effects. No I/O.
func update(m Model, key tcell.Key, r rune) (Model, []Cmd) {
	// Ctrl-C quits from ANY mode — checked first so a focus overlay can't trap it
	// (cp-tui-1 QA F-1).
	if key == tcell.KeyCtrlC {
		return m, []Cmd{{Op: "quit"}}
	}
	// Overlays capture keys until dismissed.
	if m.Focus == focusModal {
		switch key {
		case tcell.KeyEnter:
			m.Focus = focusList
			return m, []Cmd{{Op: "quarantine", A: m.Pending}}
		case tcell.KeyEsc:
			m.Focus = focusList
		}
		return m, nil
	}
	if m.Focus == focusHelp {
		if key == tcell.KeyEsc || (key == tcell.KeyRune && r == '?') {
			m.Focus = focusList
		}
		return m, nil
	}
	if m.Focus == focusFilter {
		switch key {
		case tcell.KeyEsc:
			m.Filter, m.Focus, m.Selected = "", focusList, 0
		case tcell.KeyEnter:
			m.Focus = focusList
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if m.Filter != "" {
				m.Filter = m.Filter[:len(m.Filter)-1]
			}
			m.Selected = 0
		case tcell.KeyRune:
			m.Filter += string(r)
			m.Selected = 0
		}
		return m, nil
	}

	v := m.visible() // computed once per event (was 2–3× per keystroke)
	n := len(v)
	switch key {
	case tcell.KeyDown:
		return moveSel(m, +1, n), nil
	case tcell.KeyUp:
		return moveSel(m, -1, n), nil
	case tcell.KeyRune:
		switch r {
		case 'j':
			return moveSel(m, +1, n), nil
		case 'k':
			return moveSel(m, -1, n), nil
		case 's':
			m.Sort = (m.Sort + 1) % 3
			m.Toast = "sorted by " + m.Sort.label()
		case '/':
			m.Focus = focusFilter
		case '?':
			m.Focus = focusHelp
		case 'q':
			if n == 0 || m.Selected >= n || v[m.Selected].Recommendation == model.RecMonitor {
				break
			}
			if m.ReadOnly {
				m.Toast = "quarantine disabled for --from snapshots — run a live scan to act"
				break
			}
			m.Pending = v[m.Selected]
			m.Focus = focusModal
		case 'u':
			// Per-item undo: restore the SELECTED finding if it was quarantined this session
			// (#8) rather than reversing the whole session at once.
			if n == 0 || m.Selected >= n {
				break
			}
			sel := v[m.Selected]
			if !m.Done[sel.Subject.Key()] {
				m.Toast = "nothing to undo on " + sel.Subject.Display() + " (not quarantined this session)"
				break
			}
			return m, []Cmd{{Op: "restoreItem", A: sel}}
		case 'g':
			if n == 0 || m.Selected >= n {
				break
			}
			return m, []Cmd{{Op: "labelFP", A: v[m.Selected]}}
		case 'b':
			if n == 0 || m.Selected >= n {
				break
			}
			return m, []Cmd{{Op: "labelTP", A: v[m.Selected]}}
		case 'a':
			if n == 0 || m.Selected >= n {
				break
			}
			// Revisitable toggle: ack an unacked finding, un-ack an already-decided one.
			op := "ack"
			if m.Acked[v[m.Selected].Subject.Key()] {
				op = "unack"
			}
			return m, []Cmd{{Op: op, A: v[m.Selected]}}
		case 'Q':
			return m, []Cmd{{Op: "quit"}}
		}
	}
	return m, nil
}

func moveSel(m Model, d, n int) Model {
	if n == 0 {
		m.Selected = 0
		return m
	}
	m.Selected += d
	if m.Selected < 0 {
		m.Selected = 0
	}
	if m.Selected > n-1 {
		m.Selected = n - 1
	}
	return m
}
