package tui

import (
	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Cmd is an effect the event loop must perform (Run executes it). update stays pure.
type Cmd struct {
	Op string // "quarantine" | "restore" | "quit"
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

	n := len(m.visible())
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
			m.SortByRec = !m.SortByRec
		case 'm':
			m.ShowMonitor = !m.ShowMonitor
			m.Selected = 0
		case '/':
			m.Focus = focusFilter
		case '?':
			m.Focus = focusHelp
		case 'q':
			v := m.visible()
			if len(v) > 0 && m.Selected < len(v) && v[m.Selected].Recommendation != model.RecMonitor {
				m.Pending = v[m.Selected]
				m.Focus = focusModal
			}
		case 'u':
			return m, []Cmd{{Op: "restore"}}
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
