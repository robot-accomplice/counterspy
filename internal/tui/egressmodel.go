// internal/tui/egressmodel.go
package tui

import (
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type egressSort int

const (
	sortRate egressSort = iota
	sortConcern
	sortExfil
	sortApp
)

// egressRow is one rendered line in the 3-level tree:
//   - group only            -> app header row
//   - group + member        -> instance (PID) row
//   - group + member + conn -> connection row (leaf)
type egressRow struct {
	group  model.EgressGroup
	member *model.EgressInstance
	conn   *model.Conn
}

// EgressModel is the pure state of the live egress view.
type EgressModel struct {
	Groups   []model.EgressGroup
	Selected int // index into visibleRows()
	Sort     egressSort
	Filter   string
	Paused   bool

	expanded    map[string]bool // app name -> expanded (shows instance rows)
	expandedPID map[int]bool    // pid -> expanded (shows connection rows)
}

func NewEgress() EgressModel {
	return EgressModel{expanded: map[string]bool{}, expandedPID: map[int]bool{}}
}

// withGroups returns a copy with fresh data (called each tick). Selection/expanded/sort
// are preserved.
func (m EgressModel) withGroups(gs []model.EgressGroup) EgressModel {
	m.Groups = gs
	if m.Selected >= len(m.visibleRows()) {
		m.Selected = 0
	}
	return m
}

func (m EgressModel) orderedGroups() []model.EgressGroup {
	out := make([]model.EgressGroup, 0, len(m.Groups))
	for _, g := range m.Groups {
		if m.Filter == "" || strings.Contains(strings.ToLower(g.App), strings.ToLower(m.Filter)) {
			out = append(out, g)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		switch m.Sort {
		case sortConcern:
			return out[i].Concern > out[j].Concern
		case sortExfil:
			return out[i].ExfilRisk > out[j].ExfilRisk
		case sortApp:
			return out[i].App < out[j].App
		default:
			return out[i].OutRate > out[j].OutRate
		}
	})
	return out
}

// visibleRows expands the ordered groups into the 3-level tree: each app header, followed by
// one instance row per Member when the app is expanded, followed by one conn row per that
// instance's Conns when the instance (by PID) is expanded.
func (m EgressModel) visibleRows() []egressRow {
	var rows []egressRow
	for _, g := range m.orderedGroups() {
		g := g
		rows = append(rows, egressRow{group: g})
		if !m.expanded[g.App] {
			continue
		}
		for i := range g.Members {
			mem := g.Members[i]
			rows = append(rows, egressRow{group: g, member: &mem})
			if !m.expandedPID[mem.PID] {
				continue
			}
			for j := range mem.Conns {
				rows = append(rows, egressRow{group: g, member: &mem, conn: &mem.Conns[j]})
			}
		}
	}
	return rows
}

// egressUpdate is the pure transition. Returns (model, quit).
func egressUpdate(m EgressModel, key tcell.Key, r rune) (EgressModel, bool) {
	if key == tcell.KeyCtrlC {
		return m, true
	}
	rows := m.visibleRows()
	switch key {
	case tcell.KeyDown:
		m.Selected = clamp(m.Selected+1, len(rows))
	case tcell.KeyUp:
		m.Selected = clamp(m.Selected-1, len(rows))
	case tcell.KeyEnter, tcell.KeyRight:
		m = m.expandSelected(rows)
	case tcell.KeyLeft:
		m = m.collapseSelected(rows)
	case tcell.KeyRune:
		switch r {
		case 'j':
			m.Selected = clamp(m.Selected+1, len(rows))
		case 'k':
			m.Selected = clamp(m.Selected-1, len(rows))
		case 's':
			m.Sort = (m.Sort + 1) % 4
		case 'p':
			m.Paused = !m.Paused
		case 'Q':
			return m, true
		}
	}
	return m, false
}

// expandSelected opens the next level of the selected row: an app header reveals its
// instances, an instance row reveals its connections. Conn rows (leaves) are a no-op.
func (m EgressModel) expandSelected(rows []egressRow) EgressModel {
	if m.Selected >= len(rows) {
		return m
	}
	row := rows[m.Selected]
	switch {
	case row.member == nil: // app header
		m.expanded = cloneSet(m.expanded)
		m.expanded[row.group.App] = true
	case row.conn == nil: // instance row
		m.expandedPID = clonePIDSet(m.expandedPID)
		m.expandedPID[row.member.PID] = true
	}
	return m
}

// collapseSelected closes the level the selected row belongs to: an app header collapses its
// instances, an instance row collapses its connections, and a conn row collapses its parent
// instance (there is nothing "under" a leaf to close).
func (m EgressModel) collapseSelected(rows []egressRow) EgressModel {
	if m.Selected >= len(rows) {
		return m
	}
	row := rows[m.Selected]
	switch {
	case row.member == nil: // app header
		m.expanded = cloneSet(m.expanded)
		delete(m.expanded, row.group.App)
	default: // instance or conn row
		m.expandedPID = clonePIDSet(m.expandedPID)
		delete(m.expandedPID, row.member.PID)
	}
	return m
}

func clamp(i, n int) int {
	if n == 0 || i < 0 {
		return 0
	}
	if i > n-1 {
		return n - 1
	}
	return i
}

func cloneSet(s map[string]bool) map[string]bool {
	n := make(map[string]bool, len(s)+1)
	for k, v := range s {
		n[k] = v
	}
	return n
}

func clonePIDSet(s map[int]bool) map[int]bool {
	n := make(map[int]bool, len(s)+1)
	for k, v := range s {
		n[k] = v
	}
	return n
}
