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

// egressRow is one rendered line: a group header, or (when expanded) one of its conns.
type egressRow struct {
	group model.EgressGroup
	conn  *model.Conn // nil = the group header row; non-nil = a child connection row
}

// EgressModel is the pure state of the live egress view.
type EgressModel struct {
	Groups   []model.EgressGroup
	Selected int
	Sort     egressSort
	Filter   string
	Paused   bool
	expanded map[string]bool // group key (App) → expanded
}

func NewEgress() EgressModel { return EgressModel{expanded: map[string]bool{}} }

// withGroups returns a copy with fresh data (called each tick). Selection/expanded/sort
// are preserved.
func (m EgressModel) withGroups(gs []model.EgressGroup) EgressModel {
	m.Groups = gs
	if m.Selected >= len(m.orderedGroups()) {
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

// visibleRows expands the ordered groups: each group header, followed by its conns when the
// group is expanded.
func (m EgressModel) visibleRows() []egressRow {
	var rows []egressRow
	for _, g := range m.orderedGroups() {
		g := g
		rows = append(rows, egressRow{group: g})
		if m.expanded[g.App] {
			for i := range g.Conns {
				rows = append(rows, egressRow{group: g, conn: &g.Conns[i]})
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
	groups := m.orderedGroups()
	switch key {
	case tcell.KeyDown:
		m.Selected = clamp(m.Selected+1, len(groups))
	case tcell.KeyUp:
		m.Selected = clamp(m.Selected-1, len(groups))
	case tcell.KeyEnter, tcell.KeyRight:
		if m.Selected < len(groups) {
			m.expanded = cloneSet(m.expanded)
			m.expanded[groups[m.Selected].App] = true
		}
	case tcell.KeyLeft:
		if m.Selected < len(groups) {
			m.expanded = cloneSet(m.expanded)
			delete(m.expanded, groups[m.Selected].App)
		}
	case tcell.KeyRune:
		switch r {
		case 'j':
			m.Selected = clamp(m.Selected+1, len(groups))
		case 'k':
			m.Selected = clamp(m.Selected-1, len(groups))
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
