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

type trendMode int

const (
	trendOut      trendMode = iota // sparkline plots out-rate (temperature = share-of-peak volume)
	trendIn                        // sparkline plots in-rate (temperature)
	trendCombined                  // height = in+out, color = green→amber direction
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
	Trend    trendMode // which series/coloring the TREND column shows (cycled by `t`)
	Status   string    // transient feedback line (e.g. "copied path"); cleared on the next key
	CopyReq  string    // full path the run loop should copy to the clipboard, then clear

	expanded    map[string]bool // app name -> expanded (shows instance rows)
	expandedPID map[int]bool    // pid -> expanded (shows connection rows)
	sampled     bool            // a sampler result has arrived at least once (gates the empty-state
	//                             remediation: before the first sample we're "collecting", not empty)

	// Inspection overlay (spec §4): a modal over the tree, driven off the pure update like CopyReq —
	// egressUpdate only sets the request; RunConsole performs the capture I/O. There is NO consent
	// gate: pressing `i` on your own machine's own flow IS the intent — the boundary that keeps this
	// counter-spy (own-machine-only) is architectural, not a runtime prompt (maintainer decision).
	InspectReq *inspectTarget // RunConsole should capture+inspect this target, then clear it
	Inspection *inspection    // result overlay is open (nil = closed)
	Reveal     bool           // content pane is revealed (redaction off) for the open inspection
}

// inspectTarget is the flow the user chose to inspect, plus the display context the overlay
// header needs (resolved from the selected row, which the pure engine result doesn't carry).
type inspectTarget struct {
	app   string
	pid   int
	trust string // egress trust-label string → mark.TrustLabel for the header glyph
	conn  model.Conn
}

// inspection is an open result overlay: the target (for the header) + the rendered view.
type inspection struct {
	target inspectTarget
	view   model.InspectView
}

// selectedPath returns the full executable path of the selected row (the instance's path for
// an instance/conn row, else the group's binary path), or "" if there's no selectable row.
func (m EgressModel) selectedPath(rows []egressRow) string {
	if m.Selected < 0 || m.Selected >= len(rows) {
		return ""
	}
	row := rows[m.Selected]
	if row.member != nil {
		return row.member.Path
	}
	return row.group.Path
}

func NewEgress() EgressModel {
	return EgressModel{expanded: map[string]bool{}, expandedPID: map[int]bool{}}
}

// withGroups returns a copy with fresh data (called each tick). Selection/expanded/sort
// are preserved.
func (m EgressModel) withGroups(gs []model.EgressGroup) EgressModel {
	m.Groups = gs
	m.sampled = true // a real sampler result arrived — even an empty one means we've looked
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
	// The inspection result overlay is modal: it owns every key until dismissed.
	if m.Inspection != nil {
		switch {
		case key == tcell.KeyEscape, r == 'i':
			m.Inspection, m.Reveal = nil, false // back to the tree
		case r == 'v':
			m.Reveal = !m.Reveal // toggle secret masking — view/hide the plaintext (§6)
		case r == 'Q':
			return m, true
		}
		return m, false
	}
	m.Status = "" // any key clears the previous transient status
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
		case 't':
			m.Trend = (m.Trend + 1) % 3 // out → in → combined → out
		case 'y', 'c':
			if path := m.selectedPath(rows); path != "" {
				m.CopyReq = path // the run loop performs the clipboard I/O and sets Status
			}
		case 'i':
			m = m.requestInspect(rows) // queue the capture; RunConsole performs the I/O
		case 'Q':
			return m, true
		}
	}
	return m, false
}

// requestInspect resolves the selected row to a concrete (pid, remote) flow and queues the capture
// request. A row without a resolvable single connection (an app header) sets a status hint instead
// of guessing a flow.
func (m EgressModel) requestInspect(rows []egressRow) EgressModel {
	target, hint := resolveInspectTarget(rows, m.Selected)
	if target == nil {
		m.Status = hint
		return m
	}
	m.InspectReq = target // `i` captures directly — no consent gate (own machine, own data)
	return m
}

// resolveInspectTarget picks the flow to inspect from the selected row: a connection row is that
// connection; an instance row uses its busiest connection; an app header is ambiguous (many pids)
// so it returns a hint to drill in rather than fabricating a flow (the T-8 over-merge concern).
func resolveInspectTarget(rows []egressRow, selected int) (*inspectTarget, string) {
	if selected < 0 || selected >= len(rows) {
		return nil, ""
	}
	row := rows[selected]
	switch {
	case row.conn != nil: // connection leaf — exact flow
		return &inspectTarget{app: row.group.App, pid: row.member.PID, trust: row.member.Trust, conn: *row.conn}, ""
	case row.member != nil: // instance — inspect its busiest connection
		c := busiestConn(row.member.Conns)
		if c == nil {
			return nil, "no connection on this process to inspect"
		}
		return &inspectTarget{app: row.group.App, pid: row.member.PID, trust: row.member.Trust, conn: *c}, ""
	default: // app header — spans multiple pids; ambiguous
		return nil, "expand to a process or connection to inspect"
	}
}

// busiestConn returns the highest-out-rate connection (the most likely exfil channel), or nil.
func busiestConn(conns []model.Conn) *model.Conn {
	var best *model.Conn
	for i := range conns {
		if best == nil || conns[i].OutRate > best.OutRate {
			best = &conns[i]
		}
	}
	return best
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
