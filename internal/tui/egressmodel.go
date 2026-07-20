// internal/tui/egressmodel.go
package tui

import (
	"fmt"
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

	Zoom *zoomState // group-zoom dashboard is open (nil = closed); rendered under any Inspection

	// Phase 2.5 merge: intercepted per-message events for this app/path.
	ProxyAddr        string                                // armed proxy endpoint, e.g. "127.0.0.1:62443"
	Messages         map[string][]model.InterceptedMessage // key = binary Path
	InterceptedDests map[string]struct{}                   // canonical DestIP strings seen in stream
	MessageDropCount int
}

// zoomState is the open group-zoom dashboard: the group (re-resolved by name each frame so live
// samples flow in), the selected PID index within the sorted members, and the graph metric mode.
type zoomState struct {
	app     string
	sel     int       // cursor in the PIDs box
	selDest int       // cursor in the destinations box
	mode    trendMode // graph metric: out / in / combined
	byDest  bool      // focus + graph grouping: destinations box (true) vs PIDs box (false)
}

func (z *zoomState) withSel(sel int) *zoomState      { c := *z; c.sel = sel; return &c }
func (z *zoomState) withSelDest(i int) *zoomState    { c := *z; c.selDest = i; return &c }
func (z *zoomState) withMode(m trendMode) *zoomState { c := *z; c.mode = m; return &c }
func (z *zoomState) withByDest(b bool) *zoomState    { c := *z; c.byDest = b; return &c }

// zoomedMembers returns a group's members sorted by out-rate desc (loud talkers first), stable by
// PID — the shared order for the PID panel and the graph's colored lines.
func zoomedMembers(g model.EgressGroup) []model.EgressInstance {
	ms := append([]model.EgressInstance(nil), g.Members...)
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].OutRate != ms[j].OutRate {
			return ms[i].OutRate > ms[j].OutRate
		}
		return ms[i].PID < ms[j].PID
	})
	return ms
}

// zoomGroup resolves the currently-zoomed group by name from the live groups. ok=false if it has
// vanished between ticks (the caller then closes the zoom).
func (m EgressModel) zoomGroup() (model.EgressGroup, bool) {
	if m.Zoom == nil {
		return model.EgressGroup{}, false
	}
	for _, g := range m.orderedGroups() {
		if g.App == m.Zoom.app {
			return g, true
		}
	}
	return model.EgressGroup{}, false
}

// destRate is one destination endpoint's aggregated out-rate, for the destinations box. ep is the
// stable IP:port key (used for cursor nav + busiestConnTo); label is the display host (resolved name
// if any, else the IP) so the panel shows names while navigation stays keyed on the IP (#3).
type destRate struct {
	ep    string
	label string
	rate  uint64
}

// zoomDests aggregates a group's connections by endpoint and sorts by out-rate desc (loud first),
// stable by endpoint. Shared by the destinations panel, its cursor navigation, and the by-dest graph.
func zoomDests(g model.EgressGroup) []destRate {
	agg := map[string]uint64{}
	label := map[string]string{}
	for _, c := range g.Conns {
		ep := fmt.Sprintf("%s:%d", c.Endpoint.IP, c.Endpoint.Port)
		agg[ep] += c.OutRate
		if _, ok := label[ep]; !ok {
			label[ep] = fmt.Sprintf("%s:%d", endpointHost(c.Endpoint), c.Endpoint.Port)
		}
	}
	ds := make([]destRate, 0, len(agg))
	for ep, r := range agg {
		ds = append(ds, destRate{ep: ep, label: label[ep], rate: r})
	}
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].rate != ds[j].rate {
			return ds[i].rate > ds[j].rate
		}
		return ds[i].ep < ds[j].ep
	})
	return ds
}

// busiestConnTo returns the highest-out-rate connection to an "ip:port" endpoint (across PIDs) —
// the concrete flow `i` inspects when a destination is selected.
func busiestConnTo(g model.EgressGroup, ep string) *model.Conn {
	var best *model.Conn
	for i := range g.Conns {
		c := &g.Conns[i]
		if fmt.Sprintf("%s:%d", c.Endpoint.IP, c.Endpoint.Port) == ep {
			if best == nil || c.OutRate > best.OutRate {
				best = c
			}
		}
	}
	return best
}

// zoomInspectTarget resolves the flow to inspect from the FOCUSED box: the selected PID's busiest
// connection, or the busiest connection to the selected destination. nil if nothing resolvable.
func zoomInspectTarget(g model.EgressGroup, members []model.EgressInstance, dests []destRate, z *zoomState) *inspectTarget {
	if z.byDest {
		if z.selDest >= len(dests) {
			return nil
		}
		c := busiestConnTo(g, dests[z.selDest].ep)
		if c == nil {
			return nil
		}
		trust := ""
		for _, mem := range members {
			if mem.PID == c.PID {
				trust = mem.Trust
				break
			}
		}
		return &inspectTarget{app: g.App, pid: c.PID, trust: trust, conn: *c}
	}
	if z.sel >= len(members) {
		return nil
	}
	mem := members[z.sel]
	c := busiestConn(mem.Conns)
	if c == nil {
		return nil
	}
	return &inspectTarget{app: g.App, pid: mem.PID, trust: mem.Trust, conn: *c}
}

// pidShare is a member's percentage of the group's total out-rate (0..100), 0 when the group is
// idle. Clamped to 100: per-PID and group rates are sampled independently, so jitter can briefly
// make a member's rate exceed the group sum (cp-zoom Antagonist F2).
func pidShare(memberOut, groupOut uint64) int {
	if groupOut == 0 {
		return 0
	}
	if p := int(memberOut * 100 / groupOut); p < 100 {
		return p
	}
	return 100
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

// withMessage ingests one sanitized intercepted event into the per-app buffer, bounded so a
// noisy app can't unbounded-grow the view.
func (m EgressModel) withMessage(msg model.InterceptedMessage) EgressModel {
	if m.Messages == nil {
		m.Messages = make(map[string][]model.InterceptedMessage)
	}
	key := msg.Path
	if key == "" {
		key = msg.App
	}
	const maxPerApp = 500
	buf := append(m.Messages[key], msg)
	if len(buf) > maxPerApp {
		buf = buf[len(buf)-maxPerApp:]
		m.MessageDropCount += len(buf) - maxPerApp
	}
	m.Messages[key] = buf
	if msg.DestIP != "" {
		if m.InterceptedDests == nil {
			m.InterceptedDests = make(map[string]struct{})
		}
		m.InterceptedDests[msg.DestIP] = struct{}{}
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
	// The zoom dashboard is modal under any inspection: it owns keys until dismissed. `i` here
	// requests inspection for the SELECTED pid, which then stacks on top.
	if m.Zoom != nil {
		g, ok := m.zoomGroup()
		if !ok { // the group vanished between ticks — fall back to the tree
			m.Zoom = nil
			return m, false
		}
		members := zoomedMembers(g)
		dests := zoomDests(g)
		// Re-clamp BOTH box cursors against the freshly-resolved lists EVERY keypress, not only on
		// up/down: a group can gain/lose PIDs or destinations between ticks, and a stale cursor would
		// make `i` a silent no-op or go negative (cp-zoom Audit F3 / Antagonist F1). One source of truth.
		m.Zoom = m.Zoom.withSel(clamp(m.Zoom.sel, len(members))).withSelDest(clamp(m.Zoom.selDest, len(dests)))
		// Arrow keys navigate the FOCUSED box (destinations when byDest, else PIDs).
		nav := func(delta int) {
			if m.Zoom.byDest {
				m.Zoom = m.Zoom.withSelDest(clamp(m.Zoom.selDest+delta, len(dests)))
			} else {
				m.Zoom = m.Zoom.withSel(clamp(m.Zoom.sel+delta, len(members)))
			}
		}
		switch {
		case key == tcell.KeyEscape, r == 'z':
			m.Zoom = nil
		case key == tcell.KeyUp, r == 'k':
			nav(-1)
		case key == tcell.KeyDown, r == 'j':
			nav(+1)
		case r == 't':
			m.Zoom = m.Zoom.withMode((m.Zoom.mode + 1) % 3)
		case r == 'g':
			m.Zoom = m.Zoom.withByDest(!m.Zoom.byDest) // move focus: PIDs box ⇄ destinations box
		case r == 'i':
			if tgt := zoomInspectTarget(g, members, dests, m.Zoom); tgt != nil {
				m.InspectReq = tgt
			}
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
		case 'z':
			if m.Selected >= 0 && m.Selected < len(rows) {
				m.Zoom = &zoomState{app: rows[m.Selected].group.App, sel: 0, mode: m.Trend}
			}
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
