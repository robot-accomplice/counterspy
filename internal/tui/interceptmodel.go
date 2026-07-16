package tui

import (
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/mark"
	"counterspy/internal/model"
)

// Bounds. Processes are the STABLE axis — a machine runs tens of them, and the list only grows when a
// pid not seen before sends something. Flows are the fast axis, so each process keeps a bounded running
// log; a long session must not grow without limit.
const (
	maxAppLog = 500 // flows retained per process (oldest dropped)
	maxApps   = 256 // processes retained (least-recently-active dropped — short-lived pids accumulate)
)

// appRow is one originating process and its running log. Rows are append-only in FIRST-SEEN order and
// never re-sorted: a list that reorders itself under a reader is unusable for watching one process.
type appRow struct {
	PID    int
	App    string
	Flows  []model.InterceptedFlow // oldest first, bounded by maxAppLog
	LastAt string                  // most recent flow's At, for eviction + display
}

// Label is the process's display identity.
func (a appRow) Label() string {
	if a.App == "" {
		return "(unattributed)"
	}
	return a.App
}

// InterceptModel is the pure state of the Intercepted viewer: processes on the left, the selected
// process's running log on the right. No I/O touches it (§12); RunIntercepted feeds it flows.
//
// Processes are the axis because they are the STABLE one: a machine runs tens of them and the list only
// grows when a new pid speaks, so it holds still while you read. Flows are the fast, unbounded axis —
// pinning a cursor to "the newest flow" (an earlier design) means chasing a firehose.
type InterceptModel struct {
	Apps     []appRow
	Selected int    // index into visible()
	Scroll   int    // line offset into the selected process's log
	Follow   bool   // pin the log to its newest line
	Filter   string // narrows the PROCESS list (finding one among many), not the log
	Typing   bool   // the filter prompt owns the keys
	Status   string
}

func NewIntercept() InterceptModel { return InterceptModel{Follow: true} }

// withFlow files f under its originating process, creating that process's row only if the pid is new.
// This is the only way the left list grows.
func (m InterceptModel) withFlow(f model.InterceptedFlow) InterceptModel {
	i := m.indexOf(f.PID)
	if i < 0 {
		if len(m.Apps) >= maxApps {
			m = m.evictStalest()
		}
		m.Apps = append(m.Apps, appRow{PID: f.PID, App: f.App})
		i = len(m.Apps) - 1
	}
	row := m.Apps[i]
	if row.App == "" && f.App != "" {
		row.App = f.App // attribution can arrive on a later flow
	}
	// Insert by At, not arrival: a flow is PUBLISHED when its connection closes but STAMPED when it
	// opened, so a keep-alive flow lands after shorter ones that started later. The log is a timeline.
	at := sort.Search(len(row.Flows), func(j int) bool { return row.Flows[j].At > f.At })
	row.Flows = append(row.Flows, model.InterceptedFlow{})
	copy(row.Flows[at+1:], row.Flows[at:])
	row.Flows[at] = f
	if over := len(row.Flows) - maxAppLog; over > 0 {
		row.Flows = row.Flows[over:]
	}
	if f.At > row.LastAt {
		row.LastAt = f.At
	}
	m.Apps[i] = row
	m.Selected = clamp(m.Selected, len(m.visible()))
	return m
}

func (m InterceptModel) indexOf(pid int) int {
	for i, a := range m.Apps {
		if a.PID == pid {
			return i
		}
	}
	return -1
}

// evictStalest drops the least-recently-active process. Short-lived pids (each `curl` is a new one)
// would otherwise accumulate forever.
func (m InterceptModel) evictStalest() InterceptModel {
	if len(m.Apps) == 0 {
		return m
	}
	worst := 0
	for i, a := range m.Apps {
		if a.LastAt < m.Apps[worst].LastAt {
			worst = i
		}
	}
	m.Apps = append(m.Apps[:worst:worst], m.Apps[worst+1:]...)
	if m.Selected > worst {
		m.Selected--
	}
	return m
}

// visible is the processes the Filter admits. Filtering narrows which PROCESS you watch; it never drops
// captured flows — clearing it restores everything.
func (m InterceptModel) visible() []appRow {
	if m.Filter == "" {
		return m.Apps
	}
	q := strings.ToLower(m.Filter)
	out := make([]appRow, 0, len(m.Apps))
	for _, a := range m.Apps {
		if strings.Contains(strings.ToLower(a.Label()), q) || strings.Contains(itoa(a.PID), q) {
			out = append(out, a)
		}
	}
	return out
}

// selected returns the process currently being watched.
func (m InterceptModel) selected() (appRow, bool) {
	v := m.visible()
	if m.Selected < 0 || m.Selected >= len(v) {
		return appRow{}, false
	}
	return v[m.Selected], true
}

// interceptUpdate is the pure key handler: ↑↓ pick a process, PgUp/PgDn scroll its log, / find a
// process, f/G follow the newest line, g oldest, q quit.
func interceptUpdate(m InterceptModel, key tcell.Key, r rune) (InterceptModel, bool) {
	// The filter prompt owns every key while typing — otherwise 'q' in "squirrel" would quit.
	if m.Typing {
		switch key {
		case tcell.KeyEnter:
			m.Typing = false
		case tcell.KeyEscape:
			m.Typing, m.Filter = false, ""
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if m.Filter != "" {
				m.Filter = m.Filter[:len(m.Filter)-1]
			}
		default:
			if r != 0 {
				m.Filter += string(r)
			}
		}
		m.Selected = clamp(m.Selected, len(m.visible()))
		return m, false
	}
	switch {
	case key == tcell.KeyEscape:
		if m.Filter != "" {
			m.Filter = "" // Esc clears the filter before it quits — losing your place is worse than a keypress
			m.Selected = clamp(m.Selected, len(m.visible()))
			return m, false
		}
		return m, true
	case key == tcell.KeyCtrlC, r == 'q':
		return m, true
	case r == '/':
		m.Typing = true
		return m, false
	case key == tcell.KeyUp, r == 'k': // switching process shows its log from the newest line
		m.Selected--
		m.Scroll, m.Follow = 0, true
	case key == tcell.KeyDown, r == 'j':
		m.Selected++
		m.Scroll, m.Follow = 0, true
	case key == tcell.KeyPgDn:
		m.Scroll += 10
		m.Follow = false // scrolling back through the log means you want it to hold still
	case key == tcell.KeyPgUp:
		m.Scroll -= 10
		m.Follow = false
	case r == 'g': // oldest line of this process's log
		m.Scroll, m.Follow = 0, false
	case r == 'G', r == 'f': // newest line, and keep up with it
		m.Scroll, m.Follow = 0, true
	}
	m.Selected = clamp(m.Selected, len(m.visible()))
	if m.Scroll < 0 {
		m.Scroll = 0
	}
	return m, false
}

// interceptStatusStyle maps a flow status to its colour, glyph and label. Only `decrypted` reads as "we
// can see it"; the rest say honestly why we cannot, and must never look like success.
//
// The glyphs come from internal/mark — the single source of the glyph vocabulary — NOT from here. An
// earlier version invented them locally and collided with GlyphRevoked (⊘), so a pinned flow wore the
// mark for "revoked certificate". mark.Legend() is what makes a glyph decodable; a view-local glyph is
// undecodable by construction.
func interceptStatusStyle(status string) (tcell.Color, rune, string) {
	switch status {
	case model.FlowDecrypted:
		return colAccent, mark.GlyphDecrypted, "decrypted"
	case model.FlowPinned:
		return colWarn, mark.GlyphPinned, "pinned"
	case model.FlowOpaque:
		return colMonitor, mark.GlyphOpaque, "opaque"
	default:
		return colQuarantine, mark.GlyphFlowError, "error"
	}
}
