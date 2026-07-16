package tui

import (
	"sort"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// maxInterceptFlows bounds retained flows: a live session on a busy machine publishes without limit,
// and the viewer must not grow forever. Oldest are dropped.
const maxInterceptFlows = 2000

// InterceptModel is the pure state of the Intercepted viewer — the flows seen so far in TIME order,
// the selection, and the detail scroll. No I/O touches it (§12); RunIntercepted feeds it flows.
type InterceptModel struct {
	Flows    []model.InterceptedFlow // sorted by At (flow start), oldest first
	Selected int                     // index into Flows
	Scroll   int                     // detail-pane scroll offset
	Follow   bool                    // stick to the newest flow as they arrive
	Status   string
}

func NewIntercept() InterceptModel { return InterceptModel{Follow: true} }

// withFlow inserts f in At order and returns the new model.
//
// Sorting by At (not by arrival) is deliberate: a flow is PUBLISHED when its connection closes but
// stamped when it opened, so a long keep-alive connection arrives long after shorter ones that started
// later. Appending in arrival order therefore prints 14:44:58 above 14:44:28 — real output from the
// first live run, and genuinely confusing to read. Insertion keeps the list a true timeline; the
// selection follows its flow across the insert so the view never jumps under the reader.
func (m InterceptModel) withFlow(f model.InterceptedFlow) InterceptModel {
	at := sort.Search(len(m.Flows), func(i int) bool { return m.Flows[i].At > f.At })
	m.Flows = append(m.Flows, model.InterceptedFlow{})
	copy(m.Flows[at+1:], m.Flows[at:])
	m.Flows[at] = f
	if at <= m.Selected && len(m.Flows) > 1 {
		m.Selected++ // keep the SAME flow selected when one lands above it
	}
	if over := len(m.Flows) - maxInterceptFlows; over > 0 {
		m.Flows = m.Flows[over:]
		m.Selected -= over
	}
	if m.Follow {
		m.Selected = len(m.Flows) - 1 // newest
		m.Scroll = 0
	}
	m.Selected = clamp(m.Selected, len(m.Flows))
	return m
}

// selected returns the currently selected flow, ok=false when there are none yet.
func (m InterceptModel) selected() (model.InterceptedFlow, bool) {
	if m.Selected < 0 || m.Selected >= len(m.Flows) {
		return model.InterceptedFlow{}, false
	}
	return m.Flows[m.Selected], true
}

// interceptUpdate is the pure key handler: navigate the list, scroll the detail, toggle follow, quit.
func interceptUpdate(m InterceptModel, key tcell.Key, r rune) (InterceptModel, bool) {
	switch {
	case key == tcell.KeyEscape, key == tcell.KeyCtrlC, r == 'q':
		return m, true
	case key == tcell.KeyUp, r == 'k':
		m.Selected--
		m.Follow = false // moving off the newest means the reader is browsing; stop yanking them back
		m.Scroll = 0
	case key == tcell.KeyDown, r == 'j':
		m.Selected++
		m.Scroll = 0
		m.Follow = m.Selected >= len(m.Flows)-1 // stepping onto the newest resumes following
	case key == tcell.KeyHome, r == 'g':
		m.Selected, m.Scroll, m.Follow = 0, 0, false
	case key == tcell.KeyEnd, r == 'G':
		m.Selected, m.Scroll, m.Follow = len(m.Flows)-1, 0, true
	case key == tcell.KeyPgDn:
		m.Scroll += 10
	case key == tcell.KeyPgUp:
		m.Scroll -= 10
	case r == 'f':
		m.Follow = !m.Follow
		if m.Follow {
			m.Selected = len(m.Flows) - 1
			m.Scroll = 0
		}
	}
	m.Selected = clamp(m.Selected, len(m.Flows))
	if m.Scroll < 0 {
		m.Scroll = 0
	}
	return m, false
}

// interceptStatusStyle maps a flow status to its colour + label. Only `decrypted` reads as "we can see
// it"; the rest say honestly why we cannot, and must never look like success.
func interceptStatusStyle(status string) (tcell.Color, string) {
	switch status {
	case model.FlowDecrypted:
		return colAccent, "decrypted"
	case model.FlowPinned:
		return colWarn, "pinned"
	case model.FlowOpaque:
		return colMonitor, "opaque"
	default:
		return colQuarantine, "error"
	}
}
