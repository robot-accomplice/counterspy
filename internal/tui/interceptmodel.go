package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/mark"
	"counterspy/internal/model"
)

// maxAppLog bounds one app's running log. Flows are the fast, unbounded axis; a long session must not
// grow forever, so the oldest are dropped.
const maxAppLog = 500

// appRow is one originating APP and its running log. The row identity is the process NAME, not a pid:
// pids are not stable (every `curl` run is a new one, every Safari helper is another), so a pid-keyed
// list accumulates dead entries and becomes an endless scroll — the opposite of a navigation pane. The
// Exfiltration monitor already collapses "every PID, port, and protocol of an app" into one row; this
// follows that convention. The pid stays visible per LOG LINE, where it is information, not navigation.
type appRow struct {
	App   string                  // "" = unattributed
	Flows []model.InterceptedFlow // oldest first, bounded by maxAppLog
}

// Label is the row's display identity.
func (a appRow) Label() string {
	if a.App == "" {
		return "(unattributed)"
	}
	return a.App
}

// InterceptModel is the pure state of the Intercepted viewer: apps on the left (navigation), the
// selected app's running log on the right. No I/O touches it (§12).
//
// There is deliberately NO follow flag. The log tails when Back == 0, which is simply where it starts;
// scrolling back sets Back > 0 and it holds still; scrolling to the bottom (or switching apps) returns
// Back to 0 and it tails again. "Following" is a position, not a mode the reader has to track.
type InterceptModel struct {
	Apps     []appRow
	Selected int    // index into visible()
	Back     int    // log lines scrolled back from the newest; 0 == tailing
	Filter   string // narrows the APP list (finding one among many), not the log
	Typing   bool   // the find prompt owns the keys
	Status   string
}

func NewIntercept() InterceptModel { return InterceptModel{} }

// withFlow files f under its originating app, creating that app's row only if the NAME is new. This is
// the only way the left list grows — and it grows per app, not per pid, so it stays navigable.
func (m InterceptModel) withFlow(f model.InterceptedFlow) InterceptModel {
	i := m.indexOf(f.App)
	if i < 0 {
		m.Apps = append(m.Apps, appRow{App: f.App})
		i = len(m.Apps) - 1
	}
	// If the reader is scrolled back in THIS app's log, keep them on the same content as it grows.
	before := 0
	watching := false
	if sel, ok := m.selected(); ok && sel.App == f.App && m.Back > 0 {
		watching = true
		before = len(logLines(sel))
	}

	row := m.Apps[i]
	// Insert by At, not arrival: a flow is PUBLISHED when its connection closes but STAMPED when it
	// opened, so a keep-alive flow lands after shorter ones that started later. The log is a timeline.
	at := sort.Search(len(row.Flows), func(j int) bool { return row.Flows[j].At > f.At })
	row.Flows = append(row.Flows, model.InterceptedFlow{})
	copy(row.Flows[at+1:], row.Flows[at:])
	row.Flows[at] = f
	if over := len(row.Flows) - maxAppLog; over > 0 {
		row.Flows = row.Flows[over:]
	}
	m.Apps[i] = row

	if watching {
		m.Back += len(logLines(row)) - before // the newest moved down; hold the reader's position
	}
	m.Selected = clamp(m.Selected, len(m.visible()))
	return m
}

func (m InterceptModel) indexOf(app string) int {
	for i, a := range m.Apps {
		if a.App == app {
			return i
		}
	}
	return -1
}

// visible is the apps the Filter admits. Filtering narrows which app you watch; it never drops captured
// flows — clearing it restores everything.
func (m InterceptModel) visible() []appRow {
	if m.Filter == "" {
		return m.Apps
	}
	q := strings.ToLower(m.Filter)
	out := make([]appRow, 0, len(m.Apps))
	for _, a := range m.Apps {
		if strings.Contains(strings.ToLower(a.Label()), q) {
			out = append(out, a)
		}
	}
	return out
}

// selected returns the app currently being watched.
func (m InterceptModel) selected() (appRow, bool) {
	v := m.visible()
	if m.Selected < 0 || m.Selected >= len(v) {
		return appRow{}, false
	}
	return v[m.Selected], true
}

// interceptUpdate is the pure key handler: ↑↓ pick an app, PgUp/PgDn walk its log, / find an app,
// q quit. There is no follow key, because there is no follow mode.
func interceptUpdate(m InterceptModel, key tcell.Key, r rune) (InterceptModel, bool) {
	// The find prompt owns every key while typing — otherwise 'q' in "squirrel" would quit.
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
	case key == tcell.KeyUp, r == 'k': // a different app starts at its newest line
		m.Selected--
		m.Back = 0
	case key == tcell.KeyDown, r == 'j':
		m.Selected++
		m.Back = 0
	case key == tcell.KeyPgUp: // walk back through the log; it stops tailing implicitly
		m.Back += 10
	case key == tcell.KeyPgDn: // walk forward; reaching the newest resumes tailing implicitly
		m.Back -= 10
	}
	m.Selected = clamp(m.Selected, len(m.visible()))
	if m.Back < 0 {
		m.Back = 0
	}
	if sel, ok := m.selected(); ok {
		if maxBack := len(logLines(sel)); m.Back > maxBack {
			m.Back = maxBack // can't scroll past the oldest line
		}
	}
	return m, false
}

// logLine is one rendered line of an app's running log, tagged so the view can colour it without
// re-deriving meaning at draw time.
type logLine struct {
	text string
	col  tcell.Color
	bold bool
	rule bool // a divider between packets; the view draws it across the pane
}

func (l logLine) style(def tcell.Style) tcell.Style {
	st := def.Foreground(l.col)
	if l.bold {
		st = st.Bold(true)
	}
	return st
}

// logLines flattens an app's flows into its running log: per flow, a header then its content, oldest
// first so the newest lands at the bottom like a tail. Derived here (not in the view) so the model can
// hold the reader's scroll position steady as the log grows.
func logLines(a appRow) []logLine {
	var out []logLine
	for i, f := range a.Flows {
		if i > 0 {
			out = append(out, logLine{rule: true}) // packets are separate things; show the seam
		}
		col, glyph, label := interceptStatusStyle(f.Status)
		dest := f.DestName
		if dest == "" {
			dest = f.DestIP
		}
		head := fmt.Sprintf("%s %c %s  ↑%d ↓%d", clockOf(f.At), glyph, dest, f.SentBytes, f.RecvBytes)
		if f.PID != 0 {
			head += fmt.Sprintf("  [pid %d]", f.PID) // the pid belongs here, not in the navigation
		}
		out = append(out, logLine{text: capLine(head), col: col, bold: true})
		if f.Status != model.FlowDecrypted {
			// Say WHY there is no content rather than leaving a bare header the reader must interpret.
			out = append(out, logLine{text: "   " + capLine(whyNoContent(label)), col: colDim})
			continue
		}
		out = append(out, bodyLines("→", f.SentText, f.SentBytes)...)
		out = append(out, bodyLines("←", f.RecvText, f.RecvBytes)...)
	}
	return out
}

// bodyLines renders one direction's masked content in FULL — every captured line is emitted, and the log
// scrolls (PgUp/PgDn), so nothing is unreachable. An earlier version capped the display at 8 lines and
// printed "… (N more lines)", which was unreachable AND a lie: the proxy also caps what it CAPTURES at
// model.FlowCaptureBytes per direction, so for a 26KB post most of those "more lines" were never
// captured at all. wireBytes is the TRUE byte count from the wire; when it exceeds the capture cap we say
// so explicitly rather than implying the rest is merely hidden.
//
// The raw text is split BEFORE cleaning: report.Clean (via drawText) strips control bytes INCLUDING
// newlines, so cleaning first would collapse a whole body onto one line.
func bodyLines(arrow, raw string, wireBytes int) []logLine {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	src := strings.Split(raw, "\n")
	out := make([]logLine, 0, len(src)+1)
	for i, ln := range src {
		prefix := "     "
		if i == 0 {
			prefix = "   " + arrow + " "
		}
		out = append(out, logLine{text: capLine(prefix + ln), col: colText})
	}
	if wireBytes > model.FlowCaptureBytes {
		out = append(out, logLine{
			text: fmt.Sprintf("     ⋯ capture truncated: this is the first %s of %s on the wire — the rest was never captured",
				byteSize(model.FlowCaptureBytes), byteSize(wireBytes)),
			col: colWarn,
		})
	}
	return out
}

// byteSize renders a byte count compactly for the truncation notice.
func byteSize(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	if n >= 1<<10 {
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func capLine(s string) string { return truncate(s, logMaxWidth) }

// whyNoContent states plainly why a flow carries no plaintext — the log must never imply content it
// does not have.
func whyNoContent(label string) string {
	switch label {
	case "pinned":
		return "pinned — this app rejected our leaf and was BYPASSED; its traffic reached the real server untouched"
	case "opaque":
		return "opaque — not interceptable (the bytes were not TLS we could terminate)"
	default:
		return "error — a capture/relay error; the connection was not tampered with"
	}
}

// clockOf renders an RFC3339 stamp as HH:MM:SS (the date is noise in a live view).
func clockOf(at string) string {
	if i := strings.IndexByte(at, 'T'); i >= 0 && len(at) >= i+9 {
		return at[i+1 : i+9]
	}
	return truncate(at, 8)
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
