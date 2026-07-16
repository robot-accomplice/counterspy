package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
)

// Layout + display bounds.
const (
	interceptListWidth = 34 // the process column; the rest is the running log
	// logFlowLines caps how many content lines ONE flow contributes to the log, so a 26KB telemetry POST
	// can't bury the flows around it. PgUp/PgDn walks the log; the cap keeps it scannable.
	logFlowLines = 8
	// logMaxWidth caps a single line so one enormous header can't push the pane sideways.
	logMaxWidth = 200
)

// interceptView draws the Intercepted viewer: originating processes on the left, the selected process's
// running log on the right. Content is already Redact-masked by the proxy; drawText additionally Cleans
// control bytes at draw time (defense in depth).
func interceptView(m InterceptModel, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	def := tcell.StyleDefault

	x := drawText(s, 2, 0, def.Foreground(colAccent).Bold(true), "CounterSpy")
	x = drawText(s, x+2, 0, def.Foreground(colAccent).Bold(true), "Intercepted")
	vis := m.visible()
	count := fmt.Sprintf("· %d processes", len(m.Apps))
	if m.Filter != "" {
		count = fmt.Sprintf("· %d of %d processes", len(vis), len(m.Apps))
	}
	x = drawText(s, x+2, 0, def.Foreground(colDim), count)
	if m.Follow {
		drawText(s, x+2, 0, def.Foreground(colAccent), "· following")
	} else {
		drawText(s, x+2, 0, def.Foreground(colWarn), "· scrolled back (f/G to follow)")
	}

	listW := interceptListWidth
	if w < listW*2 {
		listW = w / 2
	}
	for y := 1; y < h-1; y++ {
		s.SetContent(listW, y, '│', nil, def.Foreground(colDivider))
	}
	drawProcessList(m, s, listW, h)
	drawProcessLog(m, s, listW+2, w, h)
	drawInterceptFooter(m, s, w, h)
}

// drawProcessList renders the originating processes — the STABLE axis. Rows are first-seen ordered and
// never move, so watching one process doesn't mean chasing it around the list.
func drawProcessList(m InterceptModel, s tcell.Screen, listW, h int) {
	def := tcell.StyleDefault
	vis := m.visible()
	rows := h - 3
	if rows < 1 || len(vis) == 0 {
		switch {
		case len(m.Apps) == 0:
			drawText(s, 2, 2, def.Foreground(colDim), "waiting for flows…")
		case m.Filter != "":
			drawText(s, 2, 2, def.Foreground(colWarn), truncate("no process matches "+m.Filter, listW-4))
			drawText(s, 2, 3, def.Foreground(colDim), "Esc clears")
		}
		return
	}
	top := 0
	if m.Selected >= rows {
		top = m.Selected - rows + 1
	}
	for i := 0; i < rows && top+i < len(vis); i++ {
		a := vis[top+i]
		y := i + 2
		st := def
		if top+i == m.Selected {
			st = def.Background(colSelBg)
			for cx := 0; cx < listW; cx++ {
				s.SetContent(cx, y, ' ', nil, st)
			}
			s.SetContent(0, y, '▌', nil, def.Foreground(colSelBar).Background(colSelBg))
		}
		nameSt := st.Foreground(colText).Bold(true)
		if a.App == "" {
			nameSt = st.Foreground(colDim)
		}
		drawText(s, 2, y, nameSt, truncate(a.Label(), listW-14))
		// pid + flow count: the pid identifies it, the count says how loud it is.
		meta := itoa(a.PID) + " " + itoa(len(a.Flows))
		if a.PID == 0 {
			meta = "- " + itoa(len(a.Flows))
		}
		drawText(s, listW-len(meta)-1, y, st.Foreground(colDim), meta)
	}
}

// drawProcessLog renders the selected process's running log: newest at the BOTTOM, like a tail. Each
// flow contributes a header (time · status · destination · bytes) and its masked content.
func drawProcessLog(m InterceptModel, s tcell.Screen, x0, w, h int) {
	def := tcell.StyleDefault
	a, ok := m.selected()
	if !ok {
		return
	}
	width := w - x0 - 1
	who := "(unattributed — the owning process could not be identified)"
	if a.App != "" {
		who = a.App + " (pid " + itoa(a.PID) + ")"
	}
	drawText(s, x0, 1, def.Foreground(colAccent).Bold(true), truncate(who, width))

	lines := logLines(a)
	rows := h - 4
	if rows < 1 {
		return
	}
	if len(lines) == 0 {
		drawText(s, x0, 3, def.Foreground(colDim), "no flows from this process yet")
		return
	}
	// Follow pins the view to the newest line (a tail); scrolling back holds it still.
	start := 0
	if m.Follow {
		if len(lines) > rows {
			start = len(lines) - rows
		}
	} else {
		start = clamp(m.Scroll, len(lines))
	}
	y := 3
	for i := start; i < len(lines) && y < h-1; i++ {
		drawText(s, x0, y, lines[i].style(def), truncate(lines[i].text, width))
		y++
	}
}

// logLine is one rendered line of a process's running log, tagged so the view can colour it without
// re-deriving meaning at draw time.
type logLine struct {
	text string
	col  tcell.Color
	bold bool
}

func (l logLine) style(def tcell.Style) tcell.Style {
	st := def.Foreground(l.col)
	if l.bold {
		st = st.Bold(true)
	}
	return st
}

// logLines flattens a process's flows into the running log: per flow, a header then its content.
// Oldest first, so the newest lands at the bottom like a tail.
func logLines(a appRow) []logLine {
	var out []logLine
	for _, f := range a.Flows {
		col, glyph, label := interceptStatusStyle(f.Status)
		dest := f.DestName
		if dest == "" {
			dest = f.DestIP
		}
		head := fmt.Sprintf("%s %c %s  ↑%d ↓%d", clockOf(f.At), glyph, dest, f.SentBytes, f.RecvBytes)
		out = append(out, logLine{text: capLine(head), col: col, bold: true})
		if f.Status != "decrypted" {
			// Say WHY there is no content rather than leaving a bare header the reader must interpret.
			out = append(out, logLine{text: "   " + capLine(whyNoContent(label)), col: colDim})
			continue
		}
		out = append(out, bodyLines("→", f.SentText)...)
		out = append(out, bodyLines("←", f.RecvText)...)
	}
	return out
}

// bodyLines renders one direction's masked content, arrow-marking the first line and capping the rest.
// The raw text is split BEFORE cleaning: report.Clean (via drawText) strips control bytes INCLUDING
// newlines, so cleaning first would collapse a whole body onto one line.
func bodyLines(arrow, raw string) []logLine {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	src := strings.Split(raw, "\n")
	var out []logLine
	for i, ln := range src {
		if i >= logFlowLines {
			out = append(out, logLine{text: fmt.Sprintf("     … (%d more lines)", len(src)-logFlowLines), col: colDim})
			break
		}
		prefix := "     "
		if i == 0 {
			prefix = "   " + arrow + " "
		}
		out = append(out, logLine{text: capLine(prefix + ln), col: colText})
	}
	return out
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

func drawInterceptFooter(m InterceptModel, s tcell.Screen, w, h int) {
	def := tcell.StyleDefault
	if m.Typing {
		p := drawText(s, 2, h-1, def.Foreground(colAccent), "find process: ")
		p = drawText(s, p, h-1, def.Foreground(colText), truncate(m.Filter, w-20))
		s.SetContent(p, h-1, '▏', nil, def.Foreground(colAccent))
		s.ShowCursor(p, h-1)
		return
	}
	s.HideCursor()
	hints := "↑↓ process · PgUp/PgDn scroll log · g/G ends · f follow · / find · q quit"
	if m.Filter != "" {
		hints = "Esc clear filter · " + hints
	}
	if m.Status != "" {
		hints = m.Status + " · " + hints
	}
	drawText(s, 2, h-1, def.Foreground(colDim), truncate(hints, w-4))
}
