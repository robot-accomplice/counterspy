package tui

import (
	"github.com/gdamore/tcell/v2"
)

// Layout + display bounds.
const (
	interceptListWidth = 30 // the app column (navigation); the rest is the running log
	// logFlowLines caps how many content lines ONE flow contributes, so a 26KB telemetry POST can't
	// bury the flows around it. PgUp walks the log; the cap keeps it scannable.
	logFlowLines = 8
	// logMaxWidth caps a single line so one enormous header can't push the pane sideways.
	logMaxWidth = 200
)

// interceptView draws the Intercepted viewer: originating APPS on the left (navigation — a short,
// stable list), the selected app's running log on the right. Content is already Redact-masked by the
// proxy; drawText additionally Cleans control bytes at draw time (defense in depth).
func interceptView(m InterceptModel, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	def := tcell.StyleDefault

	x := drawText(s, 2, 0, def.Foreground(colAccent).Bold(true), "CounterSpy")
	x = drawText(s, x+2, 0, def.Foreground(colAccent).Bold(true), "Intercepted")
	vis := m.visible()
	count := "· " + itoa(len(m.Apps)) + " apps"
	if m.Filter != "" {
		count = "· " + itoa(len(vis)) + " of " + itoa(len(m.Apps)) + " apps"
	}
	drawText(s, x+2, 0, def.Foreground(colDim), count)

	listW := interceptListWidth
	if w < listW*2 {
		listW = w / 2
	}
	for y := 1; y < h-1; y++ {
		s.SetContent(listW, y, '│', nil, def.Foreground(colDivider))
	}
	drawAppList(m, s, listW, h)
	drawAppLog(m, s, listW+2, w, h)
	drawInterceptFooter(m, s, w, h)
}

// drawAppList renders the apps — the navigation axis. One row per process NAME, first-seen ordered and
// never re-sorted, so the busiest app doesn't jump to the top and a new one doesn't move your cursor.
func drawAppList(m InterceptModel, s tcell.Screen, listW, h int) {
	def := tcell.StyleDefault
	vis := m.visible()
	rows := h - 3
	if rows < 1 || len(vis) == 0 {
		switch {
		case len(m.Apps) == 0:
			drawText(s, 2, 2, def.Foreground(colDim), "waiting for flows…")
		case m.Filter != "":
			drawText(s, 2, 2, def.Foreground(colWarn), truncate("no app matches "+m.Filter, listW-4))
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
		n := itoa(len(a.Flows))
		drawText(s, 2, y, nameSt, truncate(a.Label(), listW-len(n)-4))
		drawText(s, listW-len(n)-1, y, st.Foreground(colDim), n)
	}
}

// drawAppLog renders the selected app's running log, newest at the BOTTOM like a tail. Back is the
// reader's position: 0 means the newest line is on screen (tailing) — there is no mode to toggle.
func drawAppLog(m InterceptModel, s tcell.Screen, x0, w, h int) {
	def := tcell.StyleDefault
	a, ok := m.selected()
	if !ok {
		return
	}
	width := w - x0 - 1
	lines := logLines(a)
	rows := h - 3
	if rows < 1 {
		return
	}
	if len(lines) == 0 {
		drawText(s, x0, 2, def.Foreground(colDim), "no flows from this app yet")
		return
	}
	// The window ends `Back` lines above the newest.
	end := len(lines) - m.Back
	if end > len(lines) {
		end = len(lines)
	}
	if end < 1 {
		end = 1
	}
	start := end - rows
	if start < 0 {
		start = 0
	}
	y := 2
	for i := start; i < end && y < h-1; i++ {
		drawText(s, x0, y, lines[i].style(def), truncate(lines[i].text, width))
		y++
	}
	if end < len(lines) { // scrolled back — say so where it's read, not as a mode in the header
		drawText(s, x0, h-2, def.Foreground(colDim), truncate("↓ "+itoa(len(lines)-end)+" newer lines (PgDn)", width))
	}
}

func drawInterceptFooter(m InterceptModel, s tcell.Screen, w, h int) {
	def := tcell.StyleDefault
	if m.Typing {
		p := drawText(s, 2, h-1, def.Foreground(colAccent), "find app: ")
		p = drawText(s, p, h-1, def.Foreground(colText), truncate(m.Filter, w-20))
		s.SetContent(p, h-1, '▏', nil, def.Foreground(colAccent))
		s.ShowCursor(p, h-1)
		return
	}
	s.HideCursor()
	hints := "↑↓ app · PgUp/PgDn log · / find · q quit"
	if m.Filter != "" {
		hints = "Esc clear filter · " + hints
	}
	if m.Status != "" {
		hints = m.Status + " · " + hints
	}
	drawText(s, 2, h-1, def.Foreground(colDim), truncate(hints, w-4))
}
