package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
)

// interceptListWidth is the flow-list column width; the rest is the detail pane.
const interceptListWidth = 46

// interceptView draws the Intercepted viewer: a time-ordered flow list on the left, the selected
// flow's decoded + masked request/response on the right. Content is already Redact-masked by the
// proxy; drawText additionally Cleans control bytes at draw time (defense in depth).
func interceptView(m InterceptModel, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	def := tcell.StyleDefault

	x := drawText(s, 2, 0, def.Foreground(colAccent).Bold(true), "CounterSpy")
	x = drawText(s, x+2, 0, def.Foreground(colAccent).Bold(true), "Intercepted")
	vis := m.visible()
	count := fmt.Sprintf("· %d flows", len(m.Flows))
	if m.Filter != "" {
		count = fmt.Sprintf("· %d of %d flows", len(vis), len(m.Flows))
	}
	x = drawText(s, x+2, 0, def.Foreground(colDim), count)
	if m.Filter != "" {
		x = drawText(s, x+2, 0, def.Foreground(colWarn), "· tailing "+truncate(m.Filter, 24))
	}
	if m.Follow {
		drawText(s, x+2, 0, def.Foreground(colAccent), "· following")
	} else {
		drawText(s, x+2, 0, def.Foreground(colWarn), "· paused (f to follow)")
	}

	listW := interceptListWidth
	if w < listW*2 {
		listW = w / 2 // narrow terminal: split evenly rather than squeezing the detail to nothing
	}
	for y := 1; y < h-1; y++ {
		s.SetContent(listW, y, '│', nil, def.Foreground(colDivider))
	}

	drawInterceptList(m, s, listW, h)
	drawInterceptDetail(m, s, listW+2, w, h)

	if m.Typing {
		p := drawText(s, 2, h-1, def.Foreground(colAccent), "tail source: ")
		p = drawText(s, p, h-1, def.Foreground(colText), truncate(m.Filter, w-20))
		s.SetContent(p, h-1, '▏', nil, def.Foreground(colAccent))
		s.ShowCursor(p, h-1)
		return
	}
	s.HideCursor()
	hints := "/ tail a source · ↑↓ select · PgUp/PgDn scroll · f follow · g/G ends · q quit"
	if m.Filter != "" {
		hints = "Esc clear filter · " + hints
	}
	if m.Status != "" {
		hints = m.Status + " · " + hints
	}
	drawText(s, 2, h-1, def.Foreground(colDim), truncate(hints, w-4))
}

// drawInterceptList renders the time-ordered flows, windowed around the selection.
func drawInterceptList(m InterceptModel, s tcell.Screen, listW, h int) {
	def := tcell.StyleDefault
	vis := m.visible()
	rows := h - 3
	if rows < 1 || len(vis) == 0 {
		switch {
		case len(m.Flows) == 0:
			drawText(s, 2, 2, def.Foreground(colDim), "waiting for flows…")
		case m.Filter != "":
			// Say the filter is hiding them — an empty list must not read as "nothing is happening".
			drawText(s, 2, 2, def.Foreground(colWarn), truncate("no flows match "+m.Filter, listW-4))
			drawText(s, 2, 3, def.Foreground(colDim), "Esc clears the filter")
		}
		return
	}
	top := 0
	if m.Selected >= rows {
		top = m.Selected - rows + 1
	}
	for i := 0; i < rows && top+i < len(vis); i++ {
		fl := vis[top+i]
		y := i + 2
		st := def
		if top+i == m.Selected {
			st = def.Background(colSelBg)
			for cx := 0; cx < listW; cx++ {
				s.SetContent(cx, y, ' ', nil, st)
			}
			s.SetContent(0, y, '▌', nil, def.Foreground(colSelBar).Background(colSelBg))
		}
		col, _ := interceptStatusStyle(fl.Status)
		drawText(s, 2, y, st.Foreground(colDim), clockOf(fl.At))
		s.SetContent(11, y, statusGlyph(fl.Status), nil, st.Foreground(col))
		// The APP is the headline — "what is THIS app sending" is the question the tool asks.
		app := fl.App
		if app == "" {
			app = "(unattributed)"
			st = st.Foreground(colDim)
		}
		drawText(s, 13, y, st.Foreground(colText).Bold(true), truncate(app, 16))
		name := fl.DestName
		if name == "" {
			name = fl.DestIP
		}
		drawText(s, 30, y, st.Foreground(colDim), truncate(name, listW-31))
	}
}

// clockOf renders an RFC3339 stamp as HH:MM:SS (the date is noise in a live view).
func clockOf(at string) string {
	if i := strings.IndexByte(at, 'T'); i >= 0 && len(at) >= i+9 {
		return at[i+1 : i+9]
	}
	return truncate(at, 8)
}

// drawInterceptDetail renders the selected flow: its metadata, then the masked request/response. A
// non-decrypted flow shows WHY there is no content instead of an empty pane.
func drawInterceptDetail(m InterceptModel, s tcell.Screen, x0, w, h int) {
	def := tcell.StyleDefault
	fl, ok := m.selected()
	if !ok {
		return
	}
	width := w - x0 - 1
	y := 2
	col, label := interceptStatusStyle(fl.Status)
	name := fl.DestName
	if name == "" {
		name = fl.DestIP
	}
	drawText(s, x0, y, def.Foreground(colText).Bold(true), truncate(name, width))
	y++
	who := "(unattributed — the owning process could not be identified)"
	if fl.App != "" {
		who = fmt.Sprintf("%s (pid %d)", fl.App, fl.PID)
	}
	drawText(s, x0, y, def.Foreground(colAccent), truncate(who, width))
	y++
	meta := fmt.Sprintf("%s · ↑%d ↓%d", fl.At, fl.SentBytes, fl.RecvBytes)
	if fl.DestIP != "" && fl.DestIP != name {
		meta += " · " + fl.DestIP
	}
	if fl.SNI != "" && fl.SNI != name {
		meta += " · SNI " + fl.SNI
	}
	drawText(s, x0, y, def.Foreground(colDim), truncate(meta, width))
	y += 2
	drawText(s, x0, y, def.Foreground(col), label)
	y += 2

	if fl.Status != "decrypted" {
		drawText(s, x0, y, def.Foreground(colDim), truncate(interceptWhyNoContent(fl.Status), width))
		return
	}
	// Build the body once, then window it by Scroll.
	var lines []string
	add := func(head, body string) {
		if strings.TrimSpace(body) == "" {
			return
		}
		lines = append(lines, head)
		lines = append(lines, strings.Split(body, "\n")...)
		lines = append(lines, "")
	}
	add("→ request", fl.SentText)
	add("← response", fl.RecvText)
	if len(lines) == 0 {
		drawText(s, x0, y, def.Foreground(colDim), "decrypted, but no text payload captured")
		return
	}
	start := clamp(m.Scroll, len(lines))
	for i := start; i < len(lines) && y < h-1; i++ {
		st := def.Foreground(colText)
		if strings.HasPrefix(lines[i], "→ ") || strings.HasPrefix(lines[i], "← ") {
			st = def.Foreground(colAccent).Bold(true)
		}
		drawText(s, x0, y, st, truncate(lines[i], width))
		y++
	}
	if start+1 < len(lines) && y >= h-1 {
		drawText(s, x0, h-2, def.Foreground(colDim), "… PgDn for more")
	}
}

// interceptWhyNoContent states plainly why a flow carries no plaintext — the viewer must never imply
// content it does not have.
func interceptWhyNoContent(status string) string {
	switch status {
	case "pinned":
		return "This app pins its certificates and rejected our leaf, so it was BYPASSED — not decrypted.\nIts traffic reached the real server untouched; we can see that it happened, not what it said."
	case "opaque":
		return "Not interceptable (the bytes were not TLS we could terminate)."
	default:
		return "A capture/relay error occurred; the connection was not tampered with."
	}
}

// statusGlyph is the one-column status marker for the app-led list (the word form stays in the detail
// pane). Only decrypted reads as "we can see it".
func statusGlyph(status string) rune {
	switch status {
	case "decrypted":
		return '◉'
	case "pinned":
		return '⊘'
	case "opaque":
		return '▢'
	default:
		return '✗'
	}
}
