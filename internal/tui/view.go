package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func drawText(s tcell.Screen, x, y int, style tcell.Style, text string) int {
	for _, r := range text {
		s.SetContent(x, y, r, nil, style)
		x++
	}
	return x
}

func tierColor(r model.Recommendation) tcell.Color {
	switch r {
	case model.RecQuarantine:
		return colQuarantine
	case model.RecInvestigate:
		return colInvestigate
	default:
		return colMonitor
	}
}

// view draws the whole UI to the screen. tcell I/O only — no state changes.
func view(m Model, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	def := tcell.StyleDefault.Foreground(colText)
	q, inv, mon := m.counts()

	drawText(s, 2, 0, def.Foreground(colAccent).Bold(true), "CounterSpy")
	drawText(s, 2, 1, def.Foreground(colQuarantine), fmt.Sprintf("● %d Quarantine", q))
	drawText(s, 20, 1, def.Foreground(colInvestigate), fmt.Sprintf("▲ %d Investigate", inv))
	drawText(s, 40, 1, def.Foreground(colMonitor), fmt.Sprintf("· %d Monitor", mon))
	row := 2
	for _, g := range m.Gaps {
		drawText(s, 2, row, def.Foreground(colInvestigate), "⚠ "+g)
		row++
	}

	split := w / 2
	vis := m.visible()
	listTop := row + 1
	if m.Focus == focusFilter {
		drawText(s, 2, row, def.Foreground(colAccent), "/"+m.Filter+"_")
		listTop = row + 2
	}
	for i, a := range vis {
		y := listTop + i
		if y >= h-1 {
			break
		}
		st := def.Foreground(tierColor(a.Recommendation))
		if i == m.Selected {
			st = st.Reverse(true)
		}
		name := a.Subject.Display()
		if m.Done[a.Subject.Key()] {
			name = "✓ " + name
		}
		line := fmt.Sprintf(" %-11s %-28s %5d", strings.ToUpper(string(a.Recommendation)), truncate(name, 28), a.Score)
		drawText(s, 0, y, st, truncate(line, split-1))
	}
	if len(vis) == 0 {
		drawText(s, 2, listTop, def.Foreground(colDim), "no findings match")
	}

	if len(vis) > 0 && m.Selected < len(vis) {
		drawDetail(s, split+2, listTop, w-split-3, vis[m.Selected])
	}

	drawText(s, 2, h-1, def.Foreground(colDim),
		"j/k move · q quarantine · u restore · m monitor · s sort · / filter · ? help · Q quit")
	if m.Toast != "" {
		drawText(s, 2, h-2, def.Foreground(colAccent), truncate(m.Toast, w-4))
	}

	if m.Focus == focusModal {
		drawModal(s, m.Pending)
	}
	if m.Focus == focusHelp {
		drawHelp(s)
	}
}

func drawDetail(s tcell.Screen, x, y, wdt int, a model.Assessment) {
	def := tcell.StyleDefault.Foreground(colText)
	drawText(s, x, y, def.Bold(true), truncate(a.Subject.Display(), wdt))
	drawText(s, x, y+1, def.Foreground(colDim), truncate(a.Category+" · score "+itoa(a.Score), wdt))
	drawText(s, x, y+3, def, truncate(a.Verdict, wdt))
	yy := y + 5
	if a.Tripwire != "" {
		drawText(s, x, yy, def.Foreground(colQuarantine), truncate("⚠ tripwire: "+a.Tripwire, wdt))
		yy += 2
	}
	drawText(s, x, yy, def.Foreground(colDim), "EVIDENCE")
	for i, e := range a.Evidence {
		drawText(s, x, yy+1+i, def, truncate(string(e.Kind)+"  "+e.Summary, wdt))
	}
}

func drawBox(s tcell.Screen, x0, y0, bw, bh int) tcell.Style {
	box := tcell.StyleDefault.Foreground(colText).Background(tcell.NewRGBColor(20, 26, 33))
	for y := y0; y < y0+bh; y++ {
		for x := x0; x < x0+bw; x++ {
			s.SetContent(x, y, ' ', nil, box)
		}
	}
	return box
}

func drawModal(s tcell.Screen, a model.Assessment) {
	w, h := s.Size()
	bw, bh := 60, 8
	x0, y0 := (w-bw)/2, (h-bh)/2
	box := drawBox(s, x0, y0, bw, bh)
	drawText(s, x0+2, y0+1, box.Bold(true), truncate("Quarantine "+a.Subject.Display()+"?", bw-4))
	drawText(s, x0+2, y0+3, box.Foreground(colAccent), truncate("↺ reversible — moves, never deletes; undo with restore", bw-4))
	drawText(s, x0+2, y0+5, box.Foreground(colQuarantine), "[Enter] Quarantine")
	drawText(s, x0+24, y0+5, box.Foreground(colDim), "[Esc] Cancel")
}

func drawHelp(s tcell.Screen) {
	rows := []string{
		"Keys", "",
		"j / k, ↑/↓   move selection",
		"q            quarantine (confirm)",
		"u            restore this session's quarantine",
		"m            show / hide Monitor tier",
		"s            sort by score / recommendation",
		"/            filter by name   ·   esc clears",
		"?            toggle this help",
		"Q, Ctrl-C    quit",
	}
	w, h := s.Size()
	bw, bh := 52, len(rows)+2
	x0, y0 := (w-bw)/2, (h-bh)/2
	box := drawBox(s, x0, y0, bw, bh)
	for i, r := range rows {
		st := box
		if i == 0 {
			st = box.Foreground(colAccent).Bold(true)
		}
		drawText(s, x0+2, y0+1+i, st, truncate(r, bw-4))
	}
}

func truncate(s string, n int) string {
	if n < 0 {
		n = 0
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
