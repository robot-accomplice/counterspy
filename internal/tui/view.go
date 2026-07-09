package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func drawText(s tcell.Screen, x, y int, style tcell.Style, text string) int {
	for _, r := range model.Clean(text) {
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

	// Header: name + read-only badge.
	x := drawText(s, 2, 0, def.Foreground(colAccent).Bold(true), "CounterSpy")
	if m.ReadOnly {
		drawText(s, x+2, 0, def.Foreground(colWarn), "TRIAGE ONLY — snapshot, quarantine disabled")
	}
	// Counts, chained so widths never collide.
	x = drawText(s, 2, 1, def.Foreground(colQuarantine), fmt.Sprintf("● %d Quarantine", q))
	x = drawText(s, x+3, 1, def.Foreground(colInvestigate), fmt.Sprintf("▲ %d Investigate", inv))
	drawText(s, x+3, 1, def.Foreground(colMonitor), fmt.Sprintf("· %d Monitor", mon))

	row := 2
	for _, g := range m.Gaps {
		drawText(s, 2, row, def.Foreground(colWarn), "⚠ "+g)
		row++
	}
	if q > 0 && m.doneCount(model.RecQuarantine) >= q {
		drawText(s, 2, row, def.Foreground(colAccent), "✓ all Quarantine-tier items handled — review Investigate, or rescan")
		row++
	}

	// Panel labels + layout. Reserve the last two rows for footer (h-1) and toast (h-2).
	split := w / 2
	labelRow := row
	drawText(s, 2, labelRow, def.Foreground(colDim), "FINDINGS")
	drawText(s, split+2, labelRow, def.Foreground(colDim), "DETAIL")
	listTop := labelRow + 1
	contentBottom := h - 3
	if contentBottom < listTop {
		drawText(s, 2, listTop-1, def.Foreground(colWarn), "terminal too small — resize")
		return
	}
	for y := listTop; y <= contentBottom; y++ {
		s.SetContent(split, y, '│', nil, def.Foreground(colDivider))
	}

	vis := m.visible()
	visibleRows := contentBottom - listTop + 1
	// Viewport: keep the selection on-screen (stateless clamp).
	scrollTop := 0
	if m.Selected >= visibleRows {
		scrollTop = m.Selected - visibleRows + 1
	}
	for i := scrollTop; i < len(vis) && i < scrollTop+visibleRows; i++ {
		drawListRow(s, listTop+(i-scrollTop), split, i == m.Selected, m.Done[vis[i].Subject.Key()], vis[i])
	}
	if len(vis) == 0 {
		if !m.ShowMonitor && mon > 0 {
			drawText(s, 2, listTop, def.Foreground(colDim), fmt.Sprintf("nothing needs your attention — %d monitored item(s) hidden (press m)", mon))
		} else {
			drawText(s, 2, listTop, def.Foreground(colDim), "no findings match")
		}
	} else if m.Selected < len(vis) {
		drawDetail(s, split+2, listTop, contentBottom, w-split-3, vis[m.Selected])
	}

	drawText(s, 2, h-1, def.Foreground(colDim), truncate(
		"j/k move · q quarantine · u restore · m monitor · s sort · / filter · ? help · Q quit", w-3))
	if m.Focus == focusFilter {
		drawText(s, 2, h-1, def.Foreground(colAccent), truncate("/"+m.Filter+"_  (esc clears)", w-3))
	}
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

// drawListRow renders one finding row within the left pane [0, split).
func drawListRow(s tcell.Screen, y, split int, selected, done bool, a model.Assessment) {
	fg := tierColor(a.Recommendation)
	if done {
		fg = colDim
	}
	st := tcell.StyleDefault.Foreground(fg)
	if selected {
		st = st.Background(colSelBg)
		for cx := 0; cx < split; cx++ {
			s.SetContent(cx, y, ' ', nil, tcell.StyleDefault.Background(colSelBg))
		}
		s.SetContent(0, y, '▎', nil, tcell.StyleDefault.Foreground(colSelBar).Background(colSelBg))
	}
	rec := strings.ToUpper(string(a.Recommendation))
	scoreStr := fmt.Sprintf("%d", a.Score)
	drawText(s, 2, y, st.Bold(!done), rec)
	name := a.Subject.Display()
	if done {
		name = "✓ " + name
	}
	nameX := 2 + 12
	nameW := split - 2 - nameX - len(scoreStr)
	drawText(s, nameX, y, st, truncate(name, nameW))
	drawText(s, split-2-len(scoreStr), y, st, scoreStr)
}

func drawDetail(s tcell.Screen, x, top, bottom, wdt int, a model.Assessment) {
	def := tcell.StyleDefault.Foreground(colText)
	y := top
	put := func(style tcell.Style, text string) {
		if y <= bottom {
			drawText(s, x, y, style, truncate(text, wdt))
		}
		y++
	}
	put(def.Bold(true), a.Subject.Display())
	put(def.Foreground(colDim), a.Category+" · score "+itoa(a.Score))
	y++
	put(def, a.Verdict)
	if bd := breakdown(a); bd != "" {
		put(def.Foreground(colDim), bd)
	}
	if a.Tripwire != "" {
		y++
		put(def.Foreground(colQuarantine), "⚠ tripwire: "+a.Tripwire)
	}
	y++
	put(def.Foreground(colDim), "EVIDENCE")
	for _, e := range dedupe(a.Evidence) {
		suffix := ""
		if e.count > 1 {
			suffix = fmt.Sprintf("  ×%d", e.count)
		}
		put(def, string(e.kind)+"  "+e.summary+suffix)
		if e.ancestry != "" {
			put(def.Foreground(colInvestigate), "  ↳ "+e.ancestry)
		}
		if e.argv != "" {
			put(def.Foreground(colDim), "  ↳ "+e.argv)
		}
	}
}

// breakdown composes a score-provenance line from the evidence weights already on the
// Assessment (no score/interpret import needed).
func breakdown(a model.Assessment) string {
	var parts []string
	raw := 0
	for _, e := range a.Evidence {
		if e.Weight > 0 {
			parts = append(parts, fmt.Sprintf("%s +%d", e.Kind, e.Weight))
			raw += e.Weight
		}
	}
	if len(parts) == 0 {
		return ""
	}
	line := strings.Join(parts, ", ") + fmt.Sprintf(" = %d", raw)
	if len(a.Kinds) >= 2 {
		line += " ×1.5 correlation"
	}
	return line
}

type evLine struct {
	kind                    model.SignalKind
	summary, ancestry, argv string
	count                   int
}

func dedupe(ev []model.Evidence) []evLine {
	order := []string{}
	seen := map[string]*evLine{}
	for _, e := range ev {
		key := string(e.Kind) + "|" + e.Summary
		l, ok := seen[key]
		if !ok {
			l = &evLine{kind: e.Kind, summary: e.Summary, ancestry: e.Facts["ancestry"], argv: e.Facts["argv"]}
			seen[key] = l
			order = append(order, key)
		}
		l.count++
	}
	sort.SliceStable(order, func(i, j int) bool { return seen[order[i]].kind < seen[order[j]].kind })
	out := make([]evLine, 0, len(order))
	for _, k := range order {
		out = append(out, *seen[k])
	}
	return out
}

func drawBox(s tcell.Screen, x0, y0, bw, bh int) tcell.Style {
	box := tcell.StyleDefault.Foreground(colText).Background(tcell.NewRGBColor(20, 26, 33))
	edge := box.Foreground(colDim)
	for y := y0; y < y0+bh; y++ {
		for cx := x0; cx < x0+bw; cx++ {
			s.SetContent(cx, y, ' ', nil, box)
		}
	}
	for cx := x0 + 1; cx < x0+bw-1; cx++ {
		s.SetContent(cx, y0, '─', nil, edge)
		s.SetContent(cx, y0+bh-1, '─', nil, edge)
	}
	for y := y0 + 1; y < y0+bh-1; y++ {
		s.SetContent(x0, y, '│', nil, edge)
		s.SetContent(x0+bw-1, y, '│', nil, edge)
	}
	s.SetContent(x0, y0, '┌', nil, edge)
	s.SetContent(x0+bw-1, y0, '┐', nil, edge)
	s.SetContent(x0, y0+bh-1, '└', nil, edge)
	s.SetContent(x0+bw-1, y0+bh-1, '┘', nil, edge)
	return box
}

func drawModal(s tcell.Screen, a model.Assessment) {
	w, h := s.Size()
	bw := 64
	plan := planLines(a)
	bh := 7 + len(plan)
	x0, y0 := (w-bw)/2, (h-bh)/2
	box := drawBox(s, x0, y0, bw, bh)
	drawText(s, x0+2, y0+1, box.Bold(true), truncate("Quarantine "+a.Subject.Display()+"?", bw-4))
	drawText(s, x0+2, y0+2, box.Foreground(colAccent), truncate("↺ reversible — moves, never deletes; undo with restore", bw-4))
	drawText(s, x0+2, y0+4, box.Foreground(colDim), "will run:")
	for i, p := range plan {
		drawText(s, x0+2, y0+5+i, box.Foreground(tcell.NewRGBColor(159, 217, 194)), truncate(p, bw-4))
	}
	drawText(s, x0+2, y0+bh-2, box.Foreground(colQuarantine), "[Enter] Quarantine")
	drawText(s, x0+26, y0+bh-2, box.Foreground(colDim), "[Esc] Cancel")
}

// planLines renders the pre-populated Actions (set by main) as a human command preview.
func planLines(a model.Assessment) []string {
	var out []string
	for _, act := range a.Actions {
		switch act.Kind {
		case model.ActionBootout:
			out = append(out, "launchctl bootout "+act.From)
		case model.ActionMove:
			out = append(out, "move "+act.From+" → quarantine")
		}
	}
	if len(out) == 0 {
		out = []string{"(no on-disk artifact — nothing to move)"}
	}
	return out
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
