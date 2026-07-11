// internal/tui/egressview.go
package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func concernColor(c model.ConcernLevel) tcell.Color {
	switch c {
	case model.Elevated:
		return colQuarantine
	case model.Notable:
		return colInvestigate
	case model.Low:
		return colMonitor
	default:
		return colDim
	}
}

var sparkGlyphs = []rune("▁▂▃▄▅▆▇█")

func sparkline(vals []uint64) string {
	if len(vals) == 0 {
		return ""
	}
	var max uint64
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range vals {
		idx := 0
		if max > 0 {
			idx = int(v * uint64(len(sparkGlyphs)-1) / max)
		}
		b.WriteRune(sparkGlyphs[idx])
	}
	return b.String()
}

// egressView renders the full-width top table + detail strip.
func egressView(m EgressModel, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	if w < 24 || h < 6 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	drawText(s, 2, 0, tcell.StyleDefault.Foreground(colAccent).Bold(true), "CounterSpy · Egress")
	status := "sampling · p pause · Q quit"
	if m.Paused {
		status = "PAUSED · p resume · Q quit"
	}
	drawText(s, w-len(status)-2, 0, tcell.StyleDefault.Foreground(colDim), status)
	drawText(s, 2, 1, tcell.StyleDefault.Foreground(colDim),
		fmt.Sprintf("%-18s %-10s %-9s %-8s %-26s %s", "APP / PROCESS", "TRUST", "OUT↑", "RATE", "TOP DESTINATION", "CONCERN"))

	rows := m.visibleRows()
	y := 2
	for i, row := range rows {
		if y >= h-6 {
			break
		}
		if row.conn != nil {
			line := fmt.Sprintf("    %-14s %s %s:%d  %s/s", "pid "+itoa(row.conn.PID), row.conn.Proto,
				row.conn.Endpoint.IP, row.conn.Endpoint.Port, human(row.conn.OutRate))
			drawText(s, 2, y, tcell.StyleDefault.Foreground(colDim), model.Clean(line))
			y++
			continue
		}
		g := row.group
		marker := "▸"
		if m.expanded[g.App] {
			marker = "▾"
		}
		style := tcell.StyleDefault.Foreground(concernColor(g.Concern))
		if i == selectedRowIndex(m, rows) {
			style = style.Background(colSelBg)
		}
		line := fmt.Sprintf("%s %-16s %-10s %-9s %-8s %-26s %s",
			marker, truncate(g.App, 16), g.Trust, human(g.OutRate)+"/s", sparkline(g.Spark),
			truncate(topDest(g), 26), g.Concern.String())
		drawText(s, 2, y, style, model.Clean(line))
		y++
	}
	drawEgressDetail(m, s, h)
}

func selectedRowIndex(m EgressModel, rows []egressRow) int {
	groups := m.orderedGroups()
	if m.Selected >= len(groups) {
		return -1
	}
	sel := groups[m.Selected].App
	for i, r := range rows {
		if r.conn == nil && r.group.App == sel {
			return i
		}
	}
	return -1
}

func drawEgressDetail(m EgressModel, s tcell.Screen, h int) {
	groups := m.orderedGroups()
	if m.Selected >= len(groups) {
		return
	}
	g := groups[m.Selected]
	base := h - 6
	col := concernColor(g.Concern)
	drawText(s, 2, base, tcell.StyleDefault.Foreground(colDim),
		model.Clean(fmt.Sprintf("DETAIL — %s · %d instance(s) · %d conn(s)", g.App, g.Instances, len(g.Conns))))
	drawText(s, 2, base+1, tcell.StyleDefault.Foreground(colDim), model.Clean(g.Ancestry))
	drawText(s, 2, base+2, tcell.StyleDefault.Foreground(col),
		model.Clean(fmt.Sprintf("%s · %s · cadence: %s", g.Trust, bgLabel(g.Background), g.Cadence)))
	if len(g.Capabilities) > 0 {
		drawText(s, 2, base+3, tcell.StyleDefault.Foreground(colDim),
			model.Clean("can access  "+strings.Join(g.Capabilities, " · ")))
		drawText(s, 2, base+4, tcell.StyleDefault.Foreground(col),
			model.Clean(fmt.Sprintf("exfil %s — candidate: %s (inferred from capability)",
				g.ExfilRisk.String(), strings.Join(g.Candidate, ", "))))
	}
}

func bgLabel(bg bool) string {
	if bg {
		return "background daemon"
	}
	return "foreground app"
}

func topDest(g model.EgressGroup) string {
	if len(g.Destinations) == 0 {
		return "—"
	}
	d := g.Destinations[0]
	extra := ""
	if len(g.Destinations) > 1 {
		extra = fmt.Sprintf(" +%d", len(g.Destinations)-1)
	}
	return fmt.Sprintf("%s:%d%s", d.IP, d.Port, extra)
}

func human(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
