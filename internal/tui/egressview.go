// internal/tui/egressview.go
package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Column layout: TRUST, OUT↑, TREND and CONCERN are fixed-width; APP/PROCESS and
// DESTINATIONS are flex columns that share whatever width is left over.
const (
	marginX  = 2
	marginR  = 2
	colGap   = 1
	markerW  = 6
	trustW   = 8
	rateW    = 9
	trendW   = 10
	concernW = 10
)

const footerHint = "j/k ↑/↓ move · ↵/→ expand · ← collapse · y copy path · s sort · / filter · p pause · Q quit"

// middleEllipsis renders a long path as "start…/finalBinary": it keeps the leading path and
// the final component (the binary), collapsing the middle with … so both the location and the
// binary name stay visible instead of the tail being truncated away. Rune-aware.
func middleEllipsis(s string, max int) string {
	r := []rune(s)
	if max <= 1 || len(r) <= max {
		return s
	}
	base := r
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		base = []rune(s[i:]) // "/binary"
	}
	if len(base)+1 >= max { // even the final component doesn't fit; keep its tail
		return "…" + string(base[len(base)-(max-1):])
	}
	head := max - len(base) - 1 // -1 for the … rune
	return string(r[:head]) + "…" + string(base)
}

const emptyHint = "No outbound traffic observed — run with sudo for full visibility."

type egressCols struct {
	markerX      int
	appX, appW   int
	trustX       int
	rateX        int
	trendX       int
	destX, destW int
	concernX     int
}

// computeCols derives column x-positions from the terminal width w. Header labels and data
// rows both draw from this same layout, so they always align.
func computeCols(w int) egressCols {
	fixed := marginX + markerW + trustW + rateW + trendW + concernW + marginR + 6*colGap
	remaining := w - fixed
	if remaining < 0 {
		remaining = 0
	}
	appW := remaining * 2 / 5
	destW := remaining - appW

	var c egressCols
	x := marginX
	c.markerX = x
	x += markerW + colGap
	c.appX, c.appW = x, appW
	x += appW + colGap
	c.trustX = x
	x += trustW + colGap
	c.rateX = x
	x += rateW + colGap
	c.trendX = x
	x += trendW + colGap
	c.destX, c.destW = x, destW
	x += destW + colGap
	c.concernX = x
	return c
}

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

// downsample shrinks vals to at most width buckets (bucket-averaged) so a sparkline never
// prints more glyphs than its column is wide. Values already within width pass through.
func downsample(vals []uint64, width int) []uint64 {
	if width <= 0 || len(vals) <= width {
		return vals
	}
	out := make([]uint64, width)
	for i := 0; i < width; i++ {
		lo := i * len(vals) / width
		hi := (i + 1) * len(vals) / width
		if hi <= lo {
			hi = lo + 1
		}
		var sum uint64
		for j := lo; j < hi; j++ {
			sum += vals[j]
		}
		out[i] = sum / uint64(hi-lo)
	}
	return out
}

// egressView renders the 3-level tree + footer + detail strip.
func egressView(m EgressModel, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	if w < 24 || h < 6 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	drawText(s, marginX, 0, tcell.StyleDefault.Foreground(colAccent).Bold(true), "CounterSpy · Egress")

	groups := m.orderedGroups()
	status := "sampling"
	if m.Paused {
		status = "PAUSED"
	}
	statusLine := fmt.Sprintf("%d app(s) · %s", len(groups), status)
	statusColor := colDim
	if m.Status != "" { // transient feedback (e.g. copied path) takes over the status slot
		statusLine, statusColor = m.Status, colAccent
	}
	drawText(s, w-len(statusLine)-marginR, 0, tcell.StyleDefault.Foreground(statusColor), statusLine)

	cols := computeCols(w)
	headerY := 1
	drawText(s, cols.appX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("APP / PROCESS", cols.appW))
	drawText(s, cols.trustX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("TRUST", trustW))
	drawText(s, cols.rateX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("OUT↑", rateW))
	drawText(s, cols.trendX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("TREND", trendW))
	drawText(s, cols.destX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("DESTINATIONS", cols.destW))
	drawText(s, cols.concernX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("CONCERN", concernW))

	rows := m.visibleRows()
	footerY := h - 1
	detail := detailLines(rows, m.Selected, w-marginX-marginR)
	tableBottom := footerY - 1 - len(detail)

	tableTop := headerY + 1
	if len(rows) == 0 {
		cy := (tableTop + tableBottom) / 2
		cx := (w - len(emptyHint)) / 2
		if cx < 0 {
			cx = 0
		}
		drawText(s, cx, cy, tcell.StyleDefault.Foreground(colDim), emptyHint)
	} else {
		y := tableTop
		for i, row := range rows {
			if y > tableBottom {
				break
			}
			drawEgressRow(s, cols, w, y, row, i == m.Selected, m.expanded, m.expandedPID)
			y++
		}
	}

	if len(detail) > 0 {
		base := footerY - len(detail)
		for i, line := range detail {
			drawText(s, marginX, base+i, tcell.StyleDefault.Foreground(colDim), model.Clean(truncate(line, w-marginX-marginR)))
		}
	}

	drawText(s, marginX, footerY, tcell.StyleDefault.Foreground(colDim), truncate(footerHint, w-marginX-marginR))
}

func drawEgressRow(s tcell.Screen, cols egressCols, w, y int, row egressRow, selected bool, expanded map[string]bool, expandedPID map[int]bool) {
	g := row.group
	var depth int
	var marker rune
	var label, trust, rate, dest string
	var spark []uint64
	var concernText string
	color := concernColor(g.Concern)

	switch {
	case row.member == nil: // app header
		depth = 0
		if expanded[g.App] {
			marker = '▾'
		} else {
			marker = '▸'
		}
		label = g.App
		trust = g.Trust
		rate = human(g.OutRate) + "/s"
		spark = g.Spark
		dest = topDest(g)
		concernText = g.Concern.String()
	case row.conn == nil: // instance row
		mem := row.member
		depth = 1
		if expandedPID[mem.PID] {
			marker = '▾'
		} else {
			marker = '▸'
		}
		label = fmt.Sprintf("pid %d %s", mem.PID, shortPath(mem.Path))
		trust = mem.Trust
		rate = human(mem.OutRate) + "/s"
	default: // connection row (leaf)
		c := row.conn
		depth = 2
		marker = '·'
		dest = fmt.Sprintf("%s %s:%d", strings.ToUpper(c.Proto), c.Endpoint.IP, c.Endpoint.Port)
		if c.OutRate > 0 {
			rate = human(c.OutRate) + "/s"
		}
	}

	style := tcell.StyleDefault.Foreground(color)
	if selected {
		bg := tcell.StyleDefault.Background(colSelBg)
		for cx := 0; cx < w; cx++ {
			s.SetContent(cx, y, ' ', nil, bg)
		}
		style = style.Background(colSelBg)
	}

	markerStr := strings.Repeat("  ", depth) + string(marker)
	drawText(s, cols.markerX, y, style, markerStr)
	drawText(s, cols.appX, y, style, model.Clean(truncate(label, cols.appW)))
	drawText(s, cols.trustX, y, style, truncate(trust, trustW))
	drawText(s, cols.rateX, y, style, truncate(rate, rateW))
	drawText(s, cols.trendX, y, style, sparkline(downsample(spark, trendW)))
	drawText(s, cols.destX, y, style, model.Clean(truncate(dest, cols.destW)))
	drawText(s, cols.concernX, y, style, truncate(concernText, concernW))
}

// detailLines describes the selected row: the app's full detail, or "App › pid N" for an
// instance/connection row. Empty when there's no selectable row.
func detailLines(rows []egressRow, selected, maxW int) []string {
	if selected < 0 || selected >= len(rows) {
		return nil
	}
	row := rows[selected]
	g := row.group
	if row.member == nil {
		lines := []string{model.Clean(fmt.Sprintf("DETAIL — %s · %d instance(s) · %d conn(s)", g.App, g.Instances, len(g.Conns)))}
		if g.Path != "" {
			lines = append(lines, model.Clean(middleEllipsis(g.Path, maxW)))
		}
		if g.Ancestry != "" {
			lines = append(lines, model.Clean(g.Ancestry))
		}
		lines = append(lines, model.Clean(fmt.Sprintf("%s · %s · cadence: %s", g.Trust, bgLabel(g.Background), g.Cadence)))
		if len(g.Capabilities) > 0 {
			lines = append(lines, model.Clean("can access  "+strings.Join(g.Capabilities, " · ")))
			lines = append(lines, model.Clean(fmt.Sprintf("exfil %s — candidate: %s (inferred from capability)",
				g.ExfilRisk.String(), strings.Join(g.Candidate, ", "))))
		}
		return lines
	}
	mem := row.member
	return []string{
		model.Clean(fmt.Sprintf("%s › pid %d", g.App, mem.PID)),
		model.Clean(middleEllipsis(mem.Path, maxW)),
		fmt.Sprintf("%s · out %s/s · in %s/s", mem.Trust, human(mem.OutRate), human(mem.InRate)),
	}
}

func bgLabel(bg bool) string {
	if bg {
		return "background daemon"
	}
	return "foreground app"
}

func shortPath(p string) string {
	return filepath.Base(p)
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
