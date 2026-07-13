// internal/tui/egresszoom.go
package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// pidPalette is the per-PID line colors, shared between the graph lines and the PID table swatches.
// Keyed by PID (not row position) so a PID keeps its color even as the rate-sorted order reshuffles
// between ticks — a row and its line always read as the same PID (cp-zoom Audit F2).
var pidPalette = []tcell.Color{colInvestigate, colAccent, colQuarantine, colMonitor, colWarn, colText}

func pidLineColor(pid int) tcell.Color {
	return pidPalette[((pid%len(pidPalette))+len(pidPalette))%len(pidPalette)]
}

// seriesValues returns a PID's samples for the active graph metric.
func seriesValues(mem model.EgressInstance, mode trendMode) []uint64 {
	switch mode {
	case trendIn:
		return mem.InSpark
	case trendCombined:
		out, in := mem.Spark, mem.InSpark
		n := len(out)
		if len(in) > n {
			n = len(in)
		}
		sum := make([]uint64, n)
		for i := 0; i < n; i++ {
			if j := i - (n - len(out)); j >= 0 && j < len(out) {
				sum[i] += out[j]
			}
			if j := i - (n - len(in)); j >= 0 && j < len(in) {
				sum[i] += in[j]
			}
		}
		return sum
	default:
		return mem.Spark
	}
}

// drawPanel draws a single-line box [x,x+w)×[y,y+h) with a title in the top border (divider color)
// — a thin panel frame (unlike the solid-filled modal drawBox), matching the btm reference.
func drawPanel(s tcell.Screen, x, y, w, h int, title string) {
	if w < 2 || h < 2 {
		return
	}
	st := tcell.StyleDefault.Foreground(colDivider)
	for i := 1; i < w-1; i++ {
		s.SetContent(x+i, y, '─', nil, st)
		s.SetContent(x+i, y+h-1, '─', nil, st)
	}
	for j := 1; j < h-1; j++ {
		s.SetContent(x, y+j, '│', nil, st)
		s.SetContent(x+w-1, y+j, '│', nil, st)
	}
	s.SetContent(x, y, '┌', nil, st)
	s.SetContent(x+w-1, y, '┐', nil, st)
	s.SetContent(x, y+h-1, '└', nil, st)
	s.SetContent(x+w-1, y+h-1, '┘', nil, st)
	if title != "" {
		drawText(s, x+2, y, tcell.StyleDefault.Foreground(colDim), truncate(" "+title+" ", w-4))
	}
}

// drawEgressZoom renders the full-screen btm-style zoom dashboard for m.Zoom's group: a per-PID
// throughput graph, a selectable PID table (rates + %-of-group share), the destinations, and the
// group metadata with the key hints on its border.
func drawEgressZoom(s tcell.Screen, m EgressModel) {
	s.Clear()
	w, h := s.Size()
	g, ok := m.zoomGroup()
	if !ok || w < 40 || h < 12 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	members := zoomedMembers(g)
	sel := m.Zoom.sel
	if sel >= len(members) {
		sel = len(members) - 1
	}

	topH := (h - 1) / 2
	if topH < 5 {
		topH = 5
	}
	leftW := w * 62 / 100

	drawZoomGraph(s, 0, 0, leftW, topH, g, members, sel, m.Zoom.mode)
	drawZoomPIDs(s, leftW, 0, w-leftW, topH, g, members, sel)
	botY, botH := topH, h-topH
	drawZoomDests(s, 0, botY, leftW, botH, g)
	drawZoomMeta(s, leftW, botY, w-leftW, botH, g)
}

func drawZoomGraph(s tcell.Screen, x, y, w, h int, g model.EgressGroup, members []model.EgressInstance, sel int, mode trendMode) {
	drawPanel(s, x, y, w, h, fmt.Sprintf("%s · egress · %d pid(s) · %s", g.App, len(members), trendWord(mode)))
	ix, iy, iw, ih := x+1, y+1, w-2, h-2
	if iw < 10 || ih < 3 {
		return
	}
	const labelW = 6 // gutter for the Y-axis value label (e.g. "1.4M")
	plotCols, plotRows := iw-labelW, ih-1
	if plotCols < 2 || plotRows < 1 {
		return
	}
	// Plot in a STABLE order (by PID), NOT the rate-sorted members order: where lines overlap a cell,
	// plotSeries gives it to the last-plotted series, so a rate-driven reshuffle would flip the color
	// of already-rendered historical cells frame-to-frame (observed flicker). PID order is fixed, so
	// the overlap winner is deterministic. Emphasis (the selected line, drawn on top) is by PID.
	selPID := -1
	if sel >= 0 && sel < len(members) {
		selPID = members[sel].PID
	}
	byPID := append([]model.EgressInstance(nil), members...)
	sort.SliceStable(byPID, func(i, j int) bool { return byPID[i].PID < byPID[j].PID })
	var series []graphSeries
	var maxY uint64
	for _, mem := range byPID {
		vals := seriesValues(mem, mode)
		for _, v := range vals {
			if v > maxY {
				maxY = v
			}
		}
		series = append(series, graphSeries{values: vals, color: pidLineColor(mem.PID), emphasized: mem.PID == selPID})
	}
	grid := plotSeries(series, plotCols, plotRows, maxY)
	for r := 0; r < plotRows; r++ {
		for c := 0; c < plotCols; c++ {
			if cell := grid[r][c]; cell.r != ' ' {
				s.SetContent(ix+labelW+c, iy+r, cell.r, nil, tcell.StyleDefault.Foreground(cell.color))
			}
		}
	}
	// Y-axis: peak at the top, 0 at the bottom plot row.
	drawText(s, ix, iy, tcell.StyleDefault.Foreground(colDim), truncate(human(maxY), labelW-1))
	drawText(s, ix, iy+plotRows-1, tcell.StyleDefault.Foreground(colDim), "0")
	// X-axis + live totals on the last interior row. Newest sample is right-aligned; the exact
	// window depends on the sample cadence (which the view layer doesn't know), so label the
	// direction rather than assert a duration the tui can't compute (cp-zoom Audit F1).
	drawText(s, ix+labelW, iy+ih-1, tcell.StyleDefault.Foreground(colDim), "◄ older")
	totals := fmt.Sprintf("↑%s ↓%s", human(g.OutRate), human(g.InRate))
	drawText(s, ix+iw-len([]rune(totals)), iy+ih-1, tcell.StyleDefault.Foreground(colDim), totals)
}

func drawZoomPIDs(s tcell.Screen, x, y, w, h int, g model.EgressGroup, members []model.EgressInstance, sel int) {
	drawPanel(s, x, y, w, h, "PIDs")
	ix, iy, iw := x+2, y+1, w-4
	if iw < 12 {
		return
	}
	drawText(s, ix+2, iy, tcell.StyleDefault.Foreground(colDim), truncate("PID     OUT↑    IN↓  %GRP  ⚿", iw-2))
	for i, mem := range members {
		row := iy + 1 + i
		if row >= y+h-1 {
			break
		}
		share := pidShare(mem.OutRate, g.OutRate)
		line := fmt.Sprintf("%5d  %6s  %5s  %s%3d%%  ", mem.PID, human(mem.OutRate), human(mem.InRate), shareBar(share, 4), share)
		st := tcell.StyleDefault.Foreground(colText)
		if i == sel {
			st = st.Background(colSelBg).Bold(true)
			s.SetContent(x+1, row, '▸', nil, tcell.StyleDefault.Foreground(colSelBar))
		}
		drawText(s, ix, row, tcell.StyleDefault.Foreground(pidLineColor(mem.PID)), "■") // graph-matched swatch
		drawText(s, ix+2, row, st, truncate(line, iw-2))
		// Encryption annotation from the PID's busiest connection's port (the flow `i` would inspect).
		if c := busiestConn(mem.Conns); c != nil {
			if gx := ix + 2 + len([]rune(line)); gx < ix+iw {
				drawEncGlyph(s, gx, row, st, c.Endpoint.Port)
			}
		}
	}
}

// shareBar renders an n-cell block bar for a 0..100 percentage.
func shareBar(pct, n int) string {
	full := pct * n / 100
	b := make([]rune, n)
	for i := range b {
		if i < full {
			b[i] = '▇'
		} else {
			b[i] = ' '
		}
	}
	return string(b)
}

func drawZoomDests(s tcell.Screen, x, y, w, h int, g model.EgressGroup) {
	drawPanel(s, x, y, w, h, "destinations")
	ix, iy, iw := x+2, y+1, w-4
	if iw < 12 {
		return
	}
	agg := map[string]uint64{}
	for _, c := range g.Conns {
		agg[fmt.Sprintf("%s:%d", c.Endpoint.IP, c.Endpoint.Port)] += c.OutRate
	}
	type dest struct {
		ep   string
		rate uint64
	}
	ds := make([]dest, 0, len(agg))
	for ep, r := range agg {
		ds = append(ds, dest{ep, r})
	}
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].rate != ds[j].rate {
			return ds[i].rate > ds[j].rate
		}
		return ds[i].ep < ds[j].ep
	})
	for i, d := range ds {
		row := iy + i
		if row >= y+h-1 {
			break
		}
		share := pidShare(d.rate, g.OutRate)
		drawText(s, ix, row, tcell.StyleDefault.Foreground(colText),
			truncate(fmt.Sprintf("%-24s ↑%6s %3d%%", middleEllipsis(d.ep, 24), human(d.rate), share), iw))
	}
}

func drawZoomMeta(s tcell.Screen, x, y, w, h int, g model.EgressGroup) {
	drawPanel(s, x, y, w, h, "this group")
	ix, iy, iw := x+2, y+1, w-4
	lines := []string{model.Clean(fmt.Sprintf("%s · %s · cadence: %s", g.Trust, bgLabel(g.Background), g.Cadence))}
	if len(g.Capabilities) > 0 {
		lines = append(lines, model.Clean("can access  "+strings.Join(g.Capabilities, " · ")))
	}
	for i, ln := range lines {
		row := iy + i
		if row >= y+h-1 {
			break
		}
		drawText(s, ix, row, tcell.StyleDefault.Foreground(colDim), truncate(ln, iw))
	}
	// Key hints on the bottom border, like the tree footer.
	drawText(s, x+2, y+h-1, tcell.StyleDefault.Foreground(colDim),
		truncate(" i inspect · ↑/↓ pid · t out/in · z back ", w-4))
}
