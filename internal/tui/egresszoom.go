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

// destLineColor keys the palette by the destination string so an endpoint keeps its color across
// re-sorts, matching the graph line to the destinations-panel swatch (as pidLineColor does for PIDs).
func destLineColor(ep string) tcell.Color {
	var h int
	for _, r := range ep {
		h = h*31 + int(r)
	}
	return pidPalette[((h%len(pidPalette))+len(pidPalette))%len(pidPalette)]
}

// metricSamples selects/combines a flow's out/in history for the active graph metric.
func metricSamples(out, in []uint64, mode trendMode) []uint64 {
	switch mode {
	case trendIn:
		return in
	case trendCombined:
		return addAligned(out, in)
	default:
		return out
	}
}

func seriesValues(mem model.EgressInstance, mode trendMode) []uint64 {
	return metricSamples(mem.Spark, mem.InSpark, mode)
}

// addAligned sums two rate-history slices aligned at their NEWEST (right) end — histories can differ
// in length (a younger connection has fewer samples), so a left-aligned sum would misattribute time.
func addAligned(a, b []uint64) []uint64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		if j := i - (n - len(a)); j >= 0 && j < len(a) {
			out[i] += a[j]
		}
		if j := i - (n - len(b)); j >= 0 && j < len(b) {
			out[i] += b[j]
		}
	}
	return out
}

// destAgg is one destination's aggregated series for the by-destination graph.
type destAgg struct {
	ep   string
	vals []uint64
}

// destSeriesList aggregates the group's connections by endpoint, summing each endpoint's metric
// history across the PIDs that talk to it. Ordered by endpoint string for a stable plot order (so
// overlapping cells don't flicker color as rates reshuffle — same rule as the PID graph).
func destSeriesList(g model.EgressGroup, mode trendMode) []destAgg {
	agg := map[string]*destAgg{}
	for _, c := range g.Conns {
		ep := fmt.Sprintf("%s:%d", c.Endpoint.IP, c.Endpoint.Port)
		vals := metricSamples(c.Spark, c.InSpark, mode)
		if a, ok := agg[ep]; ok {
			a.vals = addAligned(a.vals, vals)
		} else {
			agg[ep] = &destAgg{ep: ep, vals: vals}
		}
	}
	out := make([]destAgg, 0, len(agg))
	for _, a := range agg {
		out = append(out, *a)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ep < out[j].ep })
	return out
}

// drawPanel draws a single-line box [x,x+w)×[y,y+h) with a title in the top border — a thin frame
// (unlike the solid-filled modal drawBox), matching the btm reference. A focused panel gets an
// accent border + title so the user can see which box the arrow keys drive.
func drawPanel(s tcell.Screen, x, y, w, h int, title string, focused bool) {
	if w < 2 || h < 2 {
		return
	}
	border, titleColor := colDivider, colDim
	if focused {
		border, titleColor = colSelBar, colAccent
	}
	st := tcell.StyleDefault.Foreground(border)
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
		ts := tcell.StyleDefault.Foreground(titleColor)
		if focused {
			ts = ts.Bold(true)
		}
		drawText(s, x+2, y, ts, truncate(" "+title+" ", w-4))
	}
}

// drawEgressZoom renders the full-screen btm-style zoom dashboard for m.Zoom's group. `g` moves
// focus between the PIDs box and the destinations box: the focused box gets an accent border, its
// cursor drives the graph emphasis, and the graph groups its lines to match (by PID or by dest).
func drawEgressZoom(s tcell.Screen, m EgressModel) {
	s.Clear()
	w, h := s.Size()
	g, ok := m.zoomGroup()
	if !ok || w < 40 || h < 12 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	members := zoomedMembers(g)
	dests := zoomDests(g)
	byDest := m.Zoom.byDest
	selPID := clamp(m.Zoom.sel, len(members))
	selDest := clamp(m.Zoom.selDest, len(dests))

	// Emphasis (the line drawn on top) is the focused box's selection.
	emphPID, emphEp := -1, ""
	if byDest {
		if selDest < len(dests) {
			emphEp = dests[selDest].ep
		}
	} else if selPID < len(members) {
		emphPID = members[selPID].PID
	}

	topH := (h - 1) / 2
	if topH < 5 {
		topH = 5
	}
	leftW := w * 62 / 100

	drawZoomGraph(s, 0, 0, leftW, topH, g, members, m.Zoom.mode, byDest, emphPID, emphEp)
	drawZoomPIDs(s, leftW, 0, w-leftW, topH, g, members, selPID, !byDest)
	botY, botH := topH, h-topH
	drawZoomDests(s, 0, botY, leftW, botH, g, dests, selDest, byDest, m.InterceptedDests)
	drawZoomMeta(s, leftW, botY, w-leftW, botH, m, g)
}

func drawZoomGraph(s tcell.Screen, x, y, w, h int, g model.EgressGroup, members []model.EgressInstance, mode trendMode, byDest bool, emphPID int, emphEp string) {
	noun, grouping, nLines := "pid(s)", "by pid", len(members)
	if byDest {
		noun, grouping, nLines = "dest(s)", "by dest", len(destSeriesList(g, mode))
	}
	drawPanel(s, x, y, w, h, fmt.Sprintf("%s · exfil · %d %s · %s · %s", g.App, nLines, noun, grouping, trendWord(mode)), false)
	ix, iy, iw, ih := x+1, y+1, w-2, h-2
	if iw < 10 || ih < 3 {
		return
	}
	const labelW = 6 // gutter for the Y-axis value label (e.g. "1.4M")
	plotCols, plotRows := iw-labelW, ih-1
	if plotCols < 2 || plotRows < 1 {
		return
	}
	// Build the lines in a STABLE order (by PID, or by endpoint string for destinations): where lines
	// overlap a cell, plotSeries gives it to the last-plotted series, so a rate-driven reshuffle would
	// flip the color of already-rendered historical cells (observed flicker). A fixed order makes the
	// overlap winner deterministic. Emphasis (drawn on top) is the focused box's selection.
	var series []graphSeries
	var maxY uint64
	if byDest {
		for _, d := range destSeriesList(g, mode) {
			for _, v := range d.vals {
				if v > maxY {
					maxY = v
				}
			}
			series = append(series, graphSeries{values: d.vals, color: destLineColor(d.ep), emphasized: d.ep == emphEp})
		}
	} else {
		byPID := append([]model.EgressInstance(nil), members...)
		sort.SliceStable(byPID, func(i, j int) bool { return byPID[i].PID < byPID[j].PID })
		for _, mem := range byPID {
			vals := seriesValues(mem, mode)
			for _, v := range vals {
				if v > maxY {
					maxY = v
				}
			}
			series = append(series, graphSeries{values: vals, color: pidLineColor(mem.PID), emphasized: mem.PID == emphPID})
		}
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

func drawZoomPIDs(s tcell.Screen, x, y, w, h int, g model.EgressGroup, members []model.EgressInstance, sel int, focused bool) {
	drawPanel(s, x, y, w, h, "PIDs", focused)
	ix, iy, iw := x+2, y+1, w-4
	if iw < 12 {
		return
	}
	drawText(s, ix+2, iy, tcell.StyleDefault.Foreground(colDim), truncate("PID     OUT↑    IN↓  %GRP  ▣", iw-2))
	for i, mem := range members {
		row := iy + 1 + i
		if row >= y+h-1 {
			break
		}
		share := pidShare(mem.OutRate, g.OutRate)
		line := fmt.Sprintf("%5d  %6s  %5s  %s%3d%%  ", mem.PID, human(mem.OutRate), human(mem.InRate), shareBar(share, 4), share)
		st := tcell.StyleDefault.Foreground(colText)
		if i == sel && focused { // the cursor only shows in the focused box (arrows drive it)
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

// destDecrypted reports whether an "IP:port" endpoint's IP appears in the decrypted stream
// (InterceptedDests). Pure so the IP match is unit-tested independent of rendering.
func destDecrypted(ep string, decrypted map[string]struct{}) bool {
	if len(decrypted) == 0 {
		return false
	}
	ip := ep
	if i := strings.LastIndex(ep, ":"); i >= 0 {
		ip = ep[:i]
	}
	_, ok := decrypted[ip]
	return ok
}

func drawZoomDests(s tcell.Screen, x, y, w, h int, g model.EgressGroup, ds []destRate, sel int, focused bool, decrypted map[string]struct{}) {
	drawPanel(s, x, y, w, h, "destinations", focused)
	ix, iy, iw := x+2, y+1, w-4
	if iw < 12 {
		return
	}
	// When this box is focused it's the graph's color legend: swatch each row to its graph line and
	// show the cursor on the emphasized endpoint (which the arrow keys drive).
	for i, d := range ds {
		row := iy + i
		if row >= y+h-1 {
			break
		}
		share := pidShare(d.rate, g.OutRate)
		st := tcell.StyleDefault.Foreground(colText)
		tx := ix
		if focused {
			drawText(s, ix, row, tcell.StyleDefault.Foreground(destLineColor(d.ep)), "■")
			tx = ix + 2
			if i == sel {
				st = st.Background(colSelBg).Bold(true)
				s.SetContent(x+1, row, '▸', nil, tcell.StyleDefault.Foreground(colSelBar))
			}
		}
		// Clean the label BEFORE layout: a destination name comes from an observed DNS packet
		// (attacker-influenceable), so a crafted name must not inject ANSI/control chars into the
		// zoom panel. IP:port labels were inert, but resolved names are not (#3).
		drawText(s, tx, row, st,
			truncate(fmt.Sprintf("%-24s ↑%6s %3d%%", middleEllipsis(model.Clean(d.label), 24), human(d.rate), share), iw-(tx-ix)))
		// Mark a destination whose TLS we decrypted (seen in the intercept stream), cross-referencing
		// the byte-level egress view with the decrypted flows. Drawn at the panel's right edge so it
		// never disturbs column layout.
		if destDecrypted(d.ep, decrypted) {
			s.SetContent(x+w-2, row, '⚿', nil, tcell.StyleDefault.Foreground(colWarn))
		}
	}
}

func drawZoomMeta(s tcell.Screen, x, y, w, h int, m EgressModel, g model.EgressGroup) {
	drawPanel(s, x, y, w, h, "this group", false)
	ix, iy, iw := x+2, y+1, w-4
	lines := []string{model.Clean(fmt.Sprintf("%s · %s · cadence: %s", g.Trust, bgLabel(g.Background), g.Cadence))}
	if len(g.Capabilities) > 0 {
		lines = append(lines, model.Clean("can access  "+strings.Join(g.Capabilities, " · ")))
	}
	// Decrypted per-message section (only in `console --intercept` mode); empty-state-aware.
	lines = append(lines, interceptSummary(m, g.Path, 6)...)
	for i, ln := range lines {
		row := iy + i
		if row >= y+h-1 {
			break
		}
		drawText(s, ix, row, tcell.StyleDefault.Foreground(colDim), truncate(ln, iw))
	}
	// Key hints on the bottom border, like the tree footer.
	drawText(s, x+2, y+h-1, tcell.StyleDefault.Foreground(colDim),
		truncate(" i inspect · ↑/↓ pid · t out/in · g pid/dest · z back ", w-4))
}

// interceptSummary renders the "decrypted flows" section for one app in the zoom meta pane. It is pure
// so the three honest states are unit-tested: not in intercept mode (nil — the section is absent),
// intercept on but nothing captured for this app yet, and the recent per-message summaries (newest
// last, bounded by max). MessageDropCount is surfaced so a bounded buffer never silently hides flows.
func interceptSummary(m EgressModel, path string, max int) []string {
	if m.ProxyAddr == "" {
		return nil // not in intercept mode
	}
	out := []string{"── decrypted · " + m.ProxyAddr}
	msgs := m.Messages[path]
	if len(msgs) == 0 {
		return append(out, "  no decrypted flows for this app yet")
	}
	start := 0
	if max > 0 && len(msgs) > max {
		start = len(msgs) - max
	}
	for _, msg := range msgs[start:] {
		out = append(out, "  "+interceptMsgLine(msg))
	}
	if m.MessageDropCount > 0 {
		out = append(out, fmt.Sprintf("  (+%d older dropped · buffer bound)", m.MessageDropCount))
	}
	return out
}

// interceptMsgLine is a one-line summary of an intercepted message: a direction arrow, the HTTP start
// line (first line of the already-redacted Text), and the destination. Connection-level events (no
// direction/text) fall back to their reason.
func interceptMsgLine(msg model.InterceptedMessage) string {
	arrow := "·"
	switch msg.Direction {
	case "request":
		arrow = "→"
	case "response":
		arrow = "←"
	}
	start := msg.Text
	if i := strings.IndexAny(start, "\r\n"); i >= 0 {
		start = start[:i]
	}
	if start == "" {
		start = msg.Reason // connection-level events carry a reason, not message text
	}
	dest := msg.DestName
	if dest == "" {
		dest = msg.DestIP
	}
	line := arrow + " " + start
	if dest != "" {
		line += "  " + dest
	}
	return model.Clean(line)
}
