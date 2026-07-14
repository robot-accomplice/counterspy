// internal/tui/egressview.go
package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/mark"
	"counterspy/internal/model"
)

// collapsedMarker is the tree-disclosure control: '+' can expand, '−' is expanded.
// A disclosure control, not a liveness state — kept distinct from the ▸ active mark
// so the two never collide (cp-T design: egress toggle moved off ▸).
func collapsedMarker(expanded bool) rune {
	if expanded {
		return '−'
	}
	return '+'
}

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

const footerHint = "⇥ switch · j/k move · ↵/→ expand · ← collapse · z zoom · i inspect · t trend · s sort · / filter · p pause · Q quit"

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

// collectingHint shows before the first sample returns, so an unsampled view doesn't render as a
// misconfiguration (the emptyHint's sudo advice only makes sense once we've actually found nothing).
const collectingHint = "Collecting outbound traffic…"

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

// heatStops is the traffic sparkline's thermal ramp: blue (cool/quiet) → cyan → yellow → red
// (hot/loud). Intensity is ABSOLUTE traffic volume, so busy flows glow red and quiet ones stay
// blue — the TREND column reads as a heat map for spotting the loud talkers (exfil north-star).
var heatStops = []struct {
	at      float64
	r, g, b int32
}{
	{0.00, 60, 130, 246}, // blue — cool / quiet
	{0.40, 45, 205, 205}, // cyan
	{0.72, 240, 205, 70}, // yellow
	{1.00, 235, 70, 70},  // red — hot / peak
}

// heatColor maps a 0..1 intensity to a color along heatStops (linear RGB interpolation).
func heatColor(frac float64) tcell.Color {
	if frac <= 0 {
		s := heatStops[0]
		return tcell.NewRGBColor(s.r, s.g, s.b)
	}
	for i := 1; i < len(heatStops); i++ {
		hi := heatStops[i]
		if frac <= hi.at {
			lo := heatStops[i-1]
			t := (frac - lo.at) / (hi.at - lo.at)
			return tcell.NewRGBColor(
				lo.r+int32(t*float64(hi.r-lo.r)),
				lo.g+int32(t*float64(hi.g-lo.g)),
				lo.b+int32(t*float64(hi.b-lo.b)),
			)
		}
	}
	s := heatStops[len(heatStops)-1]
	return tcell.NewRGBColor(s.r, s.g, s.b)
}

// tempColor is the volume temperature: a rate's share of the loudest flow in view (peak), mapped
// blue(cold)→red(hot). Replaces the old absolute log scale — an arbitrary anchor. peak==0 → cold.
func tempColor(rate, peak uint64) tcell.Color {
	if peak == 0 {
		return heatColor(0)
	}
	return heatColor(float64(rate) / float64(peak))
}

// dirStops is the direction ramp: green (all inbound / download) → amber (all outbound / exfil).
var dirStops = []struct {
	at      float64
	r, g, b int32
}{
	{0.00, 80, 200, 120}, // green — inbound / download
	{0.50, 210, 200, 90}, // muted yellow — balanced
	{1.00, 240, 170, 60}, // amber — outbound / exfil
}

// dirColor maps a 0..1 lean (0 = all in, 1 = all out) to a color along dirStops.
func dirColor(frac float64) tcell.Color {
	if frac <= 0 {
		s := dirStops[0]
		return tcell.NewRGBColor(s.r, s.g, s.b)
	}
	for i := 1; i < len(dirStops); i++ {
		hi := dirStops[i]
		if frac <= hi.at {
			lo := dirStops[i-1]
			t := (frac - lo.at) / (hi.at - lo.at)
			return tcell.NewRGBColor(
				lo.r+int32(t*float64(hi.r-lo.r)),
				lo.g+int32(t*float64(hi.g-lo.g)),
				lo.b+int32(t*float64(hi.b-lo.b)),
			)
		}
	}
	s := dirStops[len(dirStops)-1]
	return tcell.NewRGBColor(s.r, s.g, s.b)
}

// directionColor colors a combined cell by which way it leans: out/(out+in) → dirColor. Balanced or
// empty → mid.
func directionColor(out, in uint64) tcell.Color {
	total := out + in
	if total == 0 {
		return dirColor(0.5)
	}
	return dirColor(float64(out) / float64(total))
}

// drawTrend renders heights[i] as a sparkline glyph (height relative to heights' OWN max, so the
// glyph shape reads as this row's temporal trend) colored by colors[i] at (x+i, y). heights and
// colors are pre-downsampled to width and equal length. Empty draws nothing; preserves the
// selected-row background.
func drawTrend(s tcell.Screen, x, y int, heights []uint64, colors []tcell.Color, width int, selected bool) {
	if len(heights) == 0 {
		return
	}
	var max uint64
	for _, v := range heights {
		if v > max {
			max = v
		}
	}
	for i, v := range heights {
		idx := 0
		if max > 0 {
			idx = int(v * uint64(len(sparkGlyphs)-1) / max)
		}
		st := tcell.StyleDefault.Foreground(colors[i])
		if selected {
			st = st.Background(colSelBg)
		}
		drawText(s, x+i, y, st, string(sparkGlyphs[idx]))
	}
}

// trendGlyph / trendWord are the SINGLE source of the mode's symbol + name, shared by the column
// header and the legend so the two can't drift (they did in an earlier draft).
func trendGlyph(mode trendMode) string {
	switch mode {
	case trendIn:
		return "↓"
	case trendCombined:
		return "⇅"
	default:
		return "↑"
	}
}

func trendWord(mode trendMode) string {
	switch mode {
	case trendIn:
		return "in"
	case trendCombined:
		return "combined"
	default:
		return "out"
	}
}

// drawTrendLegend draws a one-line, self-coloring key for the active trend mode at row y: the
// gradient glyphs use the SAME ramp the sparklines do, so the legend is correct by construction and
// relabels/recolors itself as the user toggles `t`. Clipped to maxX so a narrow terminal truncates
// cleanly rather than running the gradient off the edge.
func drawTrendLegend(s tcell.Screen, y, maxX int, mode trendMode) {
	def := tcell.StyleDefault.Foreground(colDim)
	label := "TREND " + trendGlyph(mode) + " " + trendWord(mode) + "  "
	left, right := "quiet ", " loud"
	ramp := heatColor // blue→red volume temperature (out/in modes)
	if mode == trendCombined {
		left, right = "◀ in·download ", " out·exfil ▶"
		ramp = dirColor // green→amber direction
	}
	x := drawText(s, marginX, y, def, label)
	x = drawText(s, x, y, def, left)
	for i, n := 0, len(sparkGlyphs); i < n && x < maxX; i++ {
		frac := float64(i) / float64(n-1)
		drawText(s, x, y, tcell.StyleDefault.Foreground(ramp(frac)), string(sparkGlyphs[i]))
		x++
	}
	if x < maxX {
		drawText(s, x, y, def, right)
	}
}

// rowSpark returns the (out, in) rate history for whichever tree level this row is.
func rowSpark(row egressRow) (out, in []uint64) {
	switch {
	case row.conn != nil:
		return row.conn.Spark, row.conn.InSpark
	case row.member != nil:
		return row.member.Spark, row.member.InSpark
	default:
		return row.group.Spark, row.group.InSpark
	}
}

// framePeak is the loudest relevant rate across all visible rows this frame — the share-of-peak
// denominator for temperature coloring. Combined mode colors by direction, not temperature, so 0.
func framePeak(rows []egressRow, mode trendMode) uint64 {
	if mode == trendCombined {
		return 0
	}
	var peak uint64
	for _, row := range rows {
		out, in := rowSpark(row)
		vals := out
		if mode == trendIn {
			vals = in
		}
		for _, v := range vals {
			if v > peak {
				peak = v
			}
		}
	}
	return peak
}

// trendSeries builds the (heights, colors) a row's TREND cell renders for the mode: out/in plot
// that direction with share-of-peak temperature; combined plots out+in height with direction color.
func trendSeries(out, in []uint64, mode trendMode, peak, width int) (heights []uint64, colors []tcell.Color) {
	switch mode {
	case trendIn:
		h := downsample(in, width)
		c := make([]tcell.Color, len(h))
		for i, v := range h {
			c[i] = tempColor(v, uint64(peak))
		}
		return h, c
	case trendCombined:
		ov, iv := downsample(out, width), downsample(in, width)
		h := make([]uint64, len(ov))
		c := make([]tcell.Color, len(ov))
		for i := range ov {
			var inv uint64
			if i < len(iv) {
				inv = iv[i]
			}
			h[i] = ov[i] + inv
			c[i] = directionColor(ov[i], inv)
		}
		return h, c
	default: // trendOut
		h := downsample(out, width)
		c := make([]tcell.Color, len(h))
		for i, v := range h {
			c[i] = tempColor(v, uint64(peak))
		}
		return h, c
	}
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
	// Header band: a rule under the title, the column headers, then a rule under the headers, so
	// the title, the labels and the values each read as their own pane (not one dense block).
	drawHRule(s, 1, w)
	headerY := 2
	drawText(s, cols.appX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("APP / PROCESS", cols.appW))
	drawText(s, cols.trustX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("TRUST", trustW))
	drawText(s, cols.rateX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("OUT↑", rateW))
	drawText(s, cols.trendX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("TREND "+trendGlyph(m.Trend), trendW))
	drawText(s, cols.destX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("DESTINATIONS", cols.destW))
	drawText(s, cols.concernX, headerY, tcell.StyleDefault.Foreground(colDim), truncate("CONCERN", concernW))
	drawHRule(s, 3, w)
	tableTop := 4

	rows := m.visibleRows()
	detail := detailLines(rows, m.Selected, w-marginX-marginR)

	// Bottom deck, anchored to the last row and stacked upward: usage guide, a rule, the trend
	// legend, a rule, the detail block, and a rule that closes the table off from it. Each rule is
	// only drawn if it clears the header band, so a short terminal degrades by dropping the
	// lowest-priority separators rather than overprinting the table.
	footerY := h - 1
	legendUsageRuleY := footerY - 1
	legendY := footerY - 2
	detailLegendRuleY := legendY - 1
	tableBottom := detailLegendRuleY - 1 // with no detail, this rule doubles as the table|legend split
	if len(detail) > 0 {
		detailBottom := detailLegendRuleY - 1
		detailTop := detailBottom - len(detail) + 1
		tableDetailRuleY := detailTop - 1
		tableBottom = tableDetailRuleY - 1
		for i, line := range detail {
			y := detailTop + i
			if y <= tableTop { // never draw the detail over the table/header on a tiny terminal
				continue
			}
			drawText(s, marginX, y, tcell.StyleDefault.Foreground(colDim), model.Clean(truncate(line, w-marginX-marginR)))
		}
		drawHRule(s, tableDetailRuleY, w)
	}

	if len(rows) == 0 {
		hint := collectingHint // haven't sampled yet — don't accuse the user of a misconfig
		if m.sampled {
			hint = emptyHint // sampled and genuinely empty — now the sudo remediation is earned
		}
		cy := (tableTop + tableBottom) / 2
		cx := (w - len([]rune(hint))) / 2
		if cx < 0 {
			cx = 0
		}
		drawText(s, cx, cy, tcell.StyleDefault.Foreground(colDim), hint)
	} else {
		peak := int(framePeak(rows, m.Trend)) // share-of-peak denominator, once per frame
		y := tableTop
		for i, row := range rows {
			if y > tableBottom {
				break
			}
			drawEgressRow(s, cols, w, y, row, i == m.Selected, m.expanded, m.expandedPID, m.Trend, peak)
			y++
		}
	}

	if legendY > tableTop { // skip the legend + its rule if there's no room above the footer
		drawHRule(s, detailLegendRuleY, w)
		drawTrendLegend(s, legendY, w-marginR, m.Trend)
	}
	drawHRule(s, legendUsageRuleY, w)
	drawText(s, marginX, footerY, tcell.StyleDefault.Foreground(colDim), truncate(footerHint, w-marginX-marginR))
}

// drawHRule draws a thin panel-divider rule across the content columns at row y — a light separator
// between sections, not a full box (no verticals/corners). Guarded so it never lands on the title
// row or off-screen.
func drawHRule(s tcell.Screen, y, w int) {
	if y < 1 {
		return
	}
	n := w - marginX - marginR
	if n < 1 {
		return
	}
	drawText(s, marginX, y, tcell.StyleDefault.Foreground(colDivider), strings.Repeat("─", n))
}

// drawEncGlyph places the encryption annotation for a destination port at (x,y) — a key (⚿) for a
// TLS port, a slashed key for cleartext, nothing for an unknown port (a port-only heuristic, no
// capture). Returns the columns consumed (0 or 2) so the caller can shift following text.
func drawEncGlyph(s tcell.Screen, x, y int, style tcell.Style, port int) int {
	base, comb := mark.EncGlyph(mark.PortEnc(port))
	if base == 0 {
		return 0
	}
	s.SetContent(x, y, base, comb, style)
	return 2
}

func drawEgressRow(s tcell.Screen, cols egressCols, w, y int, row egressRow, selected bool, expanded map[string]bool, expandedPID map[int]bool, mode trendMode, peak int) {
	g := row.group
	var depth int
	var marker rune
	var label, trust, rate, dest string
	var concernText string
	var encPort int // destination port for the row's shown destination (0 = no dest / no glyph)
	color := concernColor(g.Concern)

	switch {
	case row.member == nil: // app header
		depth = 0
		marker = collapsedMarker(expanded[g.App])
		label = g.App
		trust = g.Trust
		rate = human(g.OutRate) + "/s"
		dest = topDest(g)
		concernText = g.Concern.String()
		if c := busiestConn(g.Conns); c != nil {
			encPort = c.Endpoint.Port
		}
	case row.conn == nil: // instance row
		mem := row.member
		depth = 1
		marker = collapsedMarker(expandedPID[mem.PID])
		label = fmt.Sprintf("pid %d %s", mem.PID, shortPath(mem.Path))
		trust = mem.Trust
		rate = human(mem.OutRate) + "/s"
	default: // connection row (leaf)
		c := row.conn
		depth = 2
		marker = '·'
		dest = fmt.Sprintf("%s %s:%d", strings.ToUpper(c.Proto), c.Endpoint.IP, c.Endpoint.Port)
		encPort = c.Endpoint.Port
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
	trustGlyph := ""
	if tg := mark.TrustLabel(trust); tg != 0 {
		trustGlyph = string(tg)
	}
	drawText(s, cols.trustX, y, style, trustGlyph)
	drawText(s, cols.rateX, y, style, truncate(rate, rateW))
	out, in := rowSpark(row)
	heights, colors := trendSeries(out, in, mode, peak, trendW)
	drawTrend(s, cols.trendX, y, heights, colors, trendW, selected)
	shift := 0
	if dest != "" && encPort > 0 {
		shift = drawEncGlyph(s, cols.destX, y, style, encPort)
	}
	drawText(s, cols.destX+shift, y, style, model.Clean(truncate(dest, cols.destW-shift)))
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
