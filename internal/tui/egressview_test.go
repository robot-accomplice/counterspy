package tui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/mark"
	"counterspy/internal/model"
)

// Expanding an app can push rows past the bottom edge; the tree must scroll to keep the selected
// row on-screen (it had no viewport — the overflow was just clipped). With the selection at the
// end and far more rows than fit, a top row scrolls off and a near-selection row stays visible.
func TestEgressView_ScrollsToKeepSelectionVisible(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 16) // far fewer visible rows than we create
	var groups []model.EgressGroup
	for i := 0; i < 40; i++ {
		groups = append(groups, eg(fmt.Sprintf("zz%02d", i), model.Low, uint64(i+1)))
	}
	m := NewEgress().withGroups(groups)
	rows := m.visibleRows()
	m.Selected = len(rows) - 1 // select the very last row
	egressView(m, s)
	s.Show()

	top := rows[0].group.App               // should scroll off (only appears if its row renders)
	nearSel := rows[len(rows)-2].group.App // near the selection, NOT the selected row (so not in the detail strip)
	if simContains(s, top) {
		t.Fatalf("top row %q must scroll off when the selection is at the bottom (no viewport)", top)
	}
	if !simContains(s, nearSel) {
		t.Fatalf("a row near the selection %q must stay visible", nearSel)
	}
}

// The encryption annotation: a TLS port draws the sealed box (2 cols), a cleartext port the open
// box, and an unknown port nothing (0 cols) — a port-only heuristic.
func TestDrawEncGlyph(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(20, 3)
	st := tcell.StyleDefault

	if n := drawEncGlyph(s, 0, 0, st, 443); n != 2 {
		t.Fatalf("a TLS port must consume 2 columns, got %d", n)
	}
	if r, _, _, _ := s.GetContent(0, 0); r != mark.GlyphEncrypted {
		t.Fatalf("TLS = sealed box, got %q", r)
	}
	drawEncGlyph(s, 0, 1, st, 80)
	if r, _, _, _ := s.GetContent(0, 1); r != mark.GlyphCleartext {
		t.Fatalf("cleartext = the open-box glyph, got %q", r)
	}
	if n := drawEncGlyph(s, 0, 2, st, 27123); n != 0 {
		t.Fatalf("an unknown port must draw nothing (0 cols), got %d", n)
	}
	if r, _, _, _ := s.GetContent(0, 2); r != ' ' && r != 0 {
		t.Fatalf("unknown port must leave the cell blank, got %q", r)
	}
}

func TestConcernColor_AllLevelsDistinct(t *testing.T) {
	levels := []model.ConcernLevel{model.Minimal, model.Low, model.Notable, model.Elevated}
	seen := map[tcell.Color]bool{}
	for _, l := range levels {
		c := concernColor(l)
		if seen[c] {
			t.Fatalf("concernColor(%v) reused a color already assigned to another level", l)
		}
		seen[c] = true
	}
	if concernColor(model.Elevated) != colQuarantine {
		t.Fatal("Elevated should map to colQuarantine")
	}
	if concernColor(model.Notable) != colInvestigate {
		t.Fatal("Notable should map to colInvestigate")
	}
	if concernColor(model.Low) != colMonitor {
		t.Fatal("Low should map to colMonitor")
	}
	if concernColor(model.Minimal) != colDim {
		t.Fatal("Minimal (default) should map to colDim")
	}
}

func TestSparkline_Empty(t *testing.T) {
	if got := sparkline(nil); got != "" {
		t.Fatalf("empty input should render empty string, got %q", got)
	}
	if got := sparkline([]uint64{}); got != "" {
		t.Fatalf("empty slice should render empty string, got %q", got)
	}
}

func TestSparkline_VaryingValuesMapToRamp(t *testing.T) {
	got := sparkline([]uint64{0, 50, 100})
	r := []rune(got)
	if len(r) != 3 {
		t.Fatalf("expected 3 glyphs, got %d (%q)", len(r), got)
	}
	if r[0] != sparkGlyphs[0] {
		t.Fatalf("min value should render lowest glyph, got %q", string(r[0]))
	}
	if r[2] != sparkGlyphs[len(sparkGlyphs)-1] {
		t.Fatalf("max value should render highest glyph, got %q", string(r[2]))
	}
}

func TestSparkline_AllEqualValues(t *testing.T) {
	got := sparkline([]uint64{7, 7, 7, 7})
	r := []rune(got)
	if len(r) != 4 {
		t.Fatalf("expected 4 glyphs, got %d", len(r))
	}
	for _, g := range r {
		if g != r[0] {
			t.Fatalf("all-equal values should render identical glyphs, got %q", got)
		}
	}
}

func TestHeatColor_BlueToRedRamp(t *testing.T) {
	cool := tcell.NewRGBColor(60, 130, 246) // blue
	hot := tcell.NewRGBColor(235, 70, 70)   // red
	if heatColor(0) != cool {
		t.Fatalf("frac 0 should be the blue cool stop, got %v", heatColor(0))
	}
	if heatColor(-0.5) != cool {
		t.Fatal("negative frac should clamp to the blue cool stop")
	}
	if heatColor(1) != hot {
		t.Fatalf("frac 1 should be the red hot stop, got %v", heatColor(1))
	}
	if heatColor(2) != hot {
		t.Fatal("frac >1 should clamp to the red hot stop")
	}
	// Blue at the cool end, red at the hot end: the cool color is blue-dominant, the hot
	// color is red-dominant, and they are clearly distinct.
	cr, _, cb := heatColor(0).RGB()
	hr, _, hb := heatColor(1).RGB()
	if cb <= cr {
		t.Fatalf("cool end should be blue-dominant (b>r), got r=%d b=%d", cr, cb)
	}
	if hr <= hb {
		t.Fatalf("hot end should be red-dominant (r>b), got r=%d b=%d", hr, hb)
	}
	// As intensity rises the color gets warmer: red-minus-blue increases end to end.
	if (hr - hb) <= (cr - cb) {
		t.Fatal("hot end should be warmer than cool end (higher red-minus-blue)")
	}
}

func TestDrawTrend_HeightsAndColors(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	defer s.Fini()
	heights := []uint64{0, 100}
	colors := []tcell.Color{heatColor(0), heatColor(1)}
	drawTrend(s, 0, 0, heights, colors, 2, false)
	s.Show()
	cells, _, _ := s.GetContents()
	// Height is relative to the series' own max: min → lowest glyph, max → tallest.
	if cells[0].Runes[0] != sparkGlyphs[0] {
		t.Fatalf("min height should be the lowest glyph, got %q", string(cells[0].Runes))
	}
	if cells[1].Runes[0] != sparkGlyphs[len(sparkGlyphs)-1] {
		t.Fatalf("max height should be the tallest glyph, got %q", string(cells[1].Runes))
	}
	// Each cell wears its own supplied color.
	fg0, _, _ := cells[0].Style.Decompose()
	fg1, _, _ := cells[1].Style.Decompose()
	want0, _, _ := tcell.StyleDefault.Foreground(heatColor(0)).Decompose()
	want1, _, _ := tcell.StyleDefault.Foreground(heatColor(1)).Decompose()
	if fg0 != want0 || fg1 != want1 {
		t.Fatal("drawTrend must apply the per-cell colors it is given")
	}
	// Empty heights draw nothing.
	s2 := tcell.NewSimulationScreen("")
	if err := s2.Init(); err != nil {
		t.Fatal(err)
	}
	defer s2.Fini()
	drawTrend(s2, 0, 0, nil, nil, 8, false)
	s2.Show()
	c2, _, _ := s2.GetContents()
	for _, g := range sparkGlyphs {
		if len(c2[0].Runes) > 0 && c2[0].Runes[0] == g {
			t.Fatal("empty heights should draw no glyph")
		}
	}
}

func TestTopDest_ZeroOneMany(t *testing.T) {
	if got := topDest(model.EgressGroup{}); got != "—" {
		t.Fatalf("zero destinations should render em-dash, got %q", got)
	}
	one := model.EgressGroup{Destinations: []model.Endpoint{{IP: "1.2.3.4", Port: 443}}}
	if got := topDest(one); got != "1.2.3.4:443" {
		t.Fatalf("one destination should render plainly, got %q", got)
	}
	many := model.EgressGroup{Destinations: []model.Endpoint{
		{IP: "1.2.3.4", Port: 443}, {IP: "5.6.7.8", Port: 80}, {IP: "9.9.9.9", Port: 53},
	}}
	if got := topDest(many); got != "1.2.3.4:443 +2" {
		t.Fatalf("multiple destinations should show +N extra, got %q", got)
	}
}

func TestHuman_Thresholds(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1 << 10, "1 KB"},
		{1536, "2 KB"}, // rounds via %.0f
		{1 << 20, "1.0 MB"},
		{3 * (1 << 20), "3.0 MB"},
	}
	for _, c := range cases {
		if got := human(c.in); got != c.want {
			t.Errorf("human(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBgLabel_Both(t *testing.T) {
	if got := bgLabel(true); got != "background daemon" {
		t.Fatalf("bgLabel(true) = %q", got)
	}
	if got := bgLabel(false); got != "foreground app" {
		t.Fatalf("bgLabel(false) = %q", got)
	}
}

func TestEgressView_NarrowTerminalGuard(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(22, 8) // width < 24, but still wide enough to render the warning text
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 10)})
	egressView(m, s)
	s.Show()
	if !simContains(s, "terminal too small") {
		t.Fatal("expected the too-small warning for a narrow terminal")
	}
}

func TestEgressView_ExpandedRowsAndDetail(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	g := eg("agent", model.Elevated, 900)
	g.Capabilities = []string{"screen", "keystrokes"}
	g.Candidate = []string{"credentials"}
	g.ExfilRisk = model.Notable
	g.Ancestry = "launchd -> agent"
	g.Instances = 2
	m := NewEgress().withGroups([]model.EgressGroup{g})
	// Expand the (only, selected) group so its child conn row renders too.
	m, _ = egressUpdate(m, tcell.KeyEnter, 0)
	egressView(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "pid ") {
		t.Fatalf("expanded group should show a child connection row:\n%s", out)
	}
	if !strings.Contains(out, "−") {
		t.Fatalf("expanded marker should be the '−' disclosure control (▸/▾ retired; ▸ reserved for liveness):\n%s", out)
	}
	if !strings.Contains(out, "launchd -> agent") {
		t.Fatalf("detail strip should show ancestry:\n%s", out)
	}
	if !strings.Contains(out, "can access") || !strings.Contains(out, "credentials") {
		t.Fatalf("detail strip should show capabilities/candidate when present:\n%s", out)
	}
}

func TestEgressView_FooterKeybindsPresent(t *testing.T) {
	s := simScreen(t)
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 10)})
	egressView(m, s)
	s.Show()
	out := screenText(s)
	// ⇥ switch lives here with the other hints (moved off the top tab bar), and the whole hint fits.
	for _, want := range []string{"⇥ switch", "j/k", "↵/→ expand", "← collapse", "s sort", "/ filter", "p pause", "Q quit"} {
		if !strings.Contains(out, want) {
			t.Fatalf("footer keybind hint missing %q:\n%s", want, out)
		}
	}
}

func TestEgressView_EmptyState(t *testing.T) {
	s := simScreen(t)
	m := NewEgress().withGroups(nil) // a completed sample that found nothing
	egressView(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "No outbound traffic observed — run with sudo for full visibility.") {
		t.Fatalf("expected empty-state hint, got:\n%s", out)
	}
}

// Before the first sample returns, the view must NOT accuse the user of a misconfiguration: it
// shows a neutral "collecting" message, not the "run with sudo" remediation (which only makes
// sense once we've actually sampled and genuinely found nothing).
func TestEgressView_CollectingBeforeFirstSample(t *testing.T) {
	s := simScreen(t)
	m := NewEgress() // never sampled yet
	egressView(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "Collecting") {
		t.Fatalf("expected a collecting message before the first sample, got:\n%s", out)
	}
	if strings.Contains(out, "sudo") {
		t.Fatalf("must NOT show the sudo remediation before we've sampled, got:\n%s", out)
	}
}

func TestEgressView_SparklineDownsampledAndColumnsAligned(t *testing.T) {
	s := simScreen(t) // 120x40
	spark := make([]uint64, 24)
	for i := range spark {
		spark[i] = uint64(i)
	}
	g := eg("a", model.Low, 10)
	g.Spark = spark
	m := NewEgress().withGroups([]model.EgressGroup{g})
	egressView(m, s)
	s.Show()

	cols := computeCols(120)
	row := 4 // first data row (0 title, 1 rule, 2 header, 3 rule, 4 first group)

	glyphs := 0
	for x := cols.trendX; x < cols.trendX+trendW; x++ {
		r, _, _, _ := s.GetContent(x, row)
		if r != ' ' && r != 0 {
			glyphs++
		}
	}
	if glyphs > trendW {
		t.Fatalf("sparkline overflowed its %d-wide column: found %d glyphs", trendW, glyphs)
	}
	if glyphs == 0 {
		t.Fatal("expected the sparkline to render at least one glyph")
	}

	var concern strings.Builder
	for x := cols.concernX; x < cols.concernX+concernW; x++ {
		r, _, _, _ := s.GetContent(x, row)
		if r == 0 {
			r = ' '
		}
		concern.WriteRune(r)
	}
	if !strings.Contains(concern.String(), model.Low.String()) {
		t.Fatalf("CONCERN column misaligned, got %q at x=%d", concern.String(), cols.concernX)
	}
}

// The exfil view is split into panes by light rules: one under the title (row 1), one under the
// column headers (row 3), and one directly above the footer usage line — so the title, labels,
// values, and controls read as separate sections instead of one dense block.
func TestEgressView_SectionSeparators(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	const h = 40
	s.SetSize(120, h)
	m := NewEgress().withGroups([]model.EgressGroup{eg("backuptool", model.Elevated, 900)})
	m.Selected = 0 // select the app row so the detail pane (and its rule) render too
	egressView(m, s)
	s.Show()

	isRule := func(y int) bool {
		r, _, _, _ := s.GetContent(marginX, y)
		return r == '─'
	}
	if !isRule(1) {
		t.Error("expected a rule between the title and the column headers (row 1)")
	}
	if !isRule(3) {
		t.Error("expected a rule between the column headers and the values (row 3)")
	}
	if !isRule(h - 2) {
		t.Error("expected a rule between the legend and the usage guide (row h-2)")
	}
	// The headers moved down a row to make room for the title rule.
	if r, _, _, _ := s.GetContent(computeCols(120).appX, 2); r != 'A' {
		t.Errorf("APP / PROCESS header should sit on row 2, got %q", r)
	}
}

func TestDownsample_PassThroughWhenAlreadyWithinWidth(t *testing.T) {
	in := []uint64{1, 2, 3}
	got := downsample(in, 10)
	if len(got) != 3 {
		t.Fatalf("short input should pass through unchanged, got %d values", len(got))
	}
}

func TestDownsample_BucketsDownToWidth(t *testing.T) {
	in := make([]uint64, 24)
	for i := range in {
		in[i] = uint64(i)
	}
	got := downsample(in, 8)
	if len(got) != 8 {
		t.Fatalf("expected 8 buckets, got %d", len(got))
	}
}

func TestComputeCols_ColumnsAscendAndFitWidth(t *testing.T) {
	c := computeCols(120)
	xs := []int{c.markerX, c.appX, c.trustX, c.rateX, c.trendX, c.destX, c.concernX}
	for i := 1; i < len(xs); i++ {
		if xs[i] <= xs[i-1] {
			t.Fatalf("columns must be strictly increasing left-to-right, got %v", xs)
		}
	}
	if end := c.concernX + concernW; end > 120 {
		t.Fatalf("CONCERN column overflows terminal width: ends at %d, want <= 120", end)
	}
}

// Task 8: the egress tree toggle uses +/- (a disclosure control), never ▸ (which is
// reserved for the liveness "active" mark) — resolving that glyph collision.
func TestEgressTreeTogglesWithPlusMinus(t *testing.T) {
	if got := collapsedMarker(false); got != '+' {
		t.Errorf("collapsed marker: got %q want +", got)
	}
	if got := collapsedMarker(true); got != '−' {
		t.Errorf("expanded marker: got %q want −", got)
	}
	if collapsedMarker(false) == '▸' || collapsedMarker(true) == '▸' {
		t.Error("tree toggle must not reuse ▸ (liveness-active)")
	}
}

// A fully-expanded tree (app → instance → connection) renders the connection leaf row, which
// draws that connection's OWN sparkline (covers the leaf spark path).
func TestEgressView_ConnLeafRendersSpark(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(140, 30)
	g := eg("app", model.Low, 5000)
	g.Members[0].Conns[0].Spark = []uint64{100, 5000} // this connection's own trend
	m := NewEgress().withGroups([]model.EgressGroup{g})
	m.expanded = map[string]bool{"app": true}
	m.expandedPID = map[int]bool{100: true}
	egressView(m, s)
	s.Show()
	if !simContains(s, "1.2.3.4") {
		t.Fatal("connection leaf row (with its own sparkline) should render its destination")
	}
}

func TestTempColor_ShareOfPeak(t *testing.T) {
	hot := tempColor(1000, 1000)
	cold := tempColor(1, 1000)
	if hot == cold {
		t.Fatal("peak and trickle must differ")
	}
	if hot != heatColor(1.0) || cold != heatColor(1.0/1000.0) {
		t.Fatalf("tempColor must be heatColor(rate/peak): hot=%v cold=%v", hot, cold)
	}
	_ = tempColor(0, 0) // no traffic — no divide-by-zero
}

func TestDirectionColor(t *testing.T) {
	amber := directionColor(1000, 0)
	green := directionColor(0, 1000)
	if amber == green {
		t.Fatal("all-out and all-in must differ (amber vs green)")
	}
	if amber != dirColor(1.0) || green != dirColor(0.0) {
		t.Fatalf("directionColor must map out/(out+in) through dirColor: amber=%v green=%v", amber, green)
	}
	_ = directionColor(0, 0) // no traffic — no divide-by-zero
}

func TestTrendSeries_Combined(t *testing.T) {
	out := []uint64{100, 200}
	in := []uint64{50, 0}
	heights, colors := trendSeries(out, in, trendCombined, 250, 2)
	if heights[0] != 150 || heights[1] != 200 {
		t.Fatalf("combined height must be out+in, got %v", heights)
	}
	if colors[0] != directionColor(100, 50) || colors[1] != directionColor(200, 0) {
		t.Fatal("combined color must be directionColor(out,in)")
	}
}

func TestTrendSeries_OutAndInUseTemperature(t *testing.T) {
	out := []uint64{100}
	in := []uint64{40}
	// out mode plots out with share-of-peak temperature.
	oh, oc := trendSeries(out, in, trendOut, 100, 1)
	if oh[0] != 100 || oc[0] != tempColor(100, 100) {
		t.Fatalf("out mode: height=out, color=tempColor(out,peak), got h=%v c=%v", oh, oc)
	}
	// in mode plots in.
	ih, ic := trendSeries(out, in, trendIn, 100, 1)
	if ih[0] != 40 || ic[0] != tempColor(40, 100) {
		t.Fatalf("in mode: height=in, color=tempColor(in,peak), got h=%v c=%v", ih, ic)
	}
}

func TestFramePeak_MaxAcrossRowsPerMode(t *testing.T) {
	g1 := eg("a", model.Low, 10)
	g1.Spark, g1.InSpark = []uint64{100}, []uint64{5}
	g2 := eg("b", model.Low, 10)
	g2.Spark, g2.InSpark = []uint64{40}, []uint64{500}
	rows := NewEgress().withGroups([]model.EgressGroup{g1, g2}).visibleRows()
	if p := framePeak(rows, trendOut); p != 100 {
		t.Fatalf("out peak = loudest out across rows, got %d", p)
	}
	if p := framePeak(rows, trendIn); p != 500 {
		t.Fatalf("in peak = loudest in across rows, got %d", p)
	}
	if p := framePeak(rows, trendCombined); p != 0 {
		t.Fatalf("combined uses direction color, not temperature — peak should be 0, got %d", p)
	}
}

// The mode must actually reach the rendered tree: egressView has to thread m.Trend (and the frame
// peak) into drawEgressRow → trendSeries. A group whose out and in histories have DIFFERENT shapes
// must render DIFFERENT trend glyphs in out vs in mode; identical output would mean the view
// ignores the toggle (the Rule-10 gap the pure trendSeries tests can't catch). (cp-tr2 Audit F-1)
func TestEgressView_TrendModeReachesTheTree(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	g := eg("x", model.Low, 10)
	g.Spark = []uint64{0, 0, 100}   // out: rising
	g.InSpark = []uint64{100, 0, 0} // in: falling — a different shape
	m := NewEgress().withGroups([]model.EgressGroup{g})

	trendGlyphs := func(mode trendMode) string {
		m.Trend = mode
		egressView(m, s)
		s.Show()
		cells, w, _ := s.GetContents()
		cols := computeCols(w)
		var b []rune
		for i := 0; i < trendW; i++ { // app-header data row is at y=2 (tableTop)
			b = append(b, cells[2*w+cols.trendX+i].Runes...)
		}
		return string(b)
	}
	if trendGlyphs(trendOut) == trendGlyphs(trendIn) {
		t.Fatal("out and in modes must render different trend shapes — egressView must thread m.Trend through")
	}
}

func screenHasColor(s tcell.SimulationScreen, want tcell.Color) bool {
	cells, _, _ := s.GetContents()
	for _, c := range cells {
		fg, _, _ := c.Style.Decompose()
		if fg == want {
			return true
		}
	}
	return false
}

func TestEgressView_TrendLegendAndHeader(t *testing.T) {
	render := func(mode trendMode) tcell.SimulationScreen {
		s := tcell.NewSimulationScreen("")
		if err := s.Init(); err != nil {
			t.Fatal(err)
		}
		s.SetSize(120, 40)
		m := NewEgress().withGroups([]model.EgressGroup{eg("x", model.Low, 10)})
		m.Trend = mode
		egressView(m, s)
		s.Show()
		return s
	}
	out, in, comb := render(trendOut), render(trendIn), render(trendCombined)

	// Header glyph per mode — the single-source trendGlyph reaches the column header.
	if !simContains(out, "TREND ↑") {
		t.Fatal("out header must show TREND ↑")
	}
	if !simContains(in, "TREND ↓") {
		t.Fatal("in header must show TREND ↓")
	}
	if !simContains(comb, "TREND ⇅") {
		t.Fatal("combined header must show TREND ⇅")
	}

	// Legend labels per mode (volume vs direction).
	if !simContains(out, "quiet") || !simContains(out, "loud") {
		t.Fatal("out legend must label the volume ramp (quiet → loud)")
	}
	if simContains(out, "download") {
		t.Fatal("out mode must NOT show the direction labels")
	}
	if !simContains(comb, "combined") {
		t.Fatal("combined legend must name the mode (Audit F-1: the word was dropped)")
	}
	if !simContains(comb, "download") || !simContains(comb, "exfil") {
		t.Fatal("combined legend must label the direction ramp (download → exfil)")
	}
	if !simContains(out, "t trend") {
		t.Fatal("footer must advertise the t toggle")
	}

	// The legend's COLOR ramp actually switches with the mode (Audit F-3): the green direction
	// stop (dirColor(0)) appears only in combined mode, never in the out/in heat ramp.
	green := dirColor(0)
	if !screenHasColor(comb, green) {
		t.Fatal("combined legend must use the green→amber direction ramp")
	}
	if screenHasColor(out, green) {
		t.Fatal("out legend must use the volume ramp, not the direction ramp")
	}
}

// On a degenerate small terminal with a selected row producing several detail lines, the shifted
// detail/legend must never overwrite the title/header row or panic (cp-tr3 Antagonist: the layout
// shift + tcell's bounds-checked SetContent; guard skips detail/legend at/above the header).
func TestEgressView_TinyTerminalNoHeaderClobber(t *testing.T) {
	for _, h := range []int{6, 7, 8, 10} {
		s := tcell.NewSimulationScreen("")
		if err := s.Init(); err != nil {
			t.Fatal(err)
		}
		s.SetSize(80, h)
		g := eg("agent", model.Elevated, 900)
		g.Capabilities = []string{"screen", "keystrokes"} // more detail lines
		g.Candidate = []string{"credentials"}
		g.Ancestry = "launchd → agent"
		m := NewEgress().withGroups([]model.EgressGroup{g})
		m.Selected = 0   // select the app header → detail lines render
		egressView(m, s) // must not panic
		s.Show()
		if !simContains(s, "CounterSpy") {
			t.Fatalf("h=%d: the title row must survive the shifted detail/legend", h)
		}
	}
}

// #3: destinations display the resolved name when present, else the bare IP; topDest too.
func TestEndpointHostAndTopDest_PreferName(t *testing.T) {
	if got := endpointHost(model.Endpoint{IP: "1.2.3.4"}); got != "1.2.3.4" {
		t.Fatalf("no name → IP, got %q", got)
	}
	if got := endpointHost(model.Endpoint{IP: "1.2.3.4", Name: "api.example.com"}); got != "api.example.com" {
		t.Fatalf("name present → name, got %q", got)
	}
	g := model.EgressGroup{Destinations: []model.Endpoint{{IP: "1.2.3.4", Port: 443, Name: "api.example.com"}}}
	if got := topDest(g); got != "api.example.com:443" {
		t.Fatalf("topDest should show name:port, got %q", got)
	}
	g2 := model.EgressGroup{Destinations: []model.Endpoint{{IP: "9.9.9.9", Port: 53}}}
	if got := topDest(g2); got != "9.9.9.9:53" {
		t.Fatalf("topDest nameless → IP:port, got %q", got)
	}
}
