package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

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
	if !strings.Contains(out, "▾") {
		t.Fatalf("expanded marker should be the down-caret:\n%s", out)
	}
	if !strings.Contains(out, "launchd -> agent") {
		t.Fatalf("detail strip should show ancestry:\n%s", out)
	}
	if !strings.Contains(out, "can access") || !strings.Contains(out, "credentials") {
		t.Fatalf("detail strip should show capabilities/candidate when present:\n%s", out)
	}
}

func TestSelectedRowIndex_OutOfRange(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 10)})
	m.Selected = 5 // out of range
	rows := m.visibleRows()
	if idx := selectedRowIndex(m, rows); idx != -1 {
		t.Fatalf("out-of-range selection should yield -1, got %d", idx)
	}
}
