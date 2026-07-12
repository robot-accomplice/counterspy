package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/mark"
	"counterspy/internal/model"
)

func TestView_RendersMarkCluster(t *testing.T) {
	s := simScreen(t)
	a := model.Assessment{
		Finding:        model.Finding{Subject: model.Subject{Path: "/tmp/xmrig", Label: "xmrig"}, Evidence: []model.Evidence{{Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}}}},
		Recommendation: model.RecQuarantine,
		Category:       "backdoor",
	}
	m := New([]model.Assessment{a}, nil)
	m.Liveness = map[string]mark.Liveness{"path:/tmp/xmrig": {RunState: mark.GlyphActive, Socket: mark.GlyphSocket}}
	view(m, s)
	s.Show()
	out := screenText(s)
	for _, g := range []string{"⚑", "○", "▸", "↔", "xmrig"} {
		if !strings.Contains(out, g) {
			t.Errorf("expected %q on the finding row:\n%s", g, out)
		}
	}
}

func TestView_HelpShowsMarkLegend(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("x", model.RecInvestigate, 6)}, nil)
	m.Focus = focusHelp
	view(m, s)
	s.Show()
	out := screenText(s)
	for _, want := range []string{"Marks", "unsigned", "vestigial", "revoked"} {
		if !strings.Contains(out, want) {
			t.Errorf("help overlay should list the mark legend (missing %q):\n%s", want, out)
		}
	}
}

func screenText(s tcell.SimulationScreen) string {
	cells, w, h := s.GetContents()
	var b strings.Builder
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r := cells[y*w+x].Runes
			if len(r) > 0 && r[0] != 0 {
				b.WriteRune(r[0])
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func simScreen(t *testing.T) tcell.SimulationScreen {
	t.Helper()
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	return s
}

func TestView_RendersSummaryAndHidesMonitor(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{
		mk("evil.updater", model.RecQuarantine, 14),
		mk("zoom", model.RecMonitor, 2),
	}, nil)
	view(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "CounterSpy") || !strings.Contains(out, "evil.updater") {
		t.Fatalf("summary/finding missing:\n%s", out)
	}
	if strings.Contains(out, "zoom") {
		t.Fatalf("monitor item should be hidden by default:\n%s", out)
	}
}

// Scroll viewport: the selected row stays visible even below the fold.
func TestView_ScrollKeepsSelectionVisible(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	s.Init()
	s.SetSize(120, 12) // small height → only a few list rows fit
	var as []model.Assessment
	for i := 0; i < 12; i++ {
		as = append(as, mk("item"+itoa(i), model.RecInvestigate, 6))
	}
	m := New(as, nil)
	m.Selected = 11 // last item, far below the fold
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "item11") {
		t.Fatalf("the selected (last) item must remain visible via scroll:\n%s", screenText(s))
	}
}

func TestView_DetailShowsAncestryAndBreakdown(t *testing.T) {
	s := simScreen(t)
	a := model.Assessment{
		Finding: model.Finding{
			Subject: model.Subject{Label: "beacon", PID: 777},
			Score:   6, Kinds: []model.SignalKind{model.KindProcess, model.KindCodesign},
			Evidence: []model.Evidence{
				{Kind: model.KindCodesign, Summary: "unsigned", Weight: 3, Facts: map[string]string{"signed": "false"}},
				{Kind: model.KindProcess, Summary: "listener", Weight: 2, Facts: map[string]string{"ancestry": "launchd -> python3"}},
			},
		},
		Category: "backdoor", Recommendation: model.RecInvestigate,
	}
	view(New([]model.Assessment{a}, nil), s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "launchd -> python3") {
		t.Errorf("detail should show the ancestry chain:\n%s", out)
	}
	if !strings.Contains(out, "= 5") { // breakdown: 3 + 2
		t.Errorf("detail should show the score breakdown:\n%s", out)
	}
}

func TestView_ReadOnlyBadge(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("x", model.RecInvestigate, 6)}, nil)
	m.ReadOnly = true
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "TRIAGE ONLY") {
		t.Fatalf("read-only should show a persistent badge:\n%s", screenText(s))
	}
}

func TestView_ModalShowsPlannedActions(t *testing.T) {
	s := simScreen(t)
	a := mk("com.evil", model.RecQuarantine, 14)
	a.Actions = []model.Action{
		{Kind: model.ActionBootout, From: "com.evil"},
		{Kind: model.ActionMove, From: "/x/beacon"},
	}
	m := New([]model.Assessment{a}, nil)
	m.Focus = focusModal
	m.Pending = a
	view(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "launchctl bootout com.evil") || !strings.Contains(out, "move /x/beacon") {
		t.Fatalf("modal should preview the planned actions:\n%s", out)
	}
}

func TestView_ModalShowsReversibility(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)
	m.Focus = focusModal
	m.Pending = m.Assessments[0]
	view(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "reversible") || !strings.Contains(out, "Quarantine evil?") {
		t.Fatalf("modal should show reversibility + subject:\n%s", out)
	}
}

func TestTierColor_AllThreeTiers(t *testing.T) {
	if tierColor(model.RecQuarantine) != colQuarantine {
		t.Fatal("RecQuarantine should map to colQuarantine")
	}
	if tierColor(model.RecInvestigate) != colInvestigate {
		t.Fatal("RecInvestigate should map to colInvestigate")
	}
	if tierColor(model.RecMonitor) != colMonitor {
		t.Fatal("RecMonitor (default) should map to colMonitor")
	}
}

func TestTruncate_EdgeCases(t *testing.T) {
	if got := truncate("hello", -3); got != "" {
		t.Fatalf("negative n should clamp to 0 chars, got %q", got)
	}
	if got := truncate("hi", 10); got != "hi" {
		t.Fatalf("short string should be unchanged, got %q", got)
	}
	if got := truncate("hello world", 8); got != "hello w…" {
		t.Fatalf("long string should truncate with ellipsis, got %q", got)
	}
	if got := truncate("x", 1); got != "x" {
		t.Fatalf("n<=1 should return the raw rune-cap without ellipsis, got %q", got)
	}
	if got := truncate("xy", 1); got != "x" {
		t.Fatalf("n<=1 should hard-cap to n runes, got %q", got)
	}
	// Multibyte-safe: truncation must cut on rune boundaries, not bytes.
	multi := "日本語のテキストです" // 10 runes, 3 bytes each
	if got := truncate(multi, 5); got != "日本語の…" {
		t.Fatalf("multibyte truncation should be rune-safe, got %q", got)
	}
	// Pathologically long input relative to n exercises the byte-cap guard.
	long := strings.Repeat("a", 10000)
	if got := truncate(long, 5); got != "aaaa…" {
		t.Fatalf("pathologically long input should still truncate correctly, got %q", got)
	}
}

func TestView_GapsRendered(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("x", model.RecInvestigate, 6)}, []string{"no TCC data available"})
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "no TCC data available") {
		t.Fatalf("gaps should be rendered as warnings:\n%s", screenText(s))
	}
}

func TestView_AllQuarantineHandledBanner(t *testing.T) {
	s := simScreen(t)
	a := mk("evil", model.RecQuarantine, 14)
	m := New([]model.Assessment{a}, nil)
	m.Done = map[string]bool{a.Subject.Key(): true}
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "all Quarantine-tier items handled") {
		t.Fatalf("banner should show once all quarantine items are handled:\n%s", screenText(s))
	}
}

func TestView_NarrowWidthGuard(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(20, 20) // width < 24
	m := New([]model.Assessment{mk("x", model.RecInvestigate, 6)}, nil)
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "terminal too narrow") {
		t.Fatalf("narrow width should show the resize warning:\n%s", screenText(s))
	}
}

func TestView_ShortHeightGuard(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(40, 5) // wide enough, but too short for the list viewport
	m := New([]model.Assessment{mk("x", model.RecInvestigate, 6)}, nil)
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "terminal too small") {
		t.Fatalf("short height should show the resize warning:\n%s", screenText(s))
	}
}

func TestView_NoFindingsMatchMessage(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("alpha", model.RecInvestigate, 6)}, nil)
	m.Filter = "nonexistent"
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "no findings match") {
		t.Fatalf("empty filtered list should say no findings match:\n%s", screenText(s))
	}
}

func TestView_MonitorHiddenMessage(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("zoom", model.RecMonitor, 2)}, nil)
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "monitored item(s) hidden") {
		t.Fatalf("all-monitor list should explain the hidden items:\n%s", screenText(s))
	}
}

func TestView_FilterFooterReplacesHelp(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("x", model.RecInvestigate, 6)}, nil)
	m.Focus = focusFilter
	m.Filter = "ali"
	view(m, s)
	s.Show()
	if !strings.Contains(screenText(s), "/ali_") {
		t.Fatalf("filter mode should show the live filter footer:\n%s", screenText(s))
	}
}

func TestView_HelpOverlayDrawn(t *testing.T) {
	s := simScreen(t)
	m := New([]model.Assessment{mk("x", model.RecInvestigate, 6)}, nil)
	m.Focus = focusHelp
	view(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "Keys") || !strings.Contains(out, "quarantine (confirm)") {
		t.Fatalf("help overlay should render its key reference:\n%s", out)
	}
}

func TestDrawDetail_TripwireAndDuplicateEvidence(t *testing.T) {
	s := simScreen(t)
	a := model.Assessment{
		Finding: model.Finding{
			Subject:  model.Subject{Label: "beacon"},
			Score:    9,
			Tripwire: "known C2 domain",
			Evidence: []model.Evidence{
				{Kind: model.KindProcess, Summary: "listener", Weight: 2, Facts: map[string]string{"argv": "-daemon"}},
				{Kind: model.KindProcess, Summary: "listener", Weight: 2}, // duplicate -> count 2
			},
		},
		Category: "backdoor", Recommendation: model.RecQuarantine,
	}
	view(New([]model.Assessment{a}, nil), s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "tripwire: known C2 domain") {
		t.Fatalf("detail should show the tripwire line:\n%s", out)
	}
	if !strings.Contains(out, "×2") {
		t.Fatalf("duplicate evidence should be deduped with a count suffix:\n%s", out)
	}
	if !strings.Contains(out, "-daemon") {
		t.Fatalf("detail should show the argv fact:\n%s", out)
	}
}

func TestDrawModal_ClampsToSmallScreen(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(30, 10) // smaller than the modal's natural 64-wide box
	a := mk("evil", model.RecQuarantine, 14)
	m := New([]model.Assessment{a}, nil)
	m.Focus = focusModal
	m.Pending = a
	view(m, s) // must not panic even though the modal box is clamped
	s.Show()
	if !strings.Contains(screenText(s), "Quarantine") {
		t.Fatalf("clamped modal should still render:\n%s", screenText(s))
	}
}
