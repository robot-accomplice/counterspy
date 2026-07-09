package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

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
