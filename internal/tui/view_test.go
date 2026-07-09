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
