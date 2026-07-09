package tui

import (
	"testing"

	"counterspy/internal/model"
)

func mk(label string, rec model.Recommendation, score int) model.Assessment {
	// distinct Path per label so Subject.Key() is unique (cp-tui-1 Audit F-2)
	return model.Assessment{
		Finding:        model.Finding{Subject: model.Subject{Path: "/x/" + label, Label: label}, Score: score},
		Recommendation: rec, Category: "test",
	}
}

func TestVisible_HidesMonitorUntilToggled(t *testing.T) {
	m := New([]model.Assessment{
		mk("q1", model.RecQuarantine, 12),
		mk("m1", model.RecMonitor, 2),
	}, nil)
	if len(m.visible()) != 1 {
		t.Fatalf("monitor should be hidden by default, got %d", len(m.visible()))
	}
	m.ShowMonitor = true
	if len(m.visible()) != 2 {
		t.Fatalf("monitor should show when toggled, got %d", len(m.visible()))
	}
}

func TestVisible_FilterByName(t *testing.T) {
	m := New([]model.Assessment{mk("alpha", model.RecInvestigate, 6), mk("beta", model.RecInvestigate, 6)}, nil)
	m.Filter = "alph"
	if v := m.visible(); len(v) != 1 || v[0].Subject.Label != "alpha" {
		t.Fatalf("filter failed: %+v", v)
	}
}

// Measure visible() so the "keystroke lag" concern is grounded in numbers, not
// plausibility (ABORT-TUI Auditor/Attacker perf note).
func BenchmarkVisible(b *testing.B) {
	var as []model.Assessment
	for i := 0; i < 500; i++ {
		rec := model.RecInvestigate
		if i%3 == 0 {
			rec = model.RecMonitor
		}
		as = append(as, mk("item"+itoa(i), rec, 500-i))
	}
	m := New(as, nil)
	m.Filter = "item2"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.visible()
	}
}

func TestCounts(t *testing.T) {
	m := New([]model.Assessment{
		mk("q", model.RecQuarantine, 12), mk("i", model.RecInvestigate, 6),
		mk("m1", model.RecMonitor, 2), mk("m2", model.RecMonitor, 1),
	}, nil)
	q, inv, mon := m.counts()
	if q != 1 || inv != 1 || mon != 2 {
		t.Fatalf("counts wrong: %d/%d/%d", q, inv, mon)
	}
}
