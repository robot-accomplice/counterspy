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
