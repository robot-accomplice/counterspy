package interpret

import (
	"testing"

	"counterspy/internal/model"
)

func tccEv(service, summary string) model.Evidence {
	return model.Evidence{Kind: model.KindTCC, Summary: summary, Facts: map[string]string{"service": service}}
}

// Keylogger shape: Input Monitoring + Accessibility, high score → Quarantine.
func TestAssess_KeyloggerShapeQuarantine(t *testing.T) {
	f := model.Finding{
		Subject:  model.Subject{Path: "/tmp/k"},
		Score:    12,
		Kinds:    []model.SignalKind{model.KindTCC},
		Evidence: []model.Evidence{tccEv("kTCCServiceListenEvent", "holds Input Monitoring"), tccEv("kTCCServiceAccessibility", "holds Accessibility")},
	}
	a := Assess([]model.Finding{f})
	if a[0].Category != "keylogger" {
		t.Errorf("category=%q want keylogger", a[0].Category)
	}
	if a[0].Recommendation != model.RecQuarantine {
		t.Errorf("recommendation=%q want Quarantine (score>=HighTier)", a[0].Recommendation)
	}
	if a[0].Verdict == "" {
		t.Error("verdict must be composed from the signals")
	}
}

// A tripwire always recommends Quarantine regardless of score.
func TestAssess_TripwireQuarantines(t *testing.T) {
	f := model.Finding{Subject: model.Subject{Path: "/tmp/b"}, Score: 3, Tripwire: "unsigned+persistence+listener"}
	if a := Assess([]model.Finding{f}); a[0].Recommendation != model.RecQuarantine {
		t.Errorf("tripwire must Quarantine, got %q", a[0].Recommendation)
	}
}

// Low, single-signal → Monitor.
func TestAssess_LowScoreMonitor(t *testing.T) {
	f := model.Finding{
		Subject:  model.Subject{PID: 5},
		Score:    2,
		Evidence: []model.Evidence{{Kind: model.KindProcess, Summary: "active network connection"}},
	}
	if a := Assess([]model.Finding{f}); a[0].Recommendation != model.RecMonitor {
		t.Errorf("recommendation=%q want Monitor", a[0].Recommendation)
	}
}
