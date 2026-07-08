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

// cp-9 Audit F-1: a lone permission grant on otherwise-quiet software must NOT be
// labeled spyware-generic (alarm fatigue). It's neutral and Monitor-tier.
func TestAssess_LoneGrantIsNeutralNotSpyware(t *testing.T) {
	f := model.Finding{
		Subject:  model.Subject{Label: "us.zoom.xos"},
		Score:    2,
		Evidence: []model.Evidence{tccEv("kTCCServiceScreenCapture", "holds Screen Recording")},
	}
	a := Assess([]model.Finding{f})
	if a[0].Category == "spyware-generic" {
		t.Errorf("a lone grant must not be spyware-generic, got %q", a[0].Category)
	}
	if a[0].Recommendation != model.RecMonitor {
		t.Errorf("recommendation=%q want Monitor", a[0].Recommendation)
	}
}

// A permission grant CORROBORATED by another signal IS spyware-generic.
func TestAssess_CorroboratedGrantIsSpywareGeneric(t *testing.T) {
	f := model.Finding{
		Subject: model.Subject{Path: "/x"},
		Score:   6,
		Evidence: []model.Evidence{
			tccEv("kTCCServiceSystemPolicyAllFiles", "holds Full Disk Access"),
			{Kind: model.KindPersistence, Summary: "LaunchDaemon"},
		},
	}
	if a := Assess([]model.Finding{f}); a[0].Category != "spyware-generic" {
		t.Errorf("full-disk + persistence should be spyware-generic, got %q", a[0].Category)
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
