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
// labeled surveillance-capable (alarm fatigue). It's neutral and Monitor-tier.
func TestAssess_LoneGrantIsNeutralNotSpyware(t *testing.T) {
	f := model.Finding{
		Subject:  model.Subject{Label: "us.zoom.xos"},
		Score:    2,
		Evidence: []model.Evidence{tccEv("kTCCServiceScreenCapture", "holds Screen Recording")},
	}
	a := Assess([]model.Finding{f})
	if a[0].Category == "surveillance-capable" {
		t.Errorf("a lone grant must not be surveillance-capable, got %q", a[0].Category)
	}
	if a[0].Recommendation != model.RecMonitor {
		t.Errorf("recommendation=%q want Monitor", a[0].Recommendation)
	}
}

// A permission grant CORROBORATED by another signal IS surveillance-capable.
func TestAssess_CorroboratedGrantIsSpywareGeneric(t *testing.T) {
	f := model.Finding{
		Subject: model.Subject{Path: "/x"},
		Score:   6,
		Evidence: []model.Evidence{
			tccEv("kTCCServiceSystemPolicyAllFiles", "holds Full Disk Access"),
			{Kind: model.KindPersistence, Summary: "LaunchDaemon"},
		},
	}
	if a := Assess([]model.Finding{f}); a[0].Category != "surveillance-capable" {
		t.Errorf("full-disk + persistence should be surveillance-capable, got %q", a[0].Category)
	}
}

// C3: a Gatekeeper-accepted signed app (e.g. an EDR) with a strong shape must NOT be
// auto-Quarantined — capped at Investigate so the tool can't be weaponized to disable
// legitimate security software.
func TestAssess_SignedAcceptedNeverQuarantines(t *testing.T) {
	sub := model.Subject{Path: "/Applications/Falcon.app", Label: "com.crowdstrike.falcon"}
	in := []model.Evidence{
		{Subject: sub, Kind: model.KindCodesign, Weight: 0, Facts: map[string]string{"signed": "true", "authority": "Developer ID Application: CrowdStrike"}},
		tccEv("kTCCServiceListenEvent", "holds Input Monitoring"),
		tccEv("kTCCServiceAccessibility", "holds Accessibility"),
		{Subject: sub, Kind: model.KindPersistence, Summary: "LaunchDaemon"},
		{Subject: sub, Kind: model.KindProcess, Weight: 0, Facts: map[string]string{"listener": "true"}},
	}
	// force the evidence onto one subject
	for i := range in {
		in[i].Subject = sub
	}
	a := Assess([]model.Finding{{Subject: sub, Score: 12, Evidence: in}})
	if a[0].Recommendation == model.RecQuarantine {
		t.Fatalf("a Gatekeeper-accepted signed app must never auto-Quarantine, got %q", a[0].Recommendation)
	}
}

// C3: an unsigned persistence-only item (a dev's own tool) caps at Investigate, not
// Quarantine, without a tripwire — even above HighTier.
func TestAssess_UnsignedPersistenceOnlyCapsAtInvestigate(t *testing.T) {
	sub := model.Subject{Path: "/Users/me/.roboticus/roboticus"}
	in := []model.Finding{{
		Subject: sub, Score: 12,
		Evidence: []model.Evidence{
			{Subject: sub, Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}},
			{Subject: sub, Kind: model.KindPersistence, Summary: "user-level LaunchAgent"},
		},
	}}
	if a := Assess(in); a[0].Recommendation != model.RecInvestigate {
		t.Fatalf("unsigned persistence-only should cap at Investigate, got %q", a[0].Recommendation)
	}
}
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
