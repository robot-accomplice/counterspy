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
	a := Assess([]model.Finding{f}, nil)
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
	if a := Assess([]model.Finding{f}, nil); a[0].Recommendation != model.RecQuarantine {
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
	a := Assess([]model.Finding{f}, nil)
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
	if a := Assess([]model.Finding{f}, nil); a[0].Category != "surveillance-capable" {
		t.Errorf("full-disk + persistence should be surveillance-capable, got %q", a[0].Category)
	}
}

// C3: a Gatekeeper-accepted signed app (e.g. an EDR) with a strong shape must NOT be
// auto-Quarantined, capped at Investigate so the tool can't be weaponized to disable
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
	a := Assess([]model.Finding{{Subject: sub, Score: 12, Evidence: in}}, nil)
	if a[0].Recommendation == model.RecQuarantine {
		t.Fatalf("a Gatekeeper-accepted signed app must never auto-Quarantine, got %q", a[0].Recommendation)
	}
}

// C3: an unsigned persistence-only item (a dev's own tool) caps at Investigate, not
// Quarantine, without a tripwire, even above HighTier.
func TestAssess_UnsignedPersistenceOnlyCapsAtInvestigate(t *testing.T) {
	sub := model.Subject{Path: "/Users/me/.roboticus/roboticus"}
	in := []model.Finding{{
		Subject: sub, Score: 12,
		Evidence: []model.Evidence{
			{Subject: sub, Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}},
			{Subject: sub, Kind: model.KindPersistence, Summary: "user-level LaunchAgent"},
		},
	}}
	if a := Assess(in, nil); a[0].Recommendation != model.RecInvestigate {
		t.Fatalf("unsigned persistence-only should cap at Investigate, got %q", a[0].Recommendation)
	}
}

// C3 false-negative fix: overwhelming signal on an unsigned weak-category subject still
// Quarantines (a high-scoring unsigned persistent infostealer isn't capped forever).
func TestAssess_UnsignedWeakHighScoreStillQuarantines(t *testing.T) {
	sub := model.Subject{Path: "/Users/me/.hidden/stealer"}
	in := []model.Finding{{
		Subject: sub, Score: 16, // >= CriticalTier
		Evidence: []model.Evidence{
			{Subject: sub, Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}},
			{Subject: sub, Kind: model.KindPersistence, Summary: "user-level LaunchAgent"},
		},
	}}
	if a := Assess(in, nil); a[0].Recommendation != model.RecQuarantine {
		t.Fatalf("unsigned weak-category at critical score should Quarantine, got %q", a[0].Recommendation)
	}
}
func TestAssess_LowScoreMonitor(t *testing.T) {
	f := model.Finding{
		Subject:  model.Subject{PID: 5},
		Score:    2,
		Evidence: []model.Evidence{{Kind: model.KindProcess, Summary: "active network connection"}},
	}
	if a := Assess([]model.Finding{f}, nil); a[0].Recommendation != model.RecMonitor {
		t.Errorf("recommendation=%q want Monitor", a[0].Recommendation)
	}
}

// #23: a dormant persistence remnant (missing target / disabled .bak plist) cannot execute, so it
// caps at Monitor even at a score that would otherwise Investigate, the com.ironclad.agent case
// (a dead .bak remnant must not read as urgently as a live agent).
func TestAssess_DormantRemnantCapsAtMonitor(t *testing.T) {
	sub := model.Subject{Path: "/x/agent"}
	f := model.Finding{Subject: sub, Score: 12, Kinds: []model.SignalKind{model.KindPersistence},
		Evidence: []model.Evidence{{Subject: sub, Kind: model.KindPersistence,
			Summary: "persistence target is missing/renamed", Weight: 2,
			Facts: map[string]string{"plist": "/Users/x/Library/LaunchAgents/com.evil.plist.bak.1700000000"}}}}
	a := Assess([]model.Finding{f}, nil)[0]
	if a.Liveness != model.LivenessDormant {
		t.Fatalf("missing target / .bak plist → dormant, got %q", a.Liveness)
	}
	if a.Recommendation != model.RecMonitor {
		t.Fatalf("a dormant remnant must cap at Monitor regardless of score, got %s", a.Recommendation)
	}
	// Sanity: the same finding NOT dormant would have surfaced (score 12 ≥ ShowThreshold → Investigate).
	live := model.Finding{Subject: sub, Score: 12, Kinds: []model.SignalKind{model.KindPersistence},
		Evidence: []model.Evidence{{Subject: sub, Kind: model.KindPersistence, Summary: "user-level LaunchAgent", Weight: 1,
			Facts: map[string]string{"plist": "/Users/x/Library/LaunchAgents/com.evil.plist"}}}}
	if a2 := Assess([]model.Finding{live}, nil)[0]; a2.Liveness == model.LivenessDormant || a2.Recommendation == model.RecMonitor {
		t.Fatalf("a non-dormant persistence finding must not be capped by liveness: %+v", a2.Recommendation)
	}
}

// #23 liveness derivation (interpret owns run-state now). A persistence target found in the live
// process set is active; the same target absent is armed (loaded, not dormant); an unextractable
// target stays blank so it never reads as a misleading armed/dormant (swarm cp-T2 F-1).
func TestAssess_LivenessFromRunningSet(t *testing.T) {
	persist := func(path, target string, facts map[string]string) model.Finding {
		e := model.Evidence{Subject: model.Subject{Path: path}, Kind: model.KindPersistence, Weight: 1, Facts: facts}
		return model.Finding{Subject: model.Subject{Path: path}, Score: 6,
			Kinds: []model.SignalKind{model.KindPersistence}, Evidence: []model.Evidence{e}}
	}
	live := persist("/a/agent", "/a/agent", map[string]string{"target": "/a/agent"})
	armed := persist("/b/agent", "/b/agent", map[string]string{"target": "/b/agent"})
	unknown := persist("/c/x.plist", "", map[string]string{"plist": "/c/x.plist"}) // extraction failed: no target
	running := map[string]bool{"/a/agent": true}

	got := Assess([]model.Finding{live, armed, unknown}, running)
	if got[0].Liveness != model.LivenessActive {
		t.Errorf("target in running set → active, got %q", got[0].Liveness)
	}
	if got[1].Liveness != model.LivenessArmed {
		t.Errorf("target on disk, not running → armed, got %q", got[1].Liveness)
	}
	if got[2].Liveness != "" {
		t.Errorf("unextractable target must stay blank (not armed/dormant), got %q", got[2].Liveness)
	}
	// A live process is active regardless of the running-paths map.
	proc := model.Finding{Subject: model.Subject{PID: 5}, Score: 3, Kinds: []model.SignalKind{model.KindProcess},
		Evidence: []model.Evidence{{Subject: model.Subject{PID: 5}, Kind: model.KindProcess, Weight: 1}}}
	if a := Assess([]model.Finding{proc}, nil)[0]; a.Liveness != model.LivenessActive {
		t.Errorf("a live process is active, got %q", a.Liveness)
	}
}

// #4 concern heuristic: Apple-signed system code recedes to Minimal (the ~300-row floor); an unsigned
// binary in a user path making network connections stands out; a lone notarized quiet app stays low.
func TestConcernOf(t *testing.T) {
	codesign := func(signed, authority string) model.Evidence {
		return model.Evidence{Kind: model.KindCodesign, Facts: map[string]string{"signed": signed, "authority": authority}}
	}
	proc := func(fact string) model.Evidence {
		return model.Evidence{Kind: model.KindProcess, Facts: map[string]string{"net": fact}}
	}
	cases := []struct {
		name string
		f    model.Finding
		want model.ConcernLevel
	}{
		{"apple system daemon floors at minimal", model.Finding{
			Subject:  model.Subject{Label: "com.apple.somed", Path: "/System/Library/x"},
			Evidence: []model.Evidence{codesign("true", "Software Signing")},
		}, model.Minimal},
		{"unsigned user-path networking binary stands out", model.Finding{
			Subject:  model.Subject{Path: "/Users/x/Downloads/thing"},
			Evidence: []model.Evidence{codesign("false", ""), proc("connection")},
		}, model.Elevated}, // unsigned(2) + user(1) + connection(1) = 4 → Elevated
		{"notarized quiet third-party app stays low/minimal", model.Finding{
			Subject:  model.Subject{Path: "/Applications/Foo.app"},
			Evidence: []model.Evidence{codesign("true", "Developer ID Application: Foo")},
		}, model.Minimal},
	}
	for _, c := range cases {
		got := Assess([]model.Finding{c.f}, nil)[0].Concern
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
