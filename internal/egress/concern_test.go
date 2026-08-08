package egress

import (
	"testing"

	"counterspy/internal/model"
)

func TestConcern(t *testing.T) {
	// Unsigned background daemon, sustained upload, raw IP → elevated.
	bad := model.EgressGroup{Trust: "unsigned", Background: true, OutRate: 800_000,
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}}}
	if got := Concern(bad); got != model.Elevated {
		t.Fatalf("Concern(bad) = %s, want elevated", got)
	}
	// Apple foreground app → minimal.
	good := model.EgressGroup{Trust: "apple", Background: false, OutRate: 120_000,
		Destinations: []model.Endpoint{{IP: "17.1.1.1", Port: 443}}}
	if got := Concern(good); got != model.Minimal {
		t.Fatalf("Concern(good) = %s, want minimal", got)
	}
}

func TestExfil(t *testing.T) {
	// Screen + keystroke capability + sustained raw-IP upload from a daemon → elevated,
	// candidates named from capabilities.
	g := model.EgressGroup{Trust: "unsigned", Background: true, OutRate: 800_000,
		Capabilities: []string{"screen", "keystrokes"},
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}}}
	risk, cand := Exfil(g)
	if risk != model.Elevated {
		t.Fatalf("Exfil risk = %s, want elevated", risk)
	}
	if len(cand) != 2 || cand[0] != "screen" {
		t.Fatalf("candidates = %v, want [screen keystrokes]", cand)
	}
	// Same capabilities but notarized foreground app sending modestly → low, candidates
	// still listed (they COULD leave) but risk is low.
	g2 := model.EgressGroup{Trust: "notarized", Background: false, OutRate: 5000,
		Capabilities: []string{"screen"}, Destinations: []model.Endpoint{{IP: "17.1.1.1", Port: 443}}}
	if risk2, _ := Exfil(g2); risk2 > model.Low {
		t.Fatalf("Exfil(notarized foreground) = %s, want <= low", risk2)
	}
}

// A TRUSTED app that quietly uploads in the background must still surface; trust is one
// signal, not a kill switch. Guards the trust-gating regression a review caught.
func TestConcern_TrustedBackgroundUploaderStillSurfaces(t *testing.T) {
	g := model.EgressGroup{Trust: "notarized", Background: true, OutRate: 800_000,
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}}}
	if got := Concern(g); got <= model.Minimal {
		t.Fatalf("a notarized background daemon uploading 800KB/s must surface (> minimal), got %s", got)
	}
}

// #3: the raw-IP concern nudge is LIGHT TOUCH + CORROBORATED: it lifts a band only when the app is
// already suspicious (untrusted, or a sustained background upload), and never for a trusted/idle app.
func TestConcern_RawIPIsCorroboratedAndLightTouch(t *testing.T) {
	rawIP := []model.Endpoint{{IP: "203.0.113.9"}} // nameless
	named := []model.Endpoint{{IP: "203.0.113.9", Name: "api.vendor.com"}}
	const up = sustainedBytesPerSec + 1

	// A notarized, IDLE app talking to a nameless IP gets NO nudge; stays Minimal.
	calm := model.EgressGroup{Trust: "notarized", Destinations: rawIP}
	if got := Concern(calm); got != model.Minimal {
		t.Fatalf("notarized idle app to a raw IP must stay Minimal, got %v", got)
	}

	// An unsigned background uploader: the raw-IP nudge lifts it above the same app talking to a
	// NAMED destination (corroboration present → the nudge applies).
	rawGrp := model.EgressGroup{Trust: "unsigned", Background: true, OutRate: up, Destinations: rawIP}
	namedGrp := model.EgressGroup{Trust: "unsigned", Background: true, OutRate: up, Destinations: named}
	if !(Concern(rawGrp) >= Concern(namedGrp)) {
		t.Fatalf("raw-IP must not LOWER concern: raw=%v named=%v", Concern(rawGrp), Concern(namedGrp))
	}
	if concernScore(rawGrp) != concernScore(namedGrp)+1 {
		t.Fatalf("corroborated raw-IP must add exactly +1: raw=%d named=%d",
			concernScore(rawGrp), concernScore(namedGrp))
	}
}
