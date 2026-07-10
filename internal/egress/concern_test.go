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
