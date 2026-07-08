package score

import (
	"testing"

	"counterspy/internal/model"
)

func TestScore_AllowlistedSubjectSuppressed(t *testing.T) {
	in := []model.Evidence{{
		Subject: model.Subject{Path: "/Applications/Safari.app"},
		Kind:    model.KindCodesign, Weight: 0,
		Facts: map[string]string{"authority": "Software Signing"},
	}}
	if out := Score(in); len(out) != 0 {
		t.Fatalf("allowlisted subject should be suppressed, got %d findings", len(out))
	}
}

func TestScore_TripwireFiresOnUnsignedPersistenceListener(t *testing.T) {
	sub := model.Subject{Path: "/tmp/x", PID: 5}
	in := []model.Evidence{
		{Subject: sub, Kind: model.KindCodesign, Summary: "unsigned", Weight: 3,
			Facts: map[string]string{"signed": "false"}},
		{Subject: sub, Kind: model.KindPersistence, Summary: "launch agent", Weight: 1},
		{Subject: sub, Kind: model.KindProcess, Summary: "listener", Weight: 2,
			Facts: map[string]string{"listener": "true"}},
	}
	out := Score(in)
	if len(out) != 1 || out[0].Tripwire == "" {
		t.Fatalf("expected a tripwire finding, got %+v", out)
	}
}
