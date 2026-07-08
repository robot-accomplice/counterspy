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

// cp-3 QA F-2 / Audit F-2: a tripwire must survive a co-located allowlisted authority.
func TestScore_TripwireNotSuppressedByAllowlist(t *testing.T) {
	sub := model.Subject{Path: "/tmp/pwned"}
	in := []model.Evidence{
		{Subject: sub, Kind: model.KindCodesign, Weight: 1, Facts: map[string]string{"authority": "Software Signing"}},
		{Subject: sub, Kind: model.KindCodesign, Weight: 0, Facts: map[string]string{"signed": "false"}},
		{Subject: sub, Kind: model.KindPersistence, Weight: 0},
		{Subject: sub, Kind: model.KindProcess, Weight: 0, Facts: map[string]string{"listener": "true"}},
	}
	out := Score(in)
	if len(out) != 1 || out[0].Tripwire == "" {
		t.Fatalf("tripwire must survive a co-located allowlisted authority, got %+v", out)
	}
}

// cp-3 QA F-1: a subject with any unsigned signal must never be suppressed by a
// co-located allowlisted authority.
func TestScore_UnsignedNotSuppressedByAllowlist(t *testing.T) {
	sub := model.Subject{Path: "/tmp/badactor"}
	in := []model.Evidence{
		{Subject: sub, Kind: model.KindCodesign, Weight: 1, Facts: map[string]string{"authority": "Software Signing"}},
		{Subject: sub, Kind: model.KindCodesign, Weight: 5, Facts: map[string]string{"signed": "false"}},
		{Subject: sub, Kind: model.KindPersistence, Weight: 3},
	}
	if out := Score(in); len(out) != 1 {
		t.Fatalf("subject with an unsigned signal must not be suppressed, got %d findings", len(out))
	}
}
