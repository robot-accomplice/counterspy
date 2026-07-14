package mark

import (
	"testing"

	"counterspy/internal/model"
)

func ev(kind model.SignalKind, facts map[string]string) model.Evidence {
	return model.Evidence{Kind: kind, Facts: facts}
}

// Classify no longer derives run-state — interpret does, storing it on Assessment.Liveness
// (issue #23). Classify only maps that value to a glyph and adds the socket mark, which is the
// one thing it still reads from evidence. These assert that assembly + the ▸/◐/† mapping.
func TestClassify(t *testing.T) {
	assessments := []model.Assessment{
		// active + a live listener → ▸ and ↔ co-occur (independent slots)
		{Liveness: model.LivenessActive, Finding: model.Finding{
			Subject:  model.Subject{PID: 777},
			Evidence: []model.Evidence{ev(model.KindProcess, map[string]string{"listener": "true"})},
		}},
		// armed persistence, no socket → ◐ only
		{Liveness: model.LivenessArmed, Finding: model.Finding{
			Subject:  model.Subject{Path: "/usr/local/bin/armed"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"target": "/usr/local/bin/armed"})},
		}},
		// dormant remnant → †
		{Liveness: model.LivenessDormant, Finding: model.Finding{
			Subject:  model.Subject{Path: "/usr/local/bin/dormant"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"plist": "/x/com.evil.plist.bak"})},
		}},
		// no liveness signal → both slots blank
		{Liveness: "", Finding: model.Finding{
			Subject:  model.Subject{Path: "/Applications/Foo.app"},
			Evidence: []model.Evidence{ev(model.KindCodesign, map[string]string{"signed": "false"})},
		}},
	}

	got := Classify(assessments)

	want := map[string]Liveness{
		"pid:777":                     {RunState: GlyphActive, Socket: GlyphSocket},
		"path:/usr/local/bin/armed":   {RunState: GlyphArmed},
		"path:/usr/local/bin/dormant": {RunState: GlyphVestigial},
		"path:/Applications/Foo.app":  {},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v want %+v", k, got[k], w)
		}
	}
}
