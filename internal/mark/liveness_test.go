package mark

import (
	"testing"

	"counterspy/internal/model"
)

func ev(kind model.SignalKind, facts map[string]string) model.Evidence {
	return model.Evidence{Kind: kind, Facts: facts}
}

func TestClassify(t *testing.T) {
	running := map[string]bool{"/usr/local/bin/live": true}

	assessments := []model.Assessment{
		// a running process holding a listener → active + socket
		{Finding: model.Finding{
			Subject:  model.Subject{PID: 777},
			Evidence: []model.Evidence{ev(model.KindProcess, map[string]string{"listener": "true"})},
		}},
		// persistence whose target IS running → active, no socket
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/usr/local/bin/live"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"target": "/usr/local/bin/live"})},
		}},
		// persistence whose target is NOT running → vestigial
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/usr/local/bin/dormant"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"target": "/usr/local/bin/dormant"})},
		}},
		// codesign-only finding → no liveness signal (both slots blank)
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/Applications/Foo.app"},
			Evidence: []model.Evidence{ev(model.KindCodesign, map[string]string{"signed": "false"})},
		}},
	}

	got := Classify(assessments, running)

	want := map[string]Liveness{
		"pid:777":                     {RunState: GlyphActive, Socket: GlyphSocket},
		"path:/usr/local/bin/live":    {RunState: GlyphActive},
		"path:/usr/local/bin/dormant": {RunState: GlyphVestigial},
		"path:/Applications/Foo.app":  {},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v want %+v", k, got[k], w)
		}
	}
}
