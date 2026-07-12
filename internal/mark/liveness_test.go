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

// cp-T2 review F-1/F-3: an unknown persistence target (extraction failed, so
// Subject.Path is the plist path) must render a BLANK run-state, not a misleading
// †; and a nil running map must not panic (persistence then reads vestigial).
func TestClassify_UnknownTargetAndNilRunning(t *testing.T) {
	assessments := []model.Assessment{
		// target extraction failed: Subject.Path is the plist, Facts has no target
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/Library/LaunchDaemons/x.plist"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"plist": "/Library/LaunchDaemons/x.plist"})},
		}},
		// known target, nil running set → vestigial (no panic)
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/opt/tool"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"target": "/opt/tool"})},
		}},
	}

	got := Classify(assessments, nil)

	if lv := got["path:/Library/LaunchDaemons/x.plist"]; lv.RunState != 0 {
		t.Errorf("unknown target: got run-state %q want blank(0)", lv.RunState)
	}
	if lv := got["path:/opt/tool"]; lv.RunState != GlyphVestigial {
		t.Errorf("known target, nil running: got %q want vestigial", lv.RunState)
	}
}
