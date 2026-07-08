package collect

import (
	"os"
	"testing"

	"counterspy/internal/model"
)

func TestParsePersistencePlist_FlagsHiddenTarget(t *testing.T) {
	b, err := os.ReadFile("../../testdata/agent_evil.plist.xml")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ParsePersistencePlist(b, "/Users/me/Library/LaunchAgents/com.evil.updater.plist")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) == 0 {
		t.Fatal("expected evidence")
	}
	var sawHidden bool
	for _, e := range ev {
		if e.Kind != model.KindPersistence {
			t.Errorf("wrong kind %q", e.Kind)
		}
		if e.Subject.Label != "com.evil.updater" {
			t.Errorf("label not propagated: %q", e.Subject.Label)
		}
		if e.Facts["target"] == "/Users/me/Library/.hidden/beacon" {
			sawHidden = true
		}
	}
	if !sawHidden {
		t.Error("expected the hidden target path in Facts")
	}
}
