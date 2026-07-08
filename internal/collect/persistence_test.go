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

// cp-5 Audit F-1: /usr/bin/env-wrapped persistence must resolve to the real payload,
// not the interpreter.
func TestExtractLabelAndTarget_EnvWrapperPicksPayload(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Label</key><string>com.evil</string>
	  <key>ProgramArguments</key><array><string>/usr/bin/env</string><string>/Users/me/.hidden/payload</string></array>
	</dict></plist>`)
	label, target := extractLabelAndTarget(x)
	if label != "com.evil" {
		t.Errorf("label=%q want com.evil", label)
	}
	if target != "/Users/me/.hidden/payload" {
		t.Errorf("target=%q want the real payload, not the interpreter", target)
	}
}

// cp-5 QA F-3: a decoy string value equal to "Label" must not poison key detection.
func TestExtractLabelAndTarget_DecoyValueDoesNotPoisonLabel(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Comment</key><string>Label</string>
	  <key>Label</key><string>com.real.label</string>
	  <key>ProgramArguments</key><array><string>/bin/target</string></array>
	</dict></plist>`)
	label, _ := extractLabelAndTarget(x)
	if label != "com.real.label" {
		t.Errorf("label=%q want com.real.label (decoy poisoned key tracking)", label)
	}
}
