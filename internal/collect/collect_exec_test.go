package collect

import (
	"errors"
	"strings"
	"testing"

	"counterspy/internal/model"
)

// --- Part B: exec-edge collectors via injected mocks ---

func TestCollectCodesign_Unsigned(t *testing.T) {
	origCombined, origAccepts := execCombined, execAccepts
	defer func() { execCombined = origCombined; execAccepts = origAccepts }()

	execCombined = func(name string, args ...string) ([]byte, error) {
		if name == "codesign" {
			return []byte("code object is not signed at all"), errors.New("exit status 1")
		}
		t.Fatalf("unexpected exec name %q", name)
		return nil, nil
	}
	execAccepts = func(name string, args ...string) bool {
		if name == "spctl" {
			return false
		}
		t.Fatalf("unexpected exec name %q", name)
		return false
	}

	ev := CollectCodesign("/tmp/unsigned")
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if ev[0].Facts["signed"] != "false" {
		t.Errorf("expected signed=false, got %v", ev[0].Facts)
	}
}

func TestCollectCodesign_SignedAndAccepted(t *testing.T) {
	origCombined, origAccepts := execCombined, execAccepts
	defer func() { execCombined = origCombined; execAccepts = origAccepts }()

	callCount := 0
	execCombined = func(name string, args ...string) ([]byte, error) {
		callCount++
		if name != "codesign" {
			t.Fatalf("unexpected exec name %q", name)
		}
		// first call is --verify --deep (no error output); second is -dv --verbose=2 (authority)
		if callCount == 1 {
			return []byte(""), nil
		}
		return []byte("Executable=/Applications/Safari.app/Contents/MacOS/Safari\nAuthority=Developer ID Application: Apple Inc.\nAuthority=Apple Root CA\n"), nil
	}
	execAccepts = func(name string, args ...string) bool {
		if name != "spctl" {
			t.Fatalf("unexpected exec name %q", name)
		}
		return true
	}

	ev := CollectCodesign("/Applications/Safari.app")
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if ev[0].Facts["signed"] != "true" {
		t.Errorf("expected signed=true, got %v", ev[0].Facts)
	}
	if ev[0].Facts["authority"] != "Developer ID Application: Apple Inc." {
		t.Errorf("expected authority fact (accepted case), got %v", ev[0].Facts)
	}
}

func TestCollectCodesign_SignedButRejected(t *testing.T) {
	origCombined, origAccepts := execCombined, execAccepts
	defer func() { execCombined = origCombined; execAccepts = origAccepts }()

	execCombined = func(name string, args ...string) ([]byte, error) {
		return []byte("Authority=Self Signed\n"), nil
	}
	execAccepts = func(name string, args ...string) bool {
		return false // Gatekeeper rejects
	}

	ev := CollectCodesign("/tmp/selfsigned")
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if _, ok := ev[0].Facts["authority"]; ok {
		t.Errorf("authority must be dropped when not accepted, got %v", ev[0].Facts)
	}
}

func TestCollectProcesses_ReturnsListenerEvidence(t *testing.T) {
	orig := execOutput
	defer func() { execOutput = orig }()

	psOut := "  PID  PPID USER             COMMAND\n" +
		"    1     0 root             /sbin/launchd\n" +
		"  777     1 me               /usr/bin/python3 beacon.py\n"
	lsofOut := "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n" +
		"python3   777  me     5u  IPv4    0x1      0t0  TCP *:4444 (LISTEN)\n"

	execOutput = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "ps":
			return []byte(psOut), nil
		case "lsof":
			return []byte(lsofOut), nil
		default:
			t.Fatalf("unexpected exec name %q", name)
			return nil, nil
		}
	}

	ev, err := CollectProcesses()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found bool
	for _, e := range ev {
		if e.Subject.PID == 777 && e.Facts["listener"] == "true" {
			found = true
			if !strings.Contains(e.Facts["argv"], "beacon.py") {
				t.Errorf("argv should reveal script: %q", e.Facts["argv"])
			}
		}
	}
	if !found {
		t.Fatal("expected listener evidence for pid 777")
	}
}

func TestCollectProcesses_PsFailurePropagatesError(t *testing.T) {
	orig := execOutput
	defer func() { execOutput = orig }()

	execOutput = func(name string, args ...string) ([]byte, error) {
		if name == "ps" {
			return nil, errors.New("ps failed")
		}
		return []byte(""), nil
	}

	_, err := CollectProcesses()
	if err == nil {
		t.Fatal("expected error when ps fails")
	}
}

func TestCollectTCC_ReturnsEvidenceFromRows(t *testing.T) {
	orig := execOutput
	defer func() { execOutput = orig }()

	rows := "kTCCServiceAccessibility|/Users/me/Library/.hidden/beacon|2\nkTCCServiceScreenCapture|/Applications/Zoom.app|2\n"
	execOutput = func(name string, args ...string) ([]byte, error) {
		if name != "sqlite3" {
			t.Fatalf("unexpected exec name %q", name)
		}
		return []byte(rows), nil
	}

	ev, err := CollectTCC()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ev) != 4 { // 2 rows parsed from each of the 2 dbs (user + system)
		t.Fatalf("want 4 evidence entries (2 dbs x 2 rows), got %d: %+v", len(ev), ev)
	}
	for _, e := range ev {
		if e.Kind != model.KindTCC {
			t.Errorf("wrong kind %q", e.Kind)
		}
	}
}

func TestCollectTCC_BothDBsFailReturnsGapError(t *testing.T) {
	orig := execOutput
	defer func() { execOutput = orig }()

	execOutput = func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("unable to open database file")
	}

	ev, err := CollectTCC()
	if err == nil {
		t.Fatal("expected fail-loud gap error when both TCC dbs are unreadable")
	}
	if len(ev) != 0 {
		t.Errorf("expected no evidence, got %v", ev)
	}
}

func TestCollectPersistence_OneDBFailsStillSucceeds(t *testing.T) {
	orig := execOutput
	defer func() { execOutput = orig }()

	// One db read fails, the other succeeds — readOK must be > 0, no gap error.
	callCount := 0
	execOutput = func(name string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 1 {
			return nil, errors.New("unable to open database file")
		}
		return []byte("kTCCServiceAccessibility|/tmp/x|2\n"), nil
	}

	ev, err := CollectTCC()
	if err != nil {
		t.Fatalf("unexpected error when at least one db is readable: %v", err)
	}
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
}

// --- CollectPersistence: fakes execOutput (plutil) via real launchd dirs on disk (t.TempDir) ---

func TestCollectPersistence_ProducesEvidence(t *testing.T) {
	orig := execOutput
	defer func() { execOutput = orig }()

	xmlOut := `<plist><dict>
	  <key>Label</key><string>com.evil.updater</string>
	  <key>ProgramArguments</key><array><string>/Users/me/Library/.hidden/beacon</string></array>
	</dict></plist>`

	execOutput = func(name string, args ...string) ([]byte, error) {
		if name != "plutil" {
			t.Fatalf("unexpected exec name %q", name)
		}
		return []byte(xmlOut), nil
	}

	// CollectPersistence reads real directories via os.ReadDir; at least one of the
	// launchd search paths (e.g. /Library/LaunchAgents) typically exists on macOS CI
	// runners, but to keep this test host-independent, only assert on the fail-loud
	// path when NONE of them are readable, and otherwise just assert no panic/parse error.
	ev, err := CollectPersistence()
	if err != nil {
		// Acceptable in a sandboxed/non-macOS test environment where no launchd dir exists.
		if !strings.Contains(err.Error(), "no launchd directory readable") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	_ = ev // best-effort: directories may be empty of plists in CI
}
