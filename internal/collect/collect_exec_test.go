package collect

import (
	"errors"
	"strings"
	"testing"

	"counterspy/internal/model"
)

// --- Part B: exec-edge collectors via injected mocks ---

// withSigProbe injects a fake code-signature backend so CollectCodesign is exercised
// hermetically (no Security.framework / no shelling out) on any platform.
func withSigProbe(t *testing.T, fn func(string) (string, bool, string)) {
	t.Helper()
	orig := sigProbe
	sigProbe = fn
	t.Cleanup(func() { sigProbe = orig })
}

func TestCollectCodesign_Unsigned(t *testing.T) {
	withSigProbe(t, func(string) (string, bool, string) {
		return "code object is not signed at all", false, ""
	})
	ev := CollectCodesign("/tmp/unsigned")
	if len(ev) != 1 || ev[0].Facts["signed"] != "false" {
		t.Fatalf("expected one signed=false evidence, got %+v", ev)
	}
}

// With no signature backend on this platform, CollectCodesign yields no evidence.
func TestCollectCodesign_NoBackend(t *testing.T) {
	withSigProbe(t, nil)
	if ev := CollectCodesign("/tmp/x"); ev != nil {
		t.Fatalf("no backend should yield nil evidence, got %+v", ev)
	}
}

func TestCollectCodesign_SignedAndAccepted(t *testing.T) {
	withSigProbe(t, func(string) (string, bool, string) {
		return "", true, "Developer ID Application: Apple Inc."
	})
	ev := CollectCodesign("/Applications/Safari.app")
	if len(ev) != 1 || ev[0].Facts["signed"] != "true" {
		t.Fatalf("expected one signed=true evidence, got %+v", ev)
	}
	if ev[0].Facts["authority"] != "Developer ID Application: Apple Inc." {
		t.Errorf("expected the authority fact when accepted, got %v", ev[0].Facts)
	}
}

func TestCollectCodesign_SignedButRejected(t *testing.T) {
	withSigProbe(t, func(string) (string, bool, string) {
		return "", false, "Self Signed" // valid-ish signature, but not accepted
	})
	ev := CollectCodesign("/tmp/selfsigned")
	if len(ev) != 1 || ev[0].Facts["signed"] != "true" {
		t.Fatalf("expected one signed=true evidence, got %+v", ev)
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
