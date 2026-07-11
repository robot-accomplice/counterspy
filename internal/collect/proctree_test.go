package collect

import (
	"os"
	"strings"
	"testing"
)

func TestBuildProcessEvidence_AttributesListenerToAncestry(t *testing.T) {
	psb, _ := os.ReadFile("../../testdata/ps.txt")
	lsb, _ := os.ReadFile("../../testdata/lsof.txt")
	procs := ParsePs(psb)
	listeners := ParseLsof(lsb)
	ev := BuildProcessEvidence(procs, listeners)

	var found bool
	for _, e := range ev {
		if e.Subject.PID == 777 && e.Facts["listener"] == "true" {
			found = true
			if !strings.Contains(e.Facts["argv"], "beacon.py") {
				t.Errorf("argv should reveal the script: %q", e.Facts["argv"])
			}
			if !strings.Contains(e.Facts["ancestry"], "launchd") {
				t.Errorf("ancestry chain missing: %q", e.Facts["ancestry"])
			}
		}
	}
	if !found {
		t.Fatal("expected listener evidence for pid 777 with ancestry+argv")
	}
}

// cp-7 Audit F-1 (crit): argv[0] is attacker-controlled, so it must NOT become the
// subject identity — else a listener could alias onto an allowlisted app and be suppressed.
func TestBuildProcessEvidence_KeysByPIDNotArgv0(t *testing.T) {
	procs := map[int]*Proc{999: {PID: 999, PPID: 1, Cmd: "/System/Library/CoreServices/legit /tmp/payload"}}
	listeners := map[int][]string{999: {"*:4444 (LISTEN)"}}
	ev := BuildProcessEvidence(procs, listeners)
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if ev[0].Subject.Path != "" {
		t.Fatalf("process subject must be PID-only (argv0 is spoofable), got Path=%q", ev[0].Subject.Path)
	}
	if ev[0].Subject.PID != 999 {
		t.Fatalf("want PID identity, got %d", ev[0].Subject.PID)
	}
}

// cp-7 QA F-1: an ESTABLISHED (outbound) socket is not a listener.
func TestBuildProcessEvidence_EstablishedIsNotListener(t *testing.T) {
	procs := map[int]*Proc{5: {PID: 5, PPID: 1, Cmd: "/x"}}
	listeners := map[int][]string{5: {"1.2.3.4:443 ESTABLISHED"}}
	ev := BuildProcessEvidence(procs, listeners)
	if ev[0].Facts["listener"] == "true" {
		t.Fatal("ESTABLISHED must not be labeled a listener")
	}
	if ev[0].Facts["net"] != "connection" {
		t.Errorf("want net=connection for a non-LISTEN socket, got %q", ev[0].Facts["net"])
	}
}

func TestAncestry_Exported(t *testing.T) {
	procs := map[int]*Proc{
		1:   {PID: 1, PPID: 0, Cmd: "/sbin/launchd"},
		200: {PID: 200, PPID: 1, Cmd: "/Applications/X.app/Contents/MacOS/X --flag"},
	}
	got := Ancestry(procs, 200)
	if got != "/sbin/launchd -> /Applications/X.app/Contents/MacOS/X" {
		t.Fatalf("Ancestry = %q", got)
	}
}
