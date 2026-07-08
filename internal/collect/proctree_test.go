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
