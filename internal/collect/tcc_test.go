package collect

import (
	"os"
	"testing"

	"counterspy/internal/model"
)

func TestParseTCC_KeyloggerShapeScoresHigher(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/tcc.txt")
	ev := ParseTCC(b)
	byPath := map[string]int{}
	for _, e := range ev {
		if e.Kind != model.KindTCC {
			t.Errorf("wrong kind %q", e.Kind)
		}
		byPath[e.Subject.Path] += e.Weight
	}
	if byPath["/Users/me/Library/.hidden/beacon"] <= byPath["/Applications/Zoom.app"] {
		t.Errorf("accessibility+input-monitoring should outweigh a single screen-capture grant")
	}
}

// cp-7 QA F-3: a client path containing a pipe must still parse (auth_value is the LAST field).
func TestParseTCC_ClientPathWithPipe(t *testing.T) {
	ev := ParseTCC([]byte("kTCCServiceAccessibility|/usr/bin/e|vil|2\n"))
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if ev[0].Subject.Path != "/usr/bin/e|vil" {
		t.Errorf("client path with pipe mis-parsed: %q", ev[0].Subject.Path)
	}
}
