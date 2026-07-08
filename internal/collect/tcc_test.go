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
