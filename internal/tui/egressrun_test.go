// internal/tui/egressrun_test.go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type fakeSampler struct{ groups []model.EgressGroup }

func (f fakeSampler) Sample() []model.EgressGroup { return f.groups }

func TestRunEgress_RendersAndQuits(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	tick := make(chan struct{}, 1)
	tick <- struct{}{} // one sample
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)
	sampler := fakeSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}
	if err := RunEgress(s, sampler, tick); err != nil {
		t.Fatal(err)
	}
	// The screen should have drawn the app name somewhere.
	if !simContains(s, "backuptool") {
		t.Fatal("expected 'backuptool' on screen")
	}
}

func simContains(s tcell.SimulationScreen, want string) bool {
	cells, w, h := s.GetContents()
	var b []rune
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			b = append(b, cells[y*w+x].Runes...)
		}
	}
	return len(b) > 0 && contains(string(b), want)
}

func contains(hay, needle string) bool { return len(hay) >= len(needle) && (indexOf(hay, needle) >= 0) }
func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
