// internal/tui/egressrun_test.go
package tui

import (
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type fakeSampler struct{ groups []model.EgressGroup }

func (f fakeSampler) Sample() []model.EgressGroup { return f.groups }

// countingSampler tracks how many times Sample was called, so tests can tell a tick
// actually triggered a resample (vs. being skipped while paused).
type countingSampler struct {
	groups []model.EgressGroup
	calls  int
}

func (c *countingSampler) Sample() []model.EgressGroup {
	c.calls++
	return c.groups
}

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

// A tick processed while NOT paused must trigger a resample (egressrun.go's
// `if !m.Paused` branch), distinct from the one-time initial sample taken before the loop.
func TestRunEgress_ResamplesOnUnpausedTick(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	tick := make(chan struct{}, 2)
	sampler := &countingSampler{groups: []model.EgressGroup{eg("x", model.Low, 10)}}

	done := make(chan error, 1)
	go func() { done <- RunEgress(s, sampler, tick) }()

	tick <- struct{}{}
	time.Sleep(30 * time.Millisecond) // give the loop time to process the tick before quitting
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunEgress did not quit")
	}
	if sampler.calls < 2 { // 1 initial + at least 1 from the tick
		t.Fatalf("expected the tick to trigger a resample, got %d Sample() calls", sampler.calls)
	}
}

// While paused, a tick must NOT trigger a resample.
func TestRunEgress_PausedSkipsResample(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	tick := make(chan struct{}, 2)
	sampler := &countingSampler{groups: []model.EgressGroup{eg("x", model.Low, 10)}}

	done := make(chan error, 1)
	go func() { done <- RunEgress(s, sampler, tick) }()

	s.InjectKey(tcell.KeyRune, 'p', tcell.ModNone) // pause
	time.Sleep(30 * time.Millisecond)
	callsAfterPause := sampler.calls

	tick <- struct{}{}
	time.Sleep(30 * time.Millisecond)
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunEgress did not quit")
	}
	if sampler.calls != callsAfterPause {
		t.Fatalf("a tick while paused must not resample: calls before=%d after=%d", callsAfterPause, sampler.calls)
	}
}

// PollEvent returns nil once the screen is finished; RunEgress must return cleanly.
func TestRunEgress_NilEventOnScreenFini(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	tick := make(chan struct{})
	sampler := fakeSampler{groups: []model.EgressGroup{eg("x", model.Low, 10)}}

	done := make(chan error, 1)
	go func() { done <- RunEgress(s, sampler, tick) }()

	time.Sleep(20 * time.Millisecond)
	s.Fini()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunEgress did not return after the screen finished")
	}
}
