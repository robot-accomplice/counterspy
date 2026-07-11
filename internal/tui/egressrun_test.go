// internal/tui/egressrun_test.go
package tui

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type fakeSampler struct{ groups []model.EgressGroup }

func (f fakeSampler) Sample() []model.EgressGroup { return f.groups }

// countingSampler tracks how many times Sample was called, so tests can tell a tick
// actually triggered a resample (vs. being skipped while paused). Sample() now runs on a
// dedicated background goroutine (see egressrun.go), so the counter must be atomic to be
// read race-free from the test goroutine.
type countingSampler struct {
	groups []model.EgressGroup
	calls  atomic.Int64
}

func (c *countingSampler) Sample() []model.EgressGroup {
	c.calls.Add(1)
	return c.groups
}

func TestRunEgress_RendersAndQuits(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	tick := make(chan struct{})
	sampler := fakeSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}

	// The initial sample is now delivered asynchronously (off the UI thread), so run RunEgress
	// in a goroutine and give it a moment to land before quitting — otherwise the injected 'Q'
	// could win the race and quit before the sample is ever applied.
	done := make(chan error, 1)
	go func() { done <- RunEgress(s, sampler, tick, nil) }()
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
	go func() { done <- RunEgress(s, sampler, tick, nil) }()

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
	if calls := sampler.calls.Load(); calls < 2 { // 1 initial + at least 1 from the tick
		t.Fatalf("expected the tick to trigger a resample, got %d Sample() calls", calls)
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
	go func() { done <- RunEgress(s, sampler, tick, nil) }()

	s.InjectKey(tcell.KeyRune, 'p', tcell.ModNone) // pause
	time.Sleep(30 * time.Millisecond)
	callsAfterPause := sampler.calls.Load()

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
	if calls := sampler.calls.Load(); calls != callsAfterPause {
		t.Fatalf("a tick while paused must not resample: calls before=%d after=%d", callsAfterPause, calls)
	}
}

// blockingSampler's Sample() blocks until released, simulating a slow nettop call.
type blockingSampler struct{ release chan struct{} }

func (b *blockingSampler) Sample() []model.EgressGroup {
	<-b.release
	return nil
}

// The event loop must never call the (potentially slow, ~1s+) Sample() synchronously on the
// UI thread: while a sample is in flight, key presses (especially quit) must still be handled
// immediately. Regression test for issue #13.
func TestRunEgress_QuitsWhileSampleBlocks(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	bs := &blockingSampler{release: make(chan struct{})}
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)
	done := make(chan error, 1)
	go func() { done <- RunEgress(s, bs, make(chan struct{}), nil) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunEgress: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunEgress did not quit while Sample() was blocked — UI is still coupled to the monitor")
	}
	close(bs.release) // release the orphaned sample goroutine
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
	go func() { done <- RunEgress(s, sampler, tick, nil) }()

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
