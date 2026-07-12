package tui

import (
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// RunConsole starts in Findings and does NOT sample while there (lazy sampling); a Tab switches
// to Exfiltration, which begins sampling; Shift-Tab returns to Findings and sampling stops.
func TestRunConsole_TabSwitchesModeAndLazySamples(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	cs := &countingSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)
	tick := make(chan struct{})

	done := make(chan error, 1)
	go func() { done <- RunConsole(s, m, &fakeActor{}, cs, tick, nil) }()

	// Findings mode is active: a tick must NOT sample.
	time.Sleep(20 * time.Millisecond)
	tick <- struct{}{}
	time.Sleep(20 * time.Millisecond)
	if n := cs.calls.Load(); n != 0 {
		t.Fatalf("no sampling should happen in Findings mode, got %d calls", n)
	}
	if !simContains(s, "Findings") || !simContains(s, "Exfiltration") {
		t.Fatal("mode tabs should show both Findings and Exfiltration")
	}

	// Tab → Exfiltration: an immediate warm sample fires, and subsequent ticks sample.
	s.InjectKey(tcell.KeyTab, 0, tcell.ModNone)
	time.Sleep(30 * time.Millisecond)
	tick <- struct{}{}
	time.Sleep(30 * time.Millisecond)
	afterExfil := cs.calls.Load()
	if afterExfil < 1 {
		t.Fatalf("Exfiltration mode should sample (warm + tick), got %d", afterExfil)
	}
	if !simContains(s, "backuptool") {
		t.Fatal("Exfiltration view should render the sampled group")
	}

	// Shift-Tab back to Findings: sampling stops (a later tick doesn't increase the count).
	s.InjectKey(tcell.KeyBacktab, 0, tcell.ModNone)
	time.Sleep(20 * time.Millisecond)
	quiet := cs.calls.Load()
	tick <- struct{}{}
	time.Sleep(20 * time.Millisecond)
	if cs.calls.Load() != quiet {
		t.Fatalf("no sampling after switching back to Findings, went %d → %d", quiet, cs.calls.Load())
	}

	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone) // quit from findings
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunConsole did not exit on quit")
	}
}

// A quarantine action taken in Findings mode reaches the Actor end-to-end through RunConsole.
func TestRunConsole_FindingsQuarantineFlow(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &fakeActor{}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)
	tick := make(chan struct{})

	done := make(chan error, 1)
	go func() { done <- RunConsole(s, m, fa, fakeSampler{}, tick, nil) }()

	inject := func(k tcell.Key, r rune) {
		time.Sleep(15 * time.Millisecond)
		s.InjectKey(k, r, tcell.ModNone)
	}
	inject(tcell.KeyRune, 'q') // open confirm modal
	inject(tcell.KeyEnter, 0)  // confirm
	inject(tcell.KeyRune, 'Q') // quit

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunConsole did not exit")
	}
	if len(fa.quarantined) != 1 || fa.quarantined[0] != "evil" {
		t.Fatalf("quarantine not called for 'evil': %v", fa.quarantined)
	}
}

// A slow Sample() must never block quit: it runs off the UI thread, so 'Q' in Exfiltration
// exits immediately even while a sample is in flight (was TestRunEgress_QuitsWhileSampleBlocks).
func TestRunConsole_QuitWhileSampleBlocks(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	block := make(chan struct{})
	bs := blockingSampler{release: block}
	done := make(chan error, 1)
	go func() { done <- RunConsole(s, New(nil, nil), &fakeActor{}, bs, make(chan struct{}), nil) }()
	s.InjectKey(tcell.KeyTab, 0, tcell.ModNone) // to Exfiltration → warm sample blocks
	time.Sleep(30 * time.Millisecond)
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone) // must quit despite the blocked sample
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("quit blocked on a slow Sample()")
	}
	close(block) // let the leaked sample goroutine finish
}

type blockingSampler struct{ release <-chan struct{} }

func (b blockingSampler) Sample() []model.EgressGroup {
	<-b.release
	return nil
}

// Pausing Exfiltration stops resampling on subsequent ticks (was TestRunEgress_PausedSkipsResample).
func TestRunConsole_PausedSkipsResample(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	cs := &countingSampler{groups: []model.EgressGroup{eg("x", model.Low, 1)}}
	tick := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- RunConsole(s, New(nil, nil), &fakeActor{}, cs, tick, nil) }()

	s.InjectKey(tcell.KeyTab, 0, tcell.ModNone) // to Exfiltration (warm sample)
	time.Sleep(30 * time.Millisecond)
	s.InjectKey(tcell.KeyRune, 'p', tcell.ModNone) // pause
	time.Sleep(20 * time.Millisecond)
	paused := cs.calls.Load()
	tick <- struct{}{} // a tick while paused
	time.Sleep(20 * time.Millisecond)
	if cs.calls.Load() != paused {
		t.Fatalf("paused Exfiltration must not resample, went %d → %d", paused, cs.calls.Load())
	}
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)
	<-done
}
