package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func TestMiddleEllipsis(t *testing.T) {
	full := "/Users/analyst/Library/Application Support/Claude/claude.app/Contents/MacOS/claude"
	if got := middleEllipsis(full, 200); got != full {
		t.Fatalf("a short-enough path must pass through unchanged, got %q", got)
	}
	got := middleEllipsis(full, 30)
	if !strings.HasPrefix(got, "/Users/analyst") {
		t.Fatalf("must keep the starting path, got %q", got)
	}
	if !strings.HasSuffix(got, "/claude") {
		t.Fatalf("must keep the final binary name, got %q", got)
	}
	if !strings.Contains(got, "…") {
		t.Fatalf("must bridge start and binary with an ellipsis, got %q", got)
	}
	if n := len([]rune(got)); n > 30 {
		t.Fatalf("must fit within max=30, got %q (%d runes)", got, n)
	}
}

func TestEgressUpdate_CopyKeyRequestsSelectedPath(t *testing.T) {
	path := "/Users/analyst/Library/Application Support/Foo/foo"
	m := NewEgress().withGroups([]model.EgressGroup{{App: "foo", Path: path, Concern: model.Low}})
	for _, key := range []rune{'y', 'c'} {
		next, _ := egressUpdate(m, tcell.KeyRune, key)
		if next.CopyReq != path {
			t.Fatalf("%q should request copy of the selected path, got %q", key, next.CopyReq)
		}
	}
}

func TestRunEgress_CopyPathToClipboard(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	path := "/Users/analyst/Library/Application Support/Claude/claude.app/Contents/MacOS/claude"
	sampler := fakeSampler{groups: []model.EgressGroup{{App: "claude", Path: path, Concern: model.Low}}}
	copied := make(chan string, 1)
	clip := func(p string) error {
		select {
		case copied <- p:
		default:
		}
		return nil
	}
	s.SetSize(120, 40)
	done := make(chan error, 1)
	go func() {
		done <- RunConsole(s, New(nil, nil), &fakeActor{}, sampler, nil, make(chan struct{}), clip, nil, "")
	}()
	s.InjectKey(tcell.KeyTab, 0, tcell.ModNone) // switch to Exfiltration (warm sample fires)
	time.Sleep(30 * time.Millisecond)           // let the sample land
	s.InjectKey(tcell.KeyRune, 'y', tcell.ModNone)
	time.Sleep(20 * time.Millisecond) // let the copy + status redraw happen
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunEgress did not quit")
	}
	select {
	case got := <-copied:
		if got != path {
			t.Fatalf("clipboard should receive the full path, got %q", got)
		}
	default:
		t.Fatal("clip was never called")
	}
	if !simContains(s, "copied") {
		t.Fatal("expected the 'copied' status on screen")
	}
}
