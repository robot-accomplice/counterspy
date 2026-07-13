package tui

import (
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// End-to-end through RunConsole: z opens the zoom, i inspects the selected PID (stacking on top),
// closing the inspection returns to the zoom (not the tree), and z returns to the tree.
func TestRunConsole_ZoomAndInspect(t *testing.T) {
	s := simInit(t)
	fi := &fakeInspector{view: model.InspectView{Verdict: "plaintext — readable", Coverage: model.InspectPlaintext, Sent: "GET /x"}}
	sampler := fakeSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}
	tick := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- RunConsole(s, New(nil, nil), &fakeActor{}, sampler, fi, tick, nil) }()
	step := func() { time.Sleep(35 * time.Millisecond) }

	s.InjectKey(tcell.KeyTab, 0, tcell.ModNone) // → Exfiltration
	step()
	s.InjectKey(tcell.KeyRune, 'z', tcell.ModNone) // zoom the selected group
	step()
	if !simContains(s, "PIDs") {
		t.Fatal("z should open the zoom dashboard")
	}
	s.InjectKey(tcell.KeyRune, 'i', tcell.ModNone) // inspect the selected pid
	step()
	if fi.calls.Load() == 0 {
		t.Fatal("i in the zoom must trigger a capture")
	}
	s.InjectKey(tcell.KeyEscape, 0, tcell.ModNone) // inspection → back to the zoom
	step()
	if !simContains(s, "PIDs") {
		t.Fatal("closing inspect should return to the zoom, not the tree")
	}
	s.InjectKey(tcell.KeyRune, 'z', tcell.ModNone) // zoom → tree
	step()
	if !simContains(s, "Exfiltration") {
		t.Fatal("z should return to the tree")
	}
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunConsole did not exit")
	}
}

func zoomGroupFixture() model.EgressGroup {
	return model.EgressGroup{App: "claude", Trust: "notarized", Instances: 2, Cadence: "steady",
		OutRate: 1500, InRate: 122,
		Conns: []model.Conn{
			{PID: 1802, Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp", OutRate: 1400},
			{PID: 1990, Endpoint: model.Endpoint{IP: "5.6.7.8", Port: 443}, Proto: "tcp", OutRate: 100},
		},
		Members: []model.EgressInstance{
			{PID: 1802, Path: "/A/Claude Helper (GPU)", Trust: "notarized", OutRate: 1400, InRate: 120,
				Conns: []model.Conn{{PID: 1802, Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp", OutRate: 1400}}},
			{PID: 1990, Path: "/A/Claude Helper", Trust: "notarized", OutRate: 100, InRate: 2,
				Conns: []model.Conn{{PID: 1990, Endpoint: model.Endpoint{IP: "5.6.7.8", Port: 443}, Proto: "tcp", OutRate: 100}}},
		}}
}

// z opens the zoom for the selected row's group; ↑/↓ move the PID selection; t cycles the metric;
// i inspects the SELECTED pid's busiest conn (stacking on top); z/esc exits back to the tree.
func TestZoom_EnterSelectInspectExit(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m.Selected = 0

	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	if m.Zoom == nil || m.Zoom.app != "claude" {
		t.Fatal("z must open the zoom for the selected row's group")
	}
	m, _ = egressUpdate(m, tcell.KeyDown, 0)
	if m.Zoom.sel != 1 {
		t.Fatalf("down should move PID selection to 1, got %d", m.Zoom.sel)
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 't')
	if m.Zoom.mode != trendIn {
		t.Fatalf("t should cycle the metric to trendIn, got %v", m.Zoom.mode)
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 'i')
	if m.InspectReq == nil || m.InspectReq.pid != 1990 {
		t.Fatalf("i must request inspect for the selected PID 1990, got %+v", m.InspectReq)
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	if m.Zoom != nil {
		t.Fatal("z must close the zoom")
	}
}

func TestZoom_SelectionClamps(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	m, _ = egressUpdate(m, tcell.KeyUp, 0)
	if m.Zoom.sel != 0 {
		t.Fatalf("up at top clamps to 0, got %d", m.Zoom.sel)
	}
	for i := 0; i < 5; i++ {
		m, _ = egressUpdate(m, tcell.KeyDown, 0)
	}
	if m.Zoom.sel != 1 {
		t.Fatalf("down past the end clamps to the last PID (1), got %d", m.Zoom.sel)
	}
}

// A vanished group (re-resolved by name each frame) closes the zoom rather than rendering a ghost.
func TestZoom_VanishedGroupExits(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	m = m.withGroups(nil) // the app disappeared between ticks
	m, _ = egressUpdate(m, tcell.KeyDown, 0)
	if m.Zoom != nil {
		t.Fatal("a vanished group must close the zoom")
	}
}

func TestDrawEgressZoom_RendersPanelsAndSelection(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	g := zoomGroupFixture()
	g.Members[0].Spark = []uint64{100, 400, 800, 1200, 1400}
	g.Members[0].InSpark = []uint64{10, 40, 80, 100, 120}
	m := NewEgress().withGroups([]model.EgressGroup{g})
	m.Zoom = &zoomState{app: "claude", sel: 0, mode: trendOut}
	drawEgressZoom(s, m)
	s.Show()
	for _, want := range []string{"claude", "PIDs", "destinations", "this group", "1802", "1990", "%GRP"} {
		if !simContains(s, want) {
			t.Fatalf("zoom must render %q", want)
		}
	}
}

func TestDrawEgressZoom_TinyTerminalNoPanic(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(40, 10)
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m.Zoom = &zoomState{app: "claude", sel: 0, mode: trendOut}
	drawEgressZoom(s, m) // must not panic
	s.Show()
}

func TestPidShare(t *testing.T) {
	if got := pidShare(1400, 1500); got != 93 {
		t.Fatalf("share 1400/1500 = %d, want 93", got)
	}
	if got := pidShare(5, 0); got != 0 {
		t.Fatalf("divide-by-zero group rate must be 0%%, got %d", got)
	}
}

func TestZoomedMembers_SortedByOutDesc(t *testing.T) {
	ms := zoomedMembers(zoomGroupFixture())
	if ms[0].PID != 1802 || ms[1].PID != 1990 {
		t.Fatalf("members must sort by out-rate desc, got %d,%d", ms[0].PID, ms[1].PID)
	}
}
