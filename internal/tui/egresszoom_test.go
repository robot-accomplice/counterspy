package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// End-to-end through RunConsole: z opens the zoom, i inspects the selected PID (stacking on top),
// closing the inspection returns to the zoom (not the tree), and z returns to the tree.
func TestRunConsole_ZoomAndInspect(t *testing.T) {
	s := simInit(t)
	fi := &fakeInspector{view: model.InspectView{Verdict: "plaintext, readable", Coverage: model.InspectPlaintext, Sent: "GET /x"}}
	sampler := fakeSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}
	tick := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- RunConsole(s, New(nil, nil), &fakeActor{}, sampler, fi, tick, nil, nil, "") }()
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

// The non-emphasized lines must NOT change color as the rate-sort reshuffles the table; they plot
// in a stable PID order, so an overlapping cell's winner is deterministic (the observed "historical
// points change color" flicker). The emphasized (selected) line is held constant here (a loud PID
// that always sorts first) so this isolates the overlap-order flicker from the legitimate
// selection change.
func TestDrawEgressZoom_GraphStableUnderRateReorder(t *testing.T) {
	// PID 100 is always the loudest (always selected/emphasized). PIDs 200 and 300 share the same
	// history so their lines overlap, and their table order swaps between the two renders.
	mk := func(out200, out300 uint64) tcell.SimulationScreen {
		s := tcell.NewSimulationScreen("")
		if err := s.Init(); err != nil {
			t.Fatal(err)
		}
		s.SetSize(120, 40)
		overlap := []uint64{200, 900, 300, 1000, 500}
		g := model.EgressGroup{App: "claude", Trust: "notarized", OutRate: 10000,
			Members: []model.EgressInstance{
				{PID: 100, OutRate: 9000, Spark: []uint64{50, 60, 70, 60, 50}},
				{PID: 200, OutRate: out200, Spark: overlap},
				{PID: 300, OutRate: out300, Spark: overlap},
			}}
		m := NewEgress().withGroups([]model.EgressGroup{g})
		m.Zoom = &zoomState{app: "claude", sel: 0, mode: trendOut}
		drawEgressZoom(s, m)
		s.Show()
		return s
	}
	a := mk(500, 100) // 200 sorts before 300
	b := mk(100, 500) // 300 sorts before 200
	// The whole graph plot region must be identical in rune AND color under the reorder.
	for y := 2; y < 18; y++ {
		for x := 2; x < 60; x++ {
			ra, _, sta, _ := a.GetContent(x, y)
			rb, _, stb, _ := b.GetContent(x, y)
			if ra != rb || sta != stb {
				t.Fatalf("graph cell (%d,%d) changed with rate order: %q/%v vs %q/%v; plot order not stable",
					x, y, ra, sta, rb, stb)
			}
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

// g toggles the graph grouping between by-PID and by-destination.
func TestZoom_ToggleGraphByDest(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	if m.Zoom.byDest {
		t.Fatal("the graph starts grouped by PID")
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 'g')
	if !m.Zoom.byDest {
		t.Fatal("g must toggle the graph to by-destination")
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 'g')
	if m.Zoom.byDest {
		t.Fatal("g must toggle back to by-PID")
	}
}

// With the destinations box focused (g), arrow keys move the DEST cursor (not the PID cursor), and
// i inspects the busiest flow to the selected destination.
func TestZoom_ByDestNavigateAndInspect(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	m, _ = egressUpdate(m, tcell.KeyRune, 'g') // focus the destinations box
	if !m.Zoom.byDest {
		t.Fatal("g must focus the destinations box")
	}
	m, _ = egressUpdate(m, tcell.KeyDown, 0)
	if m.Zoom.selDest != 1 {
		t.Fatalf("down must move the DEST cursor, got %d", m.Zoom.selDest)
	}
	if m.Zoom.sel != 0 {
		t.Fatalf("the PID cursor must stay put while destinations are focused, got %d", m.Zoom.sel)
	}
	// dests sort by rate desc: [1.2.3.4:443, 5.6.7.8:443]; index 1 → 5.6.7.8:443 → pid 1990.
	m, _ = egressUpdate(m, tcell.KeyRune, 'i')
	if m.InspectReq == nil || m.InspectReq.pid != 1990 {
		t.Fatalf("i must inspect the busiest flow to the selected destination (pid 1990), got %+v", m.InspectReq)
	}
}

// The focused box is drawn with an accent border so the user can see where the arrow keys act.
func TestDrawPanel_FocusHighlightsBorder(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(20, 6)
	drawPanel(s, 0, 0, 10, 4, "A", true)
	if _, _, st, _ := s.GetContent(0, 0); fgOf(st) != colSelBar {
		t.Fatalf("a focused panel border must use the accent color, got %v", fgOf(st))
	}
	drawPanel(s, 0, 0, 10, 4, "A", false)
	if _, _, st, _ := s.GetContent(0, 0); fgOf(st) != colDivider {
		t.Fatalf("an unfocused panel border must use the divider color, got %v", fgOf(st))
	}
}

func fgOf(st tcell.Style) tcell.Color { fg, _, _ := st.Decompose(); return fg }

// The by-destination graph aggregates connections by endpoint, summing each endpoint's history
// across the PIDs that talk to it (aligned at the newest sample).
func TestDestSeriesList_AggregatesByEndpoint(t *testing.T) {
	g := model.EgressGroup{Conns: []model.Conn{
		{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Spark: []uint64{10, 20}},
		{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Spark: []uint64{5, 5}},
		{Endpoint: model.Endpoint{IP: "5.6.7.8", Port: 443}, Spark: []uint64{1, 1}},
	}}
	ds := destSeriesList(g, trendOut)
	if len(ds) != 2 {
		t.Fatalf("two unique endpoints expected, got %d", len(ds))
	}
	var got []uint64
	for _, d := range ds {
		if d.ep == "1.2.3.4:443" {
			got = d.vals
		}
	}
	if len(got) != 2 || got[0] != 15 || got[1] != 25 {
		t.Fatalf("1.2.3.4:443 history must sum to [15 25], got %v", got)
	}
}

func TestDrawEgressZoom_ByDestGraphTitle(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m.Zoom = &zoomState{app: "claude", sel: 0, mode: trendOut, byDest: true}
	drawEgressZoom(s, m)
	s.Show()
	if !simContains(s, "by dest") {
		t.Fatal("the graph title must reflect by-destination grouping")
	}
}

func TestPidShare(t *testing.T) {
	if got := pidShare(1400, 1500); got != 93 {
		t.Fatalf("share 1400/1500 = %d, want 93", got)
	}
	if got := pidShare(5, 0); got != 0 {
		t.Fatalf("divide-by-zero group rate must be 0%%, got %d", got)
	}
	if got := pidShare(1400, 1300); got != 100 { // sampling jitter: member > group → clamp
		t.Fatalf("share must clamp to 100%%, got %d", got)
	}
}

// A PID keeps its color across a rate-sorted reshuffle: the palette is keyed by PID, not row index.
func TestPidLineColor_StableByPID(t *testing.T) {
	if pidLineColor(1802) != pidLineColor(1802) {
		t.Fatal("same PID must map to the same color")
	}
}

// i on a stale selection (group shrank between ticks) must still act, not silently no-op: the sel
// re-clamps against fresh members every keypress.
func TestZoom_StaleSelectionReclampsForInspect(t *testing.T) {
	full := zoomGroupFixture()
	m := NewEgress().withGroups([]model.EgressGroup{full})
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	m, _ = egressUpdate(m, tcell.KeyDown, 0) // sel = 1 (PID 1990)
	// The group loses the 2nd PID between ticks; sel=1 is now out of range.
	shrunk := full
	shrunk.Members = full.Members[:1]
	shrunk.Conns = full.Conns[:1]
	m = m.withGroups([]model.EgressGroup{shrunk})
	m, _ = egressUpdate(m, tcell.KeyRune, 'i')
	if m.InspectReq == nil || m.InspectReq.pid != 1802 {
		t.Fatalf("i on a stale sel must re-clamp and inspect the remaining PID 1802, got %+v", m.InspectReq)
	}
}

func TestZoomedMembers_SortedByOutDesc(t *testing.T) {
	ms := zoomedMembers(zoomGroupFixture())
	if ms[0].PID != 1802 || ms[1].PID != 1990 {
		t.Fatalf("members must sort by out-rate desc, got %d,%d", ms[0].PID, ms[1].PID)
	}
}

// cp-p1g self-caught: a crafted destination NAME (from an observed DNS packet) must be Clean-stripped
// before it reaches the zoom panel: no ANSI/control chars into the terminal.
func TestZoomDestLabel_CleansCraftedName(t *testing.T) {
	g := model.EgressGroup{Conns: []model.Conn{
		{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443, Name: "evil\x1b[31m\r\ninject.example"}, OutRate: 10},
	}}
	ds := zoomDests(g)
	if len(ds) != 1 {
		t.Fatalf("expected 1 dest, got %d", len(ds))
	}
	// The label itself carries the raw name (keying/aggregation is fine); the DRAW path must Clean it.
	if got := model.Clean(ds[0].label); strings.ContainsAny(got, "\x1b\r\n") {
		t.Fatalf("model.Clean must strip control chars from the label: %q", got)
	}
}

// interceptSummary drives the three honest states of the decrypted-flows section (v0.7.0 W1): off
// (no --intercept → no section at all), on-but-empty for this app, and populated with per-message
// summaries. The section must never silently show nothing while intercept is active.
func TestInterceptSummary_HonestStates(t *testing.T) {
	g := model.EgressGroup{Path: "/bin/app", Members: []model.EgressInstance{{PID: 42}}}
	// 1. Not in intercept mode: no section.
	if got := interceptSummary(EgressModel{}, g, 6); got != nil {
		t.Fatalf("off mode must produce no section, got %v", got)
	}
	// 2. Intercept on, nothing captured for this app yet: honest empty line, not silence.
	m := EgressModel{ProxyAddr: "127.0.0.1:62443"}
	empty := interceptSummary(m, g, 6)
	if len(empty) < 2 || !strings.Contains(empty[0], "127.0.0.1:62443") ||
		!strings.Contains(strings.Join(empty, "\n"), "no decrypted flows for this app yet") {
		t.Fatalf("on-but-empty must state so honestly, got %v", empty)
	}
	// 3. Populated: per-message summaries with direction + start line + dest, joined by PID.
	m.Messages = map[int][]model.InterceptedMessage{
		42: {
			{PID: 42, Direction: "request", Text: "GET /v1/data HTTP/1.1\r\nHost: api.example.com", DestName: "api.example.com"},
			{PID: 42, Direction: "response", Text: "HTTP/1.1 200 OK\r\nContent-Type: application/json", DestName: "api.example.com"},
		},
	}
	got := strings.Join(interceptSummary(m, g, 6), "\n")
	for _, want := range []string{"→ GET /v1/data HTTP/1.1", "← HTTP/1.1 200 OK", "api.example.com"} {
		if !strings.Contains(got, want) {
			t.Fatalf("populated summary missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "no decrypted flows") {
		t.Fatalf("populated summary must not show the empty state:\n%s", got)
	}
}

// The join is by PID, NOT path: the regression that motivated the redesign. When the egress group's
// Path (ps comm) differs from the message's Path (proc_pidpath) but the PID matches, messages MUST
// still render. A path-keyed join silently showed nothing here.
func TestInterceptSummary_JoinsByPIDNotPath(t *testing.T) {
	g := model.EgressGroup{
		Path:    "/opt/homebrew/bin/curl",           // ps comm (symlink)
		Members: []model.EgressInstance{{PID: 777}}, // same real pid
	}
	m := EgressModel{
		ProxyAddr: "127.0.0.1:62443",
		Messages: map[int][]model.InterceptedMessage{
			777: {{PID: 777, Direction: "request", Text: "POST /u HTTP/1.1", DestName: "api.example.com"}},
		},
	}
	got := strings.Join(interceptSummary(m, g, 6), "\n")
	if !strings.Contains(got, "POST /u HTTP/1.1") || strings.Contains(got, "no decrypted flows") {
		t.Fatalf("PID join must render even when g.Path != msg.Path:\n%s", got)
	}
}

// destProxied flags the intercept proxy endpoint itself (where an app's decrypted egress goes while
// armed), replacing the external-IP match that could never fire in that mode. (v0.7.0 ABORT re-run.)
func TestDestProxied(t *testing.T) {
	if !destProxied("127.0.0.1:62443", "127.0.0.1:62443") {
		t.Fatal("the proxy endpoint must be flagged")
	}
	if destProxied("198.51.100.7:443", "127.0.0.1:62443") {
		t.Fatal("a real external dest must not be flagged as the proxy")
	}
	if destProxied("127.0.0.1:62443", "") {
		t.Fatal("no proxy addr (not armed) must never flag")
	}
}
