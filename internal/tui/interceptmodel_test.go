package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func pidFlow(at string, pid int, app, dest string) model.InterceptedFlow {
	return model.InterceptedFlow{At: at, PID: pid, App: app, DestName: dest, Status: model.FlowDecrypted}
}

// The left axis is PROCESSES, and it only grows when a pid not seen before speaks. Ten flows from one
// app must not make ten rows — that was the flat-list design's core mistake.
func TestInterceptModel_ListGrowsOnlyOnNewPID(t *testing.T) {
	m := NewIntercept()
	for i := 0; i < 10; i++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:0"+string(rune('0'+i))+"Z", 73722, "Safari", "a.example"))
	}
	if len(m.Apps) != 1 {
		t.Fatalf("one process must stay one row, got %d", len(m.Apps))
	}
	if len(m.Apps[0].Flows) != 10 {
		t.Fatalf("its log should hold all 10 flows, got %d", len(m.Apps[0].Flows))
	}
	m = m.withFlow(pidFlow("2026-07-16T10:00:11Z", 600, "Mail", "b.example"))
	if len(m.Apps) != 2 {
		t.Fatalf("a NEW pid must add a row, got %d", len(m.Apps))
	}
}

// Rows are first-seen ordered and never re-sorted: a list that reorders under you is unusable for
// watching one process.
func TestInterceptModel_ProcessOrderIsStable(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(pidFlow("2026-07-16T10:00:01Z", 1, "First", "a"))
	m = m.withFlow(pidFlow("2026-07-16T10:00:02Z", 2, "Second", "b"))
	// The busiest/newest process must NOT jump to the top.
	for i := 0; i < 5; i++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:1"+string(rune('0'+i))+"Z", 2, "Second", "b"))
	}
	if m.Apps[0].App != "First" || m.Apps[1].App != "Second" {
		t.Fatalf("first-seen order must hold, got %q then %q", m.Apps[0].App, m.Apps[1].App)
	}
}

// Selecting a process holds still while OTHER processes appear — the point of the stable axis.
func TestInterceptModel_SelectionSurvivesNewProcesses(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(pidFlow("2026-07-16T10:00:01Z", 1, "First", "a"))
	m = m.withFlow(pidFlow("2026-07-16T10:00:02Z", 2, "Second", "b"))
	m, _ = interceptUpdate(m, tcell.KeyUp, 0) // select "First"
	if got, _ := m.selected(); got.App != "First" {
		t.Fatalf("setup: expected First, got %q", got.App)
	}
	m = m.withFlow(pidFlow("2026-07-16T10:00:03Z", 3, "Third", "c"))
	if got, _ := m.selected(); got.App != "First" {
		t.Fatalf("a new process must not move the selection, got %q", got.App)
	}
}

// Within a process the log is a TIMELINE: a keep-alive flow publishes late but is stamped early, so it
// must file in At order, not arrival order.
func TestInterceptModel_LogIsTimeOrdered(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(pidFlow("2026-07-16T14:44:58Z", 1, "App", "late-arriving"))
	m = m.withFlow(pidFlow("2026-07-16T14:44:28Z", 1, "App", "started-earlier"))
	f := m.Apps[0].Flows
	if f[0].DestName != "started-earlier" || f[1].DestName != "late-arriving" {
		t.Fatalf("log must be time-ordered, got %q then %q", f[0].DestName, f[1].DestName)
	}
}

// Unattributed flows (pid 0) collect under one honest row rather than being dropped or faked.
func TestInterceptModel_UnattributedGetsItsOwnRow(t *testing.T) {
	m := NewIntercept().withFlow(model.InterceptedFlow{At: "2026-07-16T10:00:01Z", DestName: "x", Status: model.FlowDecrypted})
	if len(m.Apps) != 1 || m.Apps[0].Label() != "(unattributed)" {
		t.Fatalf("expected one (unattributed) row, got %+v", m.Apps)
	}
}

// Attribution can arrive on a later flow; the row adopts it rather than staying anonymous forever.
func TestInterceptModel_RowAdoptsLateAttribution(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(model.InterceptedFlow{At: "2026-07-16T10:00:01Z", PID: 7, Status: model.FlowDecrypted})
	m = m.withFlow(pidFlow("2026-07-16T10:00:02Z", 7, "Safari", "a"))
	if m.Apps[0].App != "Safari" {
		t.Fatalf("row should adopt the later attribution, got %q", m.Apps[0].App)
	}
}

// Both axes are bounded: the per-process log AND the process list (short-lived pids accumulate — every
// `curl` is a new one).
func TestInterceptModel_BothAxesBounded(t *testing.T) {
	m := NewIntercept()
	for i := 0; i < maxAppLog+50; i++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:00Z", 1, "Busy", "a"))
	}
	if len(m.Apps[0].Flows) > maxAppLog {
		t.Fatalf("per-process log unbounded: %d", len(m.Apps[0].Flows))
	}
	m2 := NewIntercept()
	for i := 0; i < maxApps+20; i++ {
		m2 = m2.withFlow(pidFlow("2026-07-16T10:00:00Z", i+1, "p", "a"))
	}
	if len(m2.Apps) > maxApps {
		t.Fatalf("process list unbounded: %d", len(m2.Apps))
	}
	if m2.Selected < 0 || m2.Selected >= len(m2.visible()) {
		t.Fatalf("selection out of range after eviction: %d", m2.Selected)
	}
}

// / finds a process by name or pid; it narrows which process you watch and never drops captured flows.
func TestInterceptModel_FilterFindsAProcess(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(pidFlow("2026-07-16T10:00:01Z", 73722, "Safari", "a"))
	m = m.withFlow(pidFlow("2026-07-16T10:00:02Z", 600, "Mail", "b"))
	m.Filter = "safari"
	if v := m.visible(); len(v) != 1 || v[0].App != "Safari" {
		t.Fatalf("name filter failed: %+v", v)
	}
	m.Filter = "600"
	if v := m.visible(); len(v) != 1 || v[0].App != "Mail" {
		t.Fatalf("pid filter failed: %+v", v)
	}
	if len(m.Apps) != 2 {
		t.Fatal("filtering must be a VIEW — no process may be dropped")
	}
}

// While typing the filter, ordinary keys must NOT act as commands — 'q' in "squirrel" must not quit.
func TestInterceptModel_TypingCapturesKeys(t *testing.T) {
	m := NewIntercept()
	m, _ = interceptUpdate(m, tcell.KeyRune, '/')
	if !m.Typing {
		t.Fatal("/ must open the find prompt")
	}
	for _, r := range "squirrel" {
		var quit bool
		if m, quit = interceptUpdate(m, tcell.KeyRune, r); quit {
			t.Fatalf("typing %q must not quit", r)
		}
	}
	if m.Filter != "squirrel" {
		t.Fatalf("filter = %q", m.Filter)
	}
	m, _ = interceptUpdate(m, tcell.KeyEnter, 0)
	if _, quit := interceptUpdate(m, tcell.KeyRune, 'q'); !quit {
		t.Fatal("q must quit once the prompt is closed")
	}
}

// Esc clears the filter before it quits — losing your place is worse than an extra keypress.
func TestInterceptModel_EscClearsFilterBeforeQuitting(t *testing.T) {
	m := NewIntercept()
	m.Filter = "safari"
	m, quit := interceptUpdate(m, tcell.KeyEscape, 0)
	if quit || m.Filter != "" {
		t.Fatalf("Esc must clear the filter first (quit=%v filter=%q)", quit, m.Filter)
	}
	if _, quit := interceptUpdate(m, tcell.KeyEscape, 0); !quit {
		t.Fatal("Esc with no filter must quit")
	}
}

// Scrolling back through the log stops the tail; f/G resumes it. A log that yanks you to the bottom
// while you're reading is unusable.
func TestInterceptModel_ScrollingStopsTheTail(t *testing.T) {
	m := NewIntercept().withFlow(pidFlow("2026-07-16T10:00:01Z", 1, "App", "a"))
	if !m.Follow {
		t.Fatal("a fresh view should follow")
	}
	m, _ = interceptUpdate(m, tcell.KeyPgUp, 0)
	if m.Follow {
		t.Fatal("scrolling back must stop the tail")
	}
	m, _ = interceptUpdate(m, tcell.KeyRune, 'f')
	if !m.Follow {
		t.Fatal("f must resume the tail")
	}
	m, _ = interceptUpdate(m, tcell.KeyRune, 'g')
	if m.Follow {
		t.Fatal("g (oldest) must stop the tail")
	}
}

// drawIntercept drives the PURE view: polling a live SimulationScreen while RunIntercepted draws is a
// real data race (-race caught it — tcell's GetContents isn't locked against Show).
func drawIntercept(t *testing.T, m InterceptModel) string {
	t.Helper()
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	defer s.Fini()
	s.SetSize(160, 30)
	interceptView(m, s)
	s.Show()
	return screenText(s)
}

// The process list shows the app + pid; the log shows timestamp, destination and content.
func TestInterceptView_ProcessListAndRunningLog(t *testing.T) {
	m := NewIntercept().withFlow(model.InterceptedFlow{
		At: "2026-07-16T14:44:48Z", PID: 600, App: "Mail", DestName: "mail-api.proton.me",
		Status: model.FlowDecrypted, SentText: "POST /core/v4/reports/sentry HTTP/1.1",
		RecvText: "HTTP/1.1 200 OK", SentBytes: 26836, RecvBytes: 1518,
	})
	out := drawIntercept(t, m)
	for _, want := range []string{"Mail", "600", "14:44:48", "mail-api.proton.me", "POST /core/v4/reports/sentry", "HTTP/1.1 200 OK"} {
		if !strings.Contains(out, want) {
			t.Fatalf("view missing %q:\n%s", want, out)
		}
	}
}

// A pinned flow logs its header and WHY, never the captured text.
func TestInterceptView_PinnedLogsReasonNotContent(t *testing.T) {
	m := NewIntercept().withFlow(model.InterceptedFlow{
		At: "2026-07-16T14:44:50Z", PID: 1, App: "Mail", DestName: "calendar.proton.me",
		Status: model.FlowPinned, SentText: "MUST-NOT-RENDER", RecvText: "MUST-NOT-RENDER",
	})
	out := drawIntercept(t, m)
	if strings.Contains(out, "MUST-NOT-RENDER") {
		t.Fatalf("a pinned flow must not render captured text:\n%s", out)
	}
	if !strings.Contains(out, "BYPASSED") {
		t.Fatalf("a pinned flow must explain why there is no content:\n%s", out)
	}
}

// The empty state says it is waiting rather than looking like nothing is happening.
func TestInterceptView_EmptyStateIsExplicit(t *testing.T) {
	if out := drawIntercept(t, NewIntercept()); !strings.Contains(out, "waiting for flows") {
		t.Fatalf("empty view must say it is waiting:\n%s", out)
	}
}

// A find that matches nothing must say so, not read as an empty capture.
func TestInterceptView_EmptyFilterResultIsExplained(t *testing.T) {
	m := NewIntercept().withFlow(pidFlow("2026-07-16T10:00:01Z", 1, "Safari", "a"))
	m.Filter = "nothing-matches-this"
	if out := drawIntercept(t, m); !strings.Contains(out, "no process matches") {
		t.Fatalf("a filtered-empty list must explain itself:\n%s", out)
	}
}

// The honest-status contract at the view layer: only decrypted reads as success, and mark owns the
// glyphs (a view-local glyph is undecodable — and the first version collided with GlyphRevoked).
func TestInterceptStatusStyle_HonestAndFromMark(t *testing.T) {
	if _, _, l := interceptStatusStyle(model.FlowDecrypted); l != "decrypted" {
		t.Fatalf("decrypted label = %q", l)
	}
	for _, st := range []string{model.FlowPinned, model.FlowOpaque, model.FlowError, "garbage"} {
		c, g, l := interceptStatusStyle(st)
		if c == colAccent || l == "decrypted" {
			t.Fatalf("%q must not read as success", st)
		}
		if g == 0 {
			t.Fatalf("%q has no glyph", st)
		}
		if whyNoContent(l) == "" {
			t.Fatalf("%q must explain why there is no content", st)
		}
	}
}

// The loop exits on q. (Rendering is covered by the pure view tests above.)
func TestRunIntercepted_QuitsCleanly(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(140, 30)
	flows := make(chan model.InterceptedFlow)
	done := make(chan error, 1)
	go func() { done <- RunIntercepted(s, flows) }()
	s.InjectKey(tcell.KeyRune, 'q', tcell.ModNone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunIntercepted: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunIntercepted did not exit on q")
	}
	close(flows)
}
