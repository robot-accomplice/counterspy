package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func pidFlow(at string, pid int, app, dest string) model.InterceptedFlow {
	return model.InterceptedFlow{At: at, PID: pid, App: app, DestName: dest, Status: model.FlowDecrypted}
}

// The navigation axis is APPS, and it only grows on a name not seen before. This is THE property that
// makes it navigable: pids are not stable (every `curl` run is a new one, every Safari helper another),
// so a pid-keyed list accumulates dead rows and becomes an endless scroll.
func TestInterceptModel_ListGrowsOnlyOnNewApp(t *testing.T) {
	m := NewIntercept()
	for i := 0; i < 10; i++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:0"+string(rune('0'+i))+"Z", 73722, "Safari", "a.example"))
	}
	if len(m.Apps) != 1 {
		t.Fatalf("one app must stay one row, got %d", len(m.Apps))
	}
	if len(m.Apps[0].Flows) != 10 {
		t.Fatalf("its log should hold all 10 flows, got %d", len(m.Apps[0].Flows))
	}
	m = m.withFlow(pidFlow("2026-07-16T10:00:11Z", 600, "Mail", "b.example"))
	if len(m.Apps) != 2 {
		t.Fatalf("a NEW app must add a row, got %d", len(m.Apps))
	}
}

// 50 curl runs are 50 pids but ONE app: the navigation pane must not grow per pid. This is the defect
// that made the previous version an endless scroll.
func TestInterceptModel_ManyPidsOfOneAppCollapse(t *testing.T) {
	m := NewIntercept()
	for pid := 1000; pid < 1050; pid++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:00Z", pid, "curl", "example.com"))
	}
	if len(m.Apps) != 1 {
		t.Fatalf("50 curl pids must collapse into one row, got %d", len(m.Apps))
	}
	if len(m.Apps[0].Flows) != 50 {
		t.Fatalf("every pid's flow still belongs in the log, got %d", len(m.Apps[0].Flows))
	}
	// The pid is not lost — it moves into the log, where it is information rather than navigation.
	if !strings.Contains(renderLog(m.Apps[0]), "[pid 1000]") {
		t.Fatalf("the pid must appear on the log line:\n%s", renderLog(m.Apps[0]))
	}
}

// renderLog flattens an app's log lines for assertions.
func renderLog(a appRow) string {
	var b strings.Builder
	for _, l := range logLines(a) {
		b.WriteString(l.text + "\n")
	}
	return b.String()
}

// Rows are first-seen ordered and never re-sorted: a list that reorders under you is unusable for
// watching one app.
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

// A flow we could not attribute STAYS in (unattributed), even if the same pid is later identified.
// Re-homing it would move rows under the reader — the instability this whole design removes — and it
// would also be a small lie: at capture time we genuinely did not know who sent it.
func TestInterceptModel_UnattributedIsNotRetroactivelyRehomed(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(model.InterceptedFlow{At: "2026-07-16T10:00:01Z", PID: 7, Status: model.FlowDecrypted})
	m = m.withFlow(pidFlow("2026-07-16T10:00:02Z", 7, "Safari", "a"))
	if len(m.Apps) != 2 {
		t.Fatalf("the unattributed flow must stay put, expected 2 rows, got %d", len(m.Apps))
	}
	if m.Apps[0].Label() != "(unattributed)" || m.Apps[1].App != "Safari" {
		t.Fatalf("rows: %q, %q", m.Apps[0].Label(), m.Apps[1].Label())
	}
}

// The log is bounded (flows are the unbounded axis). The APP list needs no eviction — it is bounded by
// the number of distinct programs that actually talk, which is what makes it a navigation pane.
func TestInterceptModel_LogIsBounded(t *testing.T) {
	m := NewIntercept()
	for i := 0; i < maxAppLog+50; i++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:00Z", 1, "Busy", "a"))
	}
	if len(m.Apps[0].Flows) > maxAppLog {
		t.Fatalf("per-app log unbounded: %d", len(m.Apps[0].Flows))
	}
}

// / finds an app by name; it narrows which app you watch and never drops captured flows.
func TestInterceptModel_FilterFindsAnApp(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(pidFlow("2026-07-16T10:00:01Z", 73722, "Safari", "a"))
	m = m.withFlow(pidFlow("2026-07-16T10:00:02Z", 600, "Mail", "b"))
	m.Filter = "safari"
	if v := m.visible(); len(v) != 1 || v[0].App != "Safari" {
		t.Fatalf("name filter failed: %+v", v)
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

// Tailing is a POSITION (Back == 0), not a mode: it starts there, PgUp walks back, PgDn returns, and
// switching apps returns. There is no follow key to press and no mode to track.
func TestInterceptModel_TailingIsAPositionNotAMode(t *testing.T) {
	m := NewIntercept()
	for i := 0; i < 30; i++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:00Z", 1, "App", "a"))
	}
	if m.Back != 0 {
		t.Fatal("a fresh log starts at the newest line")
	}
	m, _ = interceptUpdate(m, tcell.KeyPgUp, 0)
	if m.Back == 0 {
		t.Fatal("PgUp must walk back through the log")
	}
	m, _ = interceptUpdate(m, tcell.KeyPgDn, 0)
	if m.Back != 0 {
		t.Fatalf("PgDn back to the newest must resume tailing implicitly, Back=%d", m.Back)
	}
	// Switching apps starts that app's log at its newest line.
	m = m.withFlow(pidFlow("2026-07-16T10:00:31Z", 2, "Other", "b"))
	m, _ = interceptUpdate(m, tcell.KeyPgUp, 0)
	m, _ = interceptUpdate(m, tcell.KeyDown, 0)
	if m.Back != 0 {
		t.Fatalf("switching app must start at its newest line, Back=%d", m.Back)
	}
}

// A reader scrolled back must stay on the SAME content as the log grows underneath them — otherwise a
// busy app scrolls what you're reading off the screen.
func TestInterceptModel_ScrollPositionHoldsAsLogGrows(t *testing.T) {
	m := NewIntercept()
	for i := 0; i < 30; i++ {
		m = m.withFlow(pidFlow("2026-07-16T10:00:00Z", 1, "App", "a"))
	}
	m, _ = interceptUpdate(m, tcell.KeyPgUp, 0)
	back, lines := m.Back, len(logLines(m.Apps[0]))
	m = m.withFlow(pidFlow("2026-07-16T10:00:40Z", 1, "App", "a")) // a new flow lands below
	grew := len(logLines(m.Apps[0])) - lines
	if m.Back != back+grew {
		t.Fatalf("position must hold as the log grows: Back %d -> %d, log grew by %d", back, m.Back, grew)
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

// The app list shows the app; the log shows timestamp, destination, content — and the pid.
func TestInterceptView_AppListAndRunningLog(t *testing.T) {
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
	if out := drawIntercept(t, m); !strings.Contains(out, "no app matches") {
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

// The log shows the FULL captured body — no display cap. An earlier version capped at 8 lines and
// printed "… (N more lines)", which was both unreachable and a lie.
func TestInterceptView_ShowsFullCapturedBody(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "Header-%d: value\n", i)
	}
	m := NewIntercept().withFlow(model.InterceptedFlow{
		At: "2026-07-17T12:45:56Z", PID: 717, App: "WhatsApp", DestName: "api.whatsapp.net",
		Status: model.FlowDecrypted, SentText: b.String(), SentBytes: 715, RecvBytes: 707,
	})
	out := renderLog(m.Apps[0])
	if !strings.Contains(out, "Header-39: value") {
		t.Fatalf("every captured line must be present (the log scrolls):\n%s", out)
	}
	if strings.Contains(out, "more lines") {
		t.Fatalf("no unreachable ellipsis should remain:\n%s", out)
	}
}

// THE honesty fix: the proxy caps what it CAPTURES at model.FlowCaptureBytes per direction. A flow whose
// wire bytes exceed that was truncated at capture — the rest was never recorded — and saying "… N more
// lines" would imply content we never had. It must say so explicitly.
func TestInterceptView_SaysWhenTheCAPTUREWasTruncated(t *testing.T) {
	m := NewIntercept().withFlow(model.InterceptedFlow{
		At: "2026-07-17T12:45:56Z", PID: 600, App: "Proton Mail Helper", DestName: "mail-api.proton.me",
		Status: model.FlowDecrypted, SentText: "POST /core/v4/reports/sentry HTTP/1.1\nbody",
		SentBytes: 26836, RecvBytes: 1518, // 26836 on the wire, only FlowCaptureBytes captured
	})
	out := renderLog(m.Apps[0])
	if !strings.Contains(out, "capture truncated") || !strings.Contains(out, "never captured") {
		t.Fatalf("a capture-truncated flow must SAY so, not imply the rest is merely hidden:\n%s", out)
	}
	if !strings.Contains(out, "8 KB") || !strings.Contains(out, "26 KB") {
		t.Fatalf("it must state how much of how much:\n%s", out)
	}
}

// A flow that fits inside the capture cap must NOT claim truncation.
func TestInterceptView_NoTruncationNoticeWhenFullyCaptured(t *testing.T) {
	m := NewIntercept().withFlow(model.InterceptedFlow{
		At: "2026-07-17T12:45:56Z", PID: 717, App: "WhatsApp", DestName: "api.whatsapp.net",
		Status: model.FlowDecrypted, SentText: "POST /falco/pigeon_health_metrics HTTP/1.1",
		SentBytes: 715, RecvBytes: 707,
	})
	if out := renderLog(m.Apps[0]); strings.Contains(out, "capture truncated") {
		t.Fatalf("a fully-captured flow must not claim truncation:\n%s", out)
	}
}

// Packets are separate things: the log carries a divider between them (and none before the first).
func TestInterceptView_DividerBetweenPackets(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(pidFlow("2026-07-17T12:45:56Z", 1, "App", "a.example"))
	if rules := countRules(logLines(m.Apps[0])); rules != 0 {
		t.Fatalf("one packet needs no divider, got %d", rules)
	}
	m = m.withFlow(pidFlow("2026-07-17T12:45:57Z", 1, "App", "b.example"))
	m = m.withFlow(pidFlow("2026-07-17T12:45:58Z", 1, "App", "c.example"))
	if rules := countRules(logLines(m.Apps[0])); rules != 2 {
		t.Fatalf("three packets need two dividers, got %d", rules)
	}
}

func countRules(ls []logLine) int {
	n := 0
	for _, l := range ls {
		if l.rule {
			n++
		}
	}
	return n
}
