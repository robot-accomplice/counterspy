package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func flowAt(at, name, status string) model.InterceptedFlow {
	return model.InterceptedFlow{At: at, DestName: name, Status: status}
}

// The ordering defect the first live run exposed: flows are PUBLISHED when their connection closes but
// stamped when it opened, so a keep-alive flow arrives after shorter ones that started later. The
// viewer must present a true timeline regardless of arrival order.
func TestInterceptModel_SortsByTimeNotArrival(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(flowAt("2026-07-16T14:44:58Z", "late-arriving", model.FlowPinned))
	m = m.withFlow(flowAt("2026-07-16T14:44:28Z", "started-earlier", model.FlowDecrypted))
	if m.Flows[0].DestName != "started-earlier" || m.Flows[1].DestName != "late-arriving" {
		t.Fatalf("flows must be time-ordered, got %q then %q", m.Flows[0].DestName, m.Flows[1].DestName)
	}
}

// A flow landing ABOVE the selection must not yank the selection onto a different row.
func TestInterceptModel_SelectionFollowsItsFlowAcrossInserts(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(flowAt("2026-07-16T10:00:05Z", "b", model.FlowDecrypted))
	m = m.withFlow(flowAt("2026-07-16T10:00:09Z", "c", model.FlowDecrypted))
	m, _ = interceptUpdate(m, tcell.KeyUp, 0) // select "b"; Follow off
	if got, _ := m.selected(); got.DestName != "b" {
		t.Fatalf("setup: expected b selected, got %q", got.DestName)
	}
	m = m.withFlow(flowAt("2026-07-16T10:00:01Z", "a", model.FlowDecrypted)) // inserts ABOVE b
	if got, _ := m.selected(); got.DestName != "b" {
		t.Fatalf("selection must stay on b after an insert above it, got %q", got.DestName)
	}
}

// Follow sticks to the newest; navigating away releases it so the view stops moving under the reader.
func TestInterceptModel_FollowSticksThenReleases(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(flowAt("2026-07-16T10:00:01Z", "a", model.FlowDecrypted))
	m = m.withFlow(flowAt("2026-07-16T10:00:02Z", "b", model.FlowDecrypted))
	if got, _ := m.selected(); got.DestName != "b" {
		t.Fatalf("follow must select the newest, got %q", got.DestName)
	}
	m, _ = interceptUpdate(m, tcell.KeyUp, 0)
	if m.Follow {
		t.Fatal("navigating up must release follow")
	}
	m = m.withFlow(flowAt("2026-07-16T10:00:03Z", "c", model.FlowDecrypted))
	if got, _ := m.selected(); got.DestName != "a" {
		t.Fatalf("with follow off the selection must not jump to the newest, got %q", got.DestName)
	}
}

// Retention is bounded — a long live session must not grow forever.
func TestInterceptModel_BoundedRetention(t *testing.T) {
	m := NewIntercept()
	for i := 0; i < maxInterceptFlows+50; i++ {
		m = m.withFlow(model.InterceptedFlow{At: "2026-07-16T10:00:00Z", Status: model.FlowDecrypted})
	}
	if len(m.Flows) > maxInterceptFlows {
		t.Fatalf("retention unbounded: %d flows", len(m.Flows))
	}
	if m.Selected < 0 || m.Selected >= len(m.Flows) {
		t.Fatalf("selection out of range after eviction: %d", m.Selected)
	}
}

// q quits.
func TestInterceptModel_QuitKeys(t *testing.T) {
	if _, quit := interceptUpdate(NewIntercept(), tcell.KeyRune, 'q'); !quit {
		t.Fatal("q must quit")
	}
}

// The honest-status contract, at the view layer: only `decrypted` reads as success, and every other
// status carries an explanation rather than an empty pane.
func TestInterceptStatusStyle_HonestAndExplained(t *testing.T) {
	if _, l := interceptStatusStyle(model.FlowDecrypted); l != "decrypted" {
		t.Fatalf("decrypted label = %q", l)
	}
	for _, st := range []string{model.FlowPinned, model.FlowOpaque, model.FlowError, "garbage"} {
		c, l := interceptStatusStyle(st)
		if c == colAccent {
			t.Fatalf("%q must NOT use the success colour", st)
		}
		if l == "decrypted" {
			t.Fatalf("%q must not be labelled decrypted", st)
		}
		if interceptWhyNoContent(l) == "" {
			t.Fatalf("%q must explain why there is no content", st)
		}
	}
}

// Rendering is tested by driving the PURE view directly rather than polling a live loop: tcell's
// SimulationScreen.GetContents() is not lock-protected against its own Show(), so polling the screen
// while RunIntercepted draws is a genuine data race (-race caught it) and would ship a flaky test.
func drawIntercept(t *testing.T, m InterceptModel) string {
	t.Helper()
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	defer s.Fini()
	s.SetSize(140, 30)
	interceptView(m, s)
	s.Show()
	return screenText(s)
}

// A decrypted flow renders its destination in the list and its masked request/response in the detail.
func TestInterceptView_RendersDecryptedDetail(t *testing.T) {
	m := NewIntercept().withFlow(model.InterceptedFlow{
		At: "2026-07-16T14:44:48Z", DestName: "mail-api.proton.me", Status: model.FlowDecrypted,
		SentText: "POST /core/v4/reports/sentry HTTP/1.1", RecvText: "HTTP/1.1 200 OK",
		SentBytes: 26836, RecvBytes: 1518,
	})
	out := drawIntercept(t, m)
	for _, want := range []string{"mail-api.proton.me", "decrypted", "POST /core/v4/reports/sentry", "HTTP/1.1 200 OK", "14:44:48"} {
		if !strings.Contains(out, want) {
			t.Fatalf("view missing %q:\n%s", want, out)
		}
	}
}

// A pinned flow must render its status + WHY, and never the captured text.
func TestInterceptView_PinnedShowsReasonNotContent(t *testing.T) {
	m := NewIntercept().withFlow(model.InterceptedFlow{
		At: "2026-07-16T14:44:50Z", DestName: "pinned.example", Status: model.FlowPinned,
		SentText: "MUST-NOT-RENDER", RecvText: "MUST-NOT-RENDER",
	})
	out := drawIntercept(t, m)
	if strings.Contains(out, "MUST-NOT-RENDER") {
		t.Fatalf("a pinned flow must not render captured text:\n%s", out)
	}
	if !strings.Contains(out, "pinned") || !strings.Contains(out, "BYPASSED") {
		t.Fatalf("a pinned flow must explain why there is no content:\n%s", out)
	}
}

// The empty state says it is waiting rather than looking like "nothing is happening".
func TestInterceptView_EmptyStateIsExplicit(t *testing.T) {
	if out := drawIntercept(t, NewIntercept()); !strings.Contains(out, "waiting for flows") {
		t.Fatalf("empty view must say it is waiting:\n%s", out)
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

func appFlow(at, app, dest string) model.InterceptedFlow {
	return model.InterceptedFlow{At: at, App: app, PID: 42, DestName: dest, Status: model.FlowDecrypted}
}

// Tailing a single source: the filter matches the ORIGINATING APP — the question the tool asks.
func TestInterceptModel_TailsASingleApp(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(appFlow("2026-07-16T10:00:01Z", "Safari", "example.com"))
	m = m.withFlow(appFlow("2026-07-16T10:00:02Z", "Mail", "mail-api.proton.me"))
	m = m.withFlow(appFlow("2026-07-16T10:00:03Z", "Safari", "news.example"))
	m.Filter = "safari" // case-insensitive
	vis := m.visible()
	if len(vis) != 2 {
		t.Fatalf("expected Safari's 2 flows, got %d", len(vis))
	}
	for _, f := range vis {
		if f.App != "Safari" {
			t.Fatalf("filter leaked %q", f.App)
		}
	}
	if len(m.Flows) != 3 {
		t.Fatal("filtering must be a VIEW — the underlying timeline must not be dropped")
	}
}

// The filter falls back to the destination so it still works for flows we could not attribute.
func TestInterceptModel_FilterFallsBackToDestination(t *testing.T) {
	m := NewIntercept()
	m = m.withFlow(appFlow("2026-07-16T10:00:01Z", "", "mail-api.proton.me")) // unattributed
	m = m.withFlow(appFlow("2026-07-16T10:00:02Z", "Safari", "example.com"))
	m.Filter = "proton"
	if v := m.visible(); len(v) != 1 || v[0].DestName != "mail-api.proton.me" {
		t.Fatalf("destination fallback failed: %+v", v)
	}
}

// While typing the filter, ordinary keys must NOT act as commands — 'q' in "squirrel" must not quit.
func TestInterceptModel_TypingCapturesKeys(t *testing.T) {
	m := NewIntercept()
	m, _ = interceptUpdate(m, tcell.KeyRune, '/')
	if !m.Typing {
		t.Fatal("/ must open the filter prompt")
	}
	for _, r := range "squirrel" {
		var quit bool
		m, quit = interceptUpdate(m, tcell.KeyRune, r)
		if quit {
			t.Fatalf("typing %q must not quit", r)
		}
	}
	if m.Filter != "squirrel" {
		t.Fatalf("filter = %q", m.Filter)
	}
	m, _ = interceptUpdate(m, tcell.KeyEnter, 0)
	if m.Typing {
		t.Fatal("Enter must close the prompt")
	}
	// Now q quits again.
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

// Follow must stick to the newest VISIBLE flow, not the newest overall — otherwise tailing one app
// jumps to another app's traffic.
func TestInterceptModel_FollowRespectsTheFilter(t *testing.T) {
	m := NewIntercept()
	m.Filter = "safari"
	m = m.withFlow(appFlow("2026-07-16T10:00:01Z", "Safari", "a"))
	m = m.withFlow(appFlow("2026-07-16T10:00:02Z", "Mail", "b")) // filtered OUT, and newest
	got, ok := m.selected()
	if !ok || got.App != "Safari" {
		t.Fatalf("follow must stay on the tailed source, got %+v ok=%v", got, ok)
	}
}

// The app is the headline in the list, and an unattributed flow says so rather than looking blank.
func TestInterceptView_ShowsAppAndUnattributed(t *testing.T) {
	m := NewIntercept().withFlow(appFlow("2026-07-16T14:44:48Z", "Mail", "mail-api.proton.me"))
	if out := drawIntercept(t, m); !strings.Contains(out, "Mail") || !strings.Contains(out, "pid 42") {
		t.Fatalf("view must show the app + pid:\n%s", out)
	}
	u := NewIntercept().withFlow(model.InterceptedFlow{At: "2026-07-16T14:44:48Z", DestName: "x.example", Status: model.FlowDecrypted})
	if out := drawIntercept(t, u); !strings.Contains(out, "unattributed") {
		t.Fatalf("an unattributed flow must say so:\n%s", out)
	}
}

// A filter that hides everything must say so — an empty list must not read as "nothing is happening".
func TestInterceptView_EmptyFilterResultIsExplained(t *testing.T) {
	m := NewIntercept().withFlow(appFlow("2026-07-16T10:00:01Z", "Safari", "a"))
	m.Filter = "nothing-matches-this"
	if out := drawIntercept(t, m); !strings.Contains(out, "no flows match") {
		t.Fatalf("a filtered-empty list must explain itself:\n%s", out)
	}
}
