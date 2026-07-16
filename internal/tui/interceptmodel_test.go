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
