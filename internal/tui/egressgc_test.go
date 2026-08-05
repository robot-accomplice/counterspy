// internal/tui/egressgc_test.go
package tui

import (
	"strings"
	"testing"

	"counterspy/internal/model"
)

func liveGroup(pid int, path string) model.EgressGroup {
	return model.EgressGroup{App: "app", Path: path, Members: []model.EgressInstance{{PID: pid, Path: path}}}
}

// W1 hygiene (v0.7.0 ABORT re-review): decrypted-message buffers for a PID that has left the live
// group set must be GC'd, so a long session doesn't retain redacted-but-still-sensitive messages for
// dead PIDs forever. A PID absent for a full grace cycle is pruned.
func TestWithGroups_GCsMessagesForDeadPID(t *testing.T) {
	m := NewEgress()
	m.Messages = map[int][]model.InterceptedMessage{999: {{PID: 999, App: "gone", Path: "/x/gone"}}}
	m.MessageDropCount = map[int]int{999: 5}
	live := liveGroup(42, "/usr/bin/app")
	m = m.withGroups([]model.EgressGroup{live}) // 999 absent once -> grace
	m = m.withGroups([]model.EgressGroup{live}) // absent twice -> pruned
	if _, ok := m.Messages[999]; ok {
		t.Fatalf("messages for a dead PID must be GC'd, got %+v", m.Messages)
	}
	if _, ok := m.MessageDropCount[999]; ok {
		t.Fatalf("drop count for a dead PID must be GC'd, got %+v", m.MessageDropCount)
	}
}

// The GC must not drop a message that arrived just before its owning PID's first sample (the sampler
// and the message stream are eventually consistent; a one-tick grace covers that window).
func TestWithGroups_GraceKeepsJustArrivedMessage(t *testing.T) {
	m := NewEgress()
	m.Messages = map[int][]model.InterceptedMessage{77: {{PID: 77, App: "new", Path: "/x/new"}}}
	other := liveGroup(1, "/o")
	m = m.withGroups([]model.EgressGroup{other}) // 77 absent once -> grace, must be KEPT
	if len(m.Messages[77]) != 1 {
		t.Fatalf("a just-arrived message must survive one grace cycle, got %+v", m.Messages)
	}
}

// A PID that stays live keeps its messages indefinitely.
func TestWithGroups_KeepsMessagesForLivePID(t *testing.T) {
	m := NewEgress()
	m.Messages = map[int][]model.InterceptedMessage{42: {{PID: 42, App: "app", Path: "/usr/bin/app"}}}
	live := liveGroup(42, "/usr/bin/app")
	m = m.withGroups([]model.EgressGroup{live})
	m = m.withGroups([]model.EgressGroup{live})
	m = m.withGroups([]model.EgressGroup{live})
	if len(m.Messages[42]) != 1 {
		t.Fatalf("messages for a live PID must be kept, got %+v", m.Messages)
	}
}

// GC is the real mitigation for PID-recycle misattribution (a fragile App/Path tiebreak is unsafe:
// the PID join is deliberately path-agnostic because egress and intercept paths diverge). Once the
// original owner exits and is GC'd, a process that later reuses the PID inherits no stale messages.
func TestWithGroups_GCPreventsPIDRecycleMisattribution(t *testing.T) {
	m := NewEgress()
	m.ProxyAddr = "127.0.0.1:62443"
	// Slack captured under PID 500.
	m.Messages = map[int][]model.InterceptedMessage{
		500: {{PID: 500, App: "Slack", Path: "/Applications/Slack.app/Contents/MacOS/Slack",
			Direction: "request", Text: "POST /steal HTTP/1.1", DestName: "evil.example.com"}},
	}
	// Slack exits: two samples without PID 500 -> its buffer is GC'd.
	gone := liveGroup(1, "/o")
	m = m.withGroups([]model.EgressGroup{gone})
	m = m.withGroups([]model.EgressGroup{gone})
	// curl now reuses PID 500.
	curl := model.EgressGroup{App: "curl", Path: "/usr/bin/curl", Members: []model.EgressInstance{{PID: 500, Path: "/usr/bin/curl"}}}
	got := strings.Join(interceptSummary(m, curl, 6), "\n")
	if strings.Contains(got, "evil.example.com") || strings.Contains(got, "/steal") {
		t.Fatalf("Slack's captured flow must not render under a PID-recycled curl:\n%s", got)
	}
}
