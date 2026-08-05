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

func msg(pid int, app, path, text, dest string) model.InterceptedMessage {
	return model.InterceptedMessage{PID: pid, App: app, Path: path, Direction: "request", Text: text, DestName: dest}
}

// Regression (v0.7.0 ABORT re-review, Defect 1): retention must NOT be keyed on the sampler's live
// set. A live process with a bursty/periodic connection is absent from a poll between bursts (group
// membership is `for pid := range conns`), so pruning by live-set membership drops captured flows for
// a still-alive, still-talking process, the exact exfil this tool exists to catch. withGroups must
// never drop a PID's messages just because it is absent from the current sample.
func TestWithMessage_RetainsBurstyLiveProcessAcrossAbsentSamples(t *testing.T) {
	m := NewEgress()
	m = m.withMessage(msg(100, "beacon", "/x/beacon", "POST /beacon HTTP/1.1", "c2.example.com"))
	other := liveGroup(1, "/o")
	m = m.withGroups([]model.EgressGroup{other}) // 100 absent (connection closed between polls)
	m = m.withMessage(msg(100, "beacon", "/x/beacon", "POST /beacon2 HTTP/1.1", "c2.example.com"))
	m = m.withGroups([]model.EgressGroup{other}) // still absent, but 100 is alive and talking
	if len(m.Messages[100]) != 2 {
		t.Fatalf("captured flows for a live, still-talking (bursty) PID must not be dropped, got %+v", m.Messages[100])
	}
}

// Recycle guard: when a PID is reused by a different process (intercept-side identity changes), the
// prior process's buffer is dropped so its flows never render under the new one. Both identities are
// intercept-side (proc_pidpath), so the comparison is safe (unlike egress-vs-intercept paths).
func TestWithMessage_RecycleClearsPriorProcessBuffer(t *testing.T) {
	m := NewEgress()
	m.ProxyAddr = "127.0.0.1:62443"
	m = m.withMessage(msg(500, "Slack", "/Applications/Slack.app/Contents/MacOS/Slack", "POST /steal HTTP/1.1", "evil.example.com"))
	// PID 500 reused by curl.
	m = m.withMessage(msg(500, "curl", "/usr/bin/curl", "GET /ok HTTP/1.1", "example.org"))
	curl := model.EgressGroup{App: "curl", Path: "/usr/bin/curl", Members: []model.EgressInstance{{PID: 500, Path: "/usr/bin/curl"}}}
	got := strings.Join(interceptSummary(m, curl, 6), "\n")
	if strings.Contains(got, "evil.example.com") || strings.Contains(got, "/steal") {
		t.Fatalf("a reused PID must not inherit the prior process's flows:\n%s", got)
	}
	if !strings.Contains(got, "example.org") {
		t.Fatalf("the new process's own flow must render:\n%s", got)
	}
}

// The same process sending many messages must NOT be treated as a recycle (identity unchanged).
func TestWithMessage_SameProcessNotClearedAcrossMessages(t *testing.T) {
	m := NewEgress()
	m = m.withMessage(msg(42, "app", "/usr/bin/app", "GET /a HTTP/1.1", "a.example.com"))
	m = m.withMessage(msg(42, "app", "/usr/bin/app", "GET /b HTTP/1.1", "b.example.com"))
	if len(m.Messages[42]) != 2 {
		t.Fatalf("same-process messages must accumulate, got %+v", m.Messages[42])
	}
}

// Retention is bounded: the number of PIDs whose buffers are kept is capped, and the LEAST recently
// active PID is evicted first (never the most recent), so a long session with many short-lived PIDs
// cannot grow the map without bound or retain redacted-but-sensitive data indefinitely.
func TestWithMessage_BoundsTrackedPIDsEvictingLeastRecent(t *testing.T) {
	m := NewEgress()
	// PID 1 is the oldest (least recently active) after this first message.
	m = m.withMessage(msg(1, "old", "/x/old", "GET /old HTTP/1.1", "old.example.com"))
	for pid := 2; pid <= maxTrackedPIDs+1; pid++ {
		m = m.withMessage(msg(pid, "a", "/x/a", "GET / HTTP/1.1", "a"))
	}
	if len(m.Messages) > maxTrackedPIDs {
		t.Fatalf("tracked-PID count must be bounded at %d, got %d", maxTrackedPIDs, len(m.Messages))
	}
	if _, ok := m.Messages[1]; ok {
		t.Fatalf("the least-recently-active PID must be evicted first, but PID 1 is still retained")
	}
	if _, ok := m.Messages[maxTrackedPIDs+1]; !ok {
		t.Fatalf("the most recent PID must be retained")
	}
}
