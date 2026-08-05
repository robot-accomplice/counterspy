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

// Retention is bounded by FREEZING at capacity, not evicting: captured security evidence must never be
// dropped by a heuristic, because a quiet, low-volume beacon (the exact exfil this tool exists to catch)
// is precisely what any age/recency eviction would drop (re-review Defect 1). When full, a NEW PID is
// refused and the loss is DISCLOSED via InterceptStatus; every already-captured buffer, including the
// quietest oldest one, is retained.
func TestWithMessage_FreezesNewPIDsWhenFull_NeverEvictsExisting(t *testing.T) {
	m := NewEgress()
	// PID 1 is a quiet beacon: one flow, then never active again.
	m = m.withMessage(msg(1, "beacon", "/x/beacon", "POST /beacon HTTP/1.1", "c2.example.com"))
	for pid := 2; pid <= maxTrackedPIDs; pid++ { // fill to capacity (PIDs 1..maxTrackedPIDs)
		m = m.withMessage(msg(pid, "a", "/x/a", "GET / HTTP/1.1", "a"))
	}
	m = m.withMessage(msg(maxTrackedPIDs+1, "new", "/x/new", "GET / HTTP/1.1", "n")) // one PID over

	if len(m.Messages) != maxTrackedPIDs {
		t.Fatalf("tracked-PID count must be bounded at %d, got %d", maxTrackedPIDs, len(m.Messages))
	}
	if _, ok := m.Messages[1]; !ok {
		t.Fatalf("the quiet oldest beacon must NEVER be evicted (that is the exfil we exist to catch)")
	}
	if _, ok := m.Messages[maxTrackedPIDs+1]; ok {
		t.Fatalf("a NEW PID over capacity must be frozen out, not admitted by evicting an existing one")
	}
	if m.InterceptStatus == "" {
		t.Fatalf("a frozen-out flow must be DISCLOSED (InterceptStatus), never silently dropped")
	}
}

// A PID already tracked keeps receiving messages even at capacity (freeze only refuses NEW PIDs).
func TestWithMessage_TrackedPIDStillUpdatesAtCapacity(t *testing.T) {
	m := NewEgress()
	for pid := 1; pid <= maxTrackedPIDs; pid++ {
		m = m.withMessage(msg(pid, "a", "/x/a", "GET /1 HTTP/1.1", "a"))
	}
	m = m.withMessage(msg(1, "a", "/x/a", "GET /2 HTTP/1.1", "a")) // existing PID, at capacity
	if len(m.Messages[1]) != 2 {
		t.Fatalf("an already-tracked PID must keep updating at capacity, got %+v", m.Messages[1])
	}
}

// Pre-existing HIGH (v0.7.0 ABORT re-review): a DECRYPTED flow whose owner attribution missed lands as
// PID 0 / App "" / Path "" but carries real captured plaintext. It must be RETAINED (the proxy publishes
// unattributable flows deliberately, Rule 13) and DISCLOSED, not silently dropped as if a stream notice.
func TestWithMessage_RetainsUnattributedDecryptedFlow(t *testing.T) {
	m := NewEgress()
	m = m.withMessage(model.InterceptedMessage{ConnID: "c-1", Seq: 1, PID: 0, Status: model.FlowDecrypted, Direction: "request", Text: "POST /exfil HTTP/1.1"})
	total := 0
	for _, b := range m.Messages {
		total += len(b)
	}
	if total != 1 {
		t.Fatalf("an unattributed decrypted flow must be retained, not dropped: %+v", m.Messages)
	}
	if m.InterceptStatus == "" {
		t.Fatalf("an unattributed flow must be disclosed so captured exfil is never silently unseen")
	}
}

// A PID-attributed but nameless decrypted flow (proc_pidpath raced: PID set, App/Path empty) must file
// under its PID so it joins its app row normally, not be dropped.
func TestWithMessage_RetainsPIDKnownNamelessFlow(t *testing.T) {
	m := NewEgress()
	m = m.withMessage(model.InterceptedMessage{ConnID: "c-2", Seq: 1, PID: 4242, Status: model.FlowDecrypted, Direction: "request", Text: "POST /x HTTP/1.1"})
	if len(m.Messages[4242]) != 1 {
		t.Fatalf("a PID-attributed nameless flow must file under its PID: %+v", m.Messages)
	}
}

// A GENUINE stream notice (ownerless, connectionless, contentless: version mismatch / malformed record)
// must still surface to InterceptStatus and NOT be buffered under a phantom PID.
func TestWithMessage_GenuineStreamNoticeNotBuffered(t *testing.T) {
	m := NewEgress()
	m = m.withMessage(model.InterceptedMessage{Status: model.FlowError, Reason: "unsupported record version"})
	if len(m.Messages) != 0 {
		t.Fatalf("a genuine ownerless/connectionless notice must not be buffered: %+v", m.Messages)
	}
	if m.InterceptStatus == "" {
		t.Fatalf("a genuine notice must surface to InterceptStatus")
	}
}

// sameProc hardening: disjoint partial identity (one side Path-only, the other App-only) shares no
// comparable field and can only arise from a crafted untrusted record; treat as DIFFERENT (drop the
// stale buffer), never silently merge.
func TestSameProc_DisjointPartialIdentityTreatedDifferent(t *testing.T) {
	if sameProc(model.InterceptedMessage{Path: "/a/evil"}, model.InterceptedMessage{App: "victim"}) {
		t.Fatal("disjoint partial identity must be treated as different (conservative), not merged")
	}
}

// ...but a genuine same-process message that merely raced to an empty Path (same App) must NOT be
// treated as a recycle (no wrongful buffer clear).
func TestSameProc_TransientPathRaceSameProcessNotCleared(t *testing.T) {
	if !sameProc(model.InterceptedMessage{App: "python", Path: "/usr/bin/python"}, model.InterceptedMessage{App: "python", Path: ""}) {
		t.Fatal("a same-process message that raced to an empty Path must not be treated as a recycle")
	}
}
