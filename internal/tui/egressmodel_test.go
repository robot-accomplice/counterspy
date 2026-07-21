// internal/tui/egressmodel_test.go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func eg(app string, c model.ConcernLevel, rate uint64) model.EgressGroup {
	return model.EgressGroup{App: app, Path: "/x/" + app, Concern: c, OutRate: rate,
		Conns: []model.Conn{{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp"}},
		Members: []model.EgressInstance{{
			PID: 100, Path: "/x/" + app, Trust: "signed", OutRate: rate,
			Conns: []model.Conn{{PID: 100, Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp", OutRate: rate}},
		}},
	}
}

// egMulti builds a group with 2 members (pid 1 has 2 conns, pid 2 has 1 conn), for exercising
// all 3 levels of the tree.
func egMulti(app string) model.EgressGroup {
	return model.EgressGroup{
		App: app, Path: "/x/" + app,
		Members: []model.EgressInstance{
			{PID: 1, Path: "/x/" + app, Conns: []model.Conn{
				{PID: 1, Endpoint: model.Endpoint{IP: "1.1.1.1", Port: 443}, Proto: "tcp"},
				{PID: 1, Endpoint: model.Endpoint{IP: "2.2.2.2", Port: 80}, Proto: "tcp"},
			}},
			{PID: 2, Path: "/x/" + app, Conns: []model.Conn{
				{PID: 2, Endpoint: model.Endpoint{IP: "3.3.3.3", Port: 53}, Proto: "udp"},
			}},
		},
	}
}

func TestEgressUpdate_QuitAndPause(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 10)})
	if _, quit := egressUpdate(m, tcell.KeyRune, 'Q'); !quit {
		t.Fatal("Q should quit")
	}
	m2, _ := egressUpdate(m, tcell.KeyRune, 'p')
	if !m2.Paused {
		t.Fatal("p should toggle pause")
	}
}

// TestVisibleRows_ThreeLevelTree walks all 3 levels: collapsed app -> expand app (reveals
// instances) -> expand an instance (reveals its conns) -> collapse each level back down.
func TestVisibleRows_ThreeLevelTree(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{egMulti("app")})
	if n := len(m.visibleRows()); n != 1 {
		t.Fatalf("collapsed app = %d rows, want 1", n)
	}

	m, _ = egressUpdate(m, tcell.KeyEnter, 0) // expand the app (selected row 0 = header)
	if n := len(m.visibleRows()); n != 3 {    // header + 2 instances
		t.Fatalf("app-expanded = %d rows, want 1 + len(Members) = 3", n)
	}

	m.Selected = 1 // pid 1's instance row (has 2 conns)
	m, _ = egressUpdate(m, tcell.KeyRight, 0)
	if n := len(m.visibleRows()); n != 5 { // header + 2 instances + pid 1's 2 conns
		t.Fatalf("instance-expanded = %d rows, want 5", n)
	}

	m, _ = egressUpdate(m, tcell.KeyLeft, 0) // collapse pid 1's conns (selection still on its row)
	if n := len(m.visibleRows()); n != 3 {
		t.Fatalf("instance-collapsed = %d rows, want 3", n)
	}

	m.Selected = 0
	m, _ = egressUpdate(m, tcell.KeyLeft, 0) // collapse the app
	if n := len(m.visibleRows()); n != 1 {
		t.Fatalf("app-collapsed = %d rows, want 1", n)
	}
}

// TestEgressUpdate_ExpandConnRowIsNoOp confirms leaf (conn) rows have no further level to open.
func TestEgressUpdate_ExpandConnRowIsNoOp(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{egMulti("app")})
	m, _ = egressUpdate(m, tcell.KeyEnter, 0) // expand app
	m.Selected = 1
	m, _ = egressUpdate(m, tcell.KeyEnter, 0) // expand pid 1's instance
	m.Selected = 2                            // first conn row under pid 1
	before := len(m.visibleRows())
	m, _ = egressUpdate(m, tcell.KeyRight, 0) // expanding a leaf is a no-op
	if n := len(m.visibleRows()); n != before {
		t.Fatalf("expanding a conn (leaf) row should be a no-op, rows changed %d -> %d", before, n)
	}
}

func TestEgressUpdate_SortByConcern(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("low", model.Low, 999), eg("elev", model.Elevated, 1)})
	m.Sort = sortConcern
	rows := m.visibleRows()
	if rows[0].group.App != "elev" {
		t.Fatalf("sort by concern should put elevated first, got %s", rows[0].group.App)
	}
}

func TestClamp(t *testing.T) {
	if got := clamp(0, 0); got != 0 {
		t.Fatalf("clamp(0,0) = %d, want 0", got)
	}
	if got := clamp(-5, 3); got != 0 {
		t.Fatalf("negative index should clamp to 0, got %d", got)
	}
	if got := clamp(99, 3); got != 2 {
		t.Fatalf("over-max index should clamp to n-1=2, got %d", got)
	}
	if got := clamp(1, 3); got != 1 {
		t.Fatalf("in-range index should pass through, got %d", got)
	}
}

func TestWithGroups_SelectionResetWhenOutOfRange(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 1), eg("b", model.Low, 2), eg("c", model.Low, 3)})
	m.Selected = 2
	m = m.withGroups([]model.EgressGroup{eg("a", model.Low, 1)}) // shrink to 1 group
	if m.Selected != 0 {
		t.Fatalf("selection should reset to 0 when it falls out of range, got %d", m.Selected)
	}
}

func TestOrderedGroups_FilterExcludesNonMatching(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("backuptool", model.Low, 1), eg("zoom", model.Low, 2)})
	m.Filter = "back"
	got := m.orderedGroups()
	if len(got) != 1 || got[0].App != "backuptool" {
		t.Fatalf("filter should exclude non-matching groups, got %+v", got)
	}
}

func TestOrderedGroups_SortExfilAndApp(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("b", model.Low, 1), eg("a", model.Low, 2)})
	m.Groups[0].ExfilRisk, m.Groups[1].ExfilRisk = model.Low, model.Elevated // b=Low, a=Elevated
	m.Sort = sortExfil
	if got := m.orderedGroups(); got[0].App != "a" {
		t.Fatalf("sortExfil should put highest exfil risk first, got %s", got[0].App)
	}
	m.Sort = sortApp
	if got := m.orderedGroups(); got[0].App != "a" || got[1].App != "b" {
		t.Fatalf("sortApp should sort alphabetically, got %+v", got)
	}
}

func TestEgressUpdate_CtrlCQuits(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 1)})
	if _, quit := egressUpdate(m, tcell.KeyCtrlC, 0); !quit {
		t.Fatal("ctrl-c should quit")
	}
}

func TestEgressUpdate_ArrowKeysAndJK(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 1), eg("b", model.Low, 2)})
	m, _ = egressUpdate(m, tcell.KeyDown, 0)
	if m.Selected != 1 {
		t.Fatalf("KeyDown should move selection to 1, got %d", m.Selected)
	}
	m, _ = egressUpdate(m, tcell.KeyUp, 0)
	if m.Selected != 0 {
		t.Fatalf("KeyUp should move selection back to 0, got %d", m.Selected)
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 'j')
	if m.Selected != 1 {
		t.Fatalf("'j' should move selection to 1, got %d", m.Selected)
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 'k')
	if m.Selected != 0 {
		t.Fatalf("'k' should move selection back to 0, got %d", m.Selected)
	}
}

func TestEgressUpdate_SortCyclesAllFourModes(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 1)})
	if m.Sort != sortRate {
		t.Fatalf("default sort should be sortRate, got %v", m.Sort)
	}
	seen := []egressSort{m.Sort}
	for i := 0; i < 4; i++ {
		m, _ = egressUpdate(m, tcell.KeyRune, 's')
		seen = append(seen, m.Sort)
	}
	want := []egressSort{sortRate, sortConcern, sortExfil, sortApp, sortRate}
	for i, w := range want {
		if seen[i] != w {
			t.Fatalf("sort cycle step %d = %v, want %v (full sequence %v)", i, seen[i], w, seen)
		}
	}
}

func TestEgressUpdate_TrendToggle(t *testing.T) {
	m := NewEgress()
	if m.Trend != trendOut {
		t.Fatal("default trend mode must be out")
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 't')
	if m.Trend != trendIn {
		t.Fatal("t → in")
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 't')
	if m.Trend != trendCombined {
		t.Fatal("t → combined")
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 't')
	if m.Trend != trendOut {
		t.Fatal("t → back to out")
	}
}

// withMessage joins by PID, routes ownerless stream-level notices to a global status line, and counts
// overflow drops per PID — the v0.7.0 ABORT re-run fixes for the merged intercept view.
func TestWithMessage_PIDJoinStatusAndDrops(t *testing.T) {
	var m EgressModel

	// A per-app message files under its PID.
	m = m.withMessage(model.InterceptedMessage{PID: 10, Path: "/bin/a", Direction: "request", Text: "GET / HTTP/1.1"})
	if len(m.Messages[10]) != 1 {
		t.Fatalf("message must file under PID 10: %+v", m.Messages)
	}

	// A version/malformed notice (no owner) goes to the global status line, NOT a phantom app.
	m = m.withMessage(model.InterceptedMessage{Status: model.FlowError, Reason: "unsupported record version — is the daemon the same build?"})
	if m.InterceptStatus == "" || len(m.Messages) != 1 {
		t.Fatalf("ownerless notice must set InterceptStatus and add no app, got status=%q messages=%v", m.InterceptStatus, m.Messages)
	}

	// Overflow drops are counted per PID, attributed to the right app.
	for i := 0; i < 520; i++ {
		m = m.withMessage(model.InterceptedMessage{PID: 20, Path: "/bin/b", Seq: i, Direction: "request"})
	}
	if m.MessageDropCount[20] != 20 {
		t.Fatalf("PID 20 should have 20 drops (520-500), got %d", m.MessageDropCount[20])
	}
	if m.MessageDropCount[10] != 0 {
		t.Fatalf("PID 10 drops must not be attributed elsewhere, got %d", m.MessageDropCount[10])
	}
}
