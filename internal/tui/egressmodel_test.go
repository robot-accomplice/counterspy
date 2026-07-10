// internal/tui/egressmodel_test.go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func eg(app string, c model.ConcernLevel, rate uint64) model.EgressGroup {
	return model.EgressGroup{App: app, Path: "/x/" + app, Concern: c, OutRate: rate,
		Conns: []model.Conn{{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp"}}}
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

func TestEgressUpdate_ExpandCollapseAddsChildRows(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Elevated, 900)})
	if n := len(m.visibleRows()); n != 1 {
		t.Fatalf("collapsed = %d rows, want 1", n)
	}
	m, _ = egressUpdate(m, tcell.KeyEnter, 0) // expand selected
	if n := len(m.visibleRows()); n != 2 {    // group + its 1 conn
		t.Fatalf("expanded = %d rows, want 2", n)
	}
	m, _ = egressUpdate(m, tcell.KeyLeft, 0) // collapse
	if n := len(m.visibleRows()); n != 1 {
		t.Fatalf("re-collapsed = %d rows, want 1", n)
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
