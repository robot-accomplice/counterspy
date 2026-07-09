package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func threeQ() Model {
	return New([]model.Assessment{
		mk("a", model.RecQuarantine, 14),
		mk("b", model.RecInvestigate, 8),
		mk("c", model.RecInvestigate, 6),
	}, nil)
}

func TestUpdate_NavClampsAtEnds(t *testing.T) {
	m := threeQ()
	for i := 0; i < 5; i++ {
		m, _ = update(m, tcell.KeyRune, 'j')
	}
	if m.Selected != 2 {
		t.Fatalf("selected should clamp at 2, got %d", m.Selected)
	}
	for i := 0; i < 5; i++ {
		m, _ = update(m, tcell.KeyRune, 'k')
	}
	if m.Selected != 0 {
		t.Fatalf("selected should clamp at 0, got %d", m.Selected)
	}
}

func TestUpdate_ToggleSortAndMonitor(t *testing.T) {
	m := threeQ()
	m, _ = update(m, tcell.KeyRune, 's')
	if !m.SortByRec {
		t.Fatal("s should enable sort-by-rec")
	}
	m, _ = update(m, tcell.KeyRune, 'm')
	if !m.ShowMonitor {
		t.Fatal("m should show monitor")
	}
}

func TestUpdate_FilterFlow(t *testing.T) {
	m := threeQ()
	m, _ = update(m, tcell.KeyRune, '/')
	if m.Focus != focusFilter {
		t.Fatal("/ should enter filter focus")
	}
	m, _ = update(m, tcell.KeyRune, 'a')
	if m.Filter != "a" {
		t.Fatalf("filter should be 'a', got %q", m.Filter)
	}
	m, _ = update(m, tcell.KeyEsc, 0)
	if m.Filter != "" || m.Focus != focusList {
		t.Fatalf("esc should clear filter and refocus list: %q %v", m.Filter, m.Focus)
	}
}

func TestUpdate_Quit(t *testing.T) {
	m := threeQ()
	_, cmds := update(m, tcell.KeyRune, 'Q')
	if len(cmds) != 1 || cmds[0].Op != "quit" {
		t.Fatalf("Q should emit quit, got %+v", cmds)
	}
	_, cmds = update(m, tcell.KeyCtrlC, 0)
	if len(cmds) != 1 || cmds[0].Op != "quit" {
		t.Fatalf("ctrl-c should emit quit, got %+v", cmds)
	}
}

func TestUpdate_QuarantineModalConfirm(t *testing.T) {
	m := threeQ() // selected 0 = "a", Quarantine tier
	m, cmds := update(m, tcell.KeyRune, 'q')
	if m.Focus != focusModal || len(cmds) != 0 {
		t.Fatalf("q should open modal, no cmd yet: focus=%v cmds=%v", m.Focus, cmds)
	}
	m, cmds = update(m, tcell.KeyEnter, 0)
	if m.Focus != focusList || len(cmds) != 1 || cmds[0].Op != "quarantine" || cmds[0].A.Subject.Label != "a" {
		t.Fatalf("enter should confirm quarantine of 'a': %v %+v", m.Focus, cmds)
	}
}

func TestUpdate_QuarantineModalCancel(t *testing.T) {
	m := threeQ()
	m, _ = update(m, tcell.KeyRune, 'q')
	m, cmds := update(m, tcell.KeyEsc, 0)
	if m.Focus != focusList || len(cmds) != 0 {
		t.Fatalf("esc should cancel with no cmd: %v %+v", m.Focus, cmds)
	}
}

func TestUpdate_RestoreEmitsCmd(t *testing.T) {
	m := threeQ()
	_, cmds := update(m, tcell.KeyRune, 'u')
	if len(cmds) != 1 || cmds[0].Op != "restore" {
		t.Fatalf("u should emit restore: %+v", cmds)
	}
}

// cp-tui-1 QA F-1: Ctrl-C must quit from ANY mode, including filter capture.
func TestUpdate_CtrlCQuitsFromFilter(t *testing.T) {
	m := threeQ()
	m, _ = update(m, tcell.KeyRune, '/') // enter filter
	_, cmds := update(m, tcell.KeyCtrlC, 0)
	if len(cmds) != 1 || cmds[0].Op != "quit" {
		t.Fatalf("ctrl-c must quit even from filter mode, got %+v", cmds)
	}
}

// cp-tui-3: a --from snapshot is read-only — 'q' must not open the quarantine modal.
func TestUpdate_ReadOnlyBlocksQuarantine(t *testing.T) {
	m := threeQ()
	m.ReadOnly = true
	m, _ = update(m, tcell.KeyRune, 'q')
	if m.Focus == focusModal {
		t.Fatal("read-only must not open the quarantine modal")
	}
	if m.Toast == "" {
		t.Fatal("read-only should explain why quarantine is blocked")
	}
}

func TestUpdate_HelpToggle(t *testing.T) {
	m := threeQ()
	m, _ = update(m, tcell.KeyRune, '?')
	if m.Focus != focusHelp {
		t.Fatal("? should open help")
	}
	m, _ = update(m, tcell.KeyEsc, 0)
	if m.Focus != focusList {
		t.Fatal("esc should close help")
	}
}
