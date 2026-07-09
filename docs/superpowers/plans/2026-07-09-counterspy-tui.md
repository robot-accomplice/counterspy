# CounterSpy TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `counterspy tui`, an interactive tcell triage UI over the existing `[]model.Assessment` core — navigate findings, drill into evidence, quarantine/restore.

**Architecture:** A thin `internal/tui` package on the outer ring. The state logic is a **pure `update(Model, key, rune) (Model, []Cmd)`** and pure `Model` helpers; tcell only does I/O in `view` and `Run`. The TUI acts through an `Actor` interface that `internal/act` (via a `main`-side adapter) satisfies — so the whole flow is testable with a fake actor and `tcell.SimulationScreen`, no sudo, no live scan.

**Tech Stack:** Go 1.21+, `github.com/gdamore/tcell/v2` (the first third-party dep — pinned/vendored), reusing `internal/{model,interpret,act}`.

## Global Constraints

- Module `counterspy`; new package `internal/tui`; new subcommand `counterspy tui`.
- **Zero changes to `internal/score`, `internal/interpret`, `internal/collect`** (§12 decoupling invariant). The TUI renders `model.Assessment` and calls the `Actor`; it performs no analysis.
- `internal/tui` imports only `model`, `act` (interface only, via `main` adapter — tui itself imports just `model` + tcell + stdlib), tcell, and stdlib. Verify no `score`/`collect`/`interpret` import in `tui`.
- Pure/testable core: `update` and `Model` helpers do no I/O. tcell touches the screen only in `view`/`Run`.
- Color encodes tier but is never the ONLY cue (recommendation text always shown).
- gofmt clean, `go vet` clean, tests pass without sudo or a live scan.

---

## File Structure

```
internal/tui/
  model.go       # Model, focusMode, palette (tcell colors), New(), visible(), counts()
  update.go      # Cmd, update(Model, tcell.Key, rune) (Model, []Cmd)  — pure
  view.go        # view(Model, tcell.Screen) + draw helpers  — tcell I/O
  run.go         # Actor interface, Run(tcell.Screen, Model, Actor) error  — event loop
  *_test.go
main.go          # add `tui` subcommand: --from snapshot | live scan, no-TTY guard, cliActor
testdata/tui_snapshot.json   # a []Assessment fixture for --from + tests
go.mod / go.sum  # add gdamore/tcell/v2
```

---

### Task 1: Add tcell + Model foundation (pure)

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/tui/model.go`, `internal/tui/model_test.go`

**Interfaces:**
- Produces: `Model` struct; `type focusMode int` with `focusList, focusModal, focusHelp, focusFilter`; `New(assessments []model.Assessment, gaps []string) Model`; `func (m Model) visible() []model.Assessment`; `func (m Model) counts() (q, inv, mon int)`; a `palette` of `tcell.Color` values.

- [ ] **Step 1: Add the dependency**

```bash
cd ~/code/counterspy && go get github.com/gdamore/tcell/v2@latest && go mod tidy
```
Expected: `go.mod` now requires `github.com/gdamore/tcell/v2`.

- [ ] **Step 2: Write the failing test**

`internal/tui/model_test.go`:
```go
package tui

import (
	"testing"

	"counterspy/internal/model"
)

func mk(label string, rec model.Recommendation, score int) model.Assessment {
	return model.Assessment{
		Finding:        model.Finding{Subject: model.Subject{Label: label}, Score: score},
		Recommendation: rec, Category: "test",
	}
}

func TestVisible_HidesMonitorUntilToggled(t *testing.T) {
	m := New([]model.Assessment{
		mk("q1", model.RecQuarantine, 12),
		mk("m1", model.RecMonitor, 2),
	}, nil)
	if len(m.visible()) != 1 {
		t.Fatalf("monitor should be hidden by default, got %d", len(m.visible()))
	}
	m.ShowMonitor = true
	if len(m.visible()) != 2 {
		t.Fatalf("monitor should show when toggled, got %d", len(m.visible()))
	}
}

func TestVisible_FilterByName(t *testing.T) {
	m := New([]model.Assessment{mk("alpha", model.RecInvestigate, 6), mk("beta", model.RecInvestigate, 6)}, nil)
	m.Filter = "alph"
	if v := m.visible(); len(v) != 1 || v[0].Subject.Label != "alpha" {
		t.Fatalf("filter failed: %+v", v)
	}
}

func TestCounts(t *testing.T) {
	m := New([]model.Assessment{
		mk("q", model.RecQuarantine, 12), mk("i", model.RecInvestigate, 6),
		mk("m1", model.RecMonitor, 2), mk("m2", model.RecMonitor, 1),
	}, nil)
	q, inv, mon := m.counts()
	if q != 1 || inv != 1 || mon != 2 {
		t.Fatalf("counts wrong: %d/%d/%d", q, inv, mon)
	}
}
```

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/tui/`
Expected: FAIL — `undefined: New`.

- [ ] **Step 4: Write `internal/tui/model.go`**

```go
// Package tui is an interactive tcell triage face over []model.Assessment. It performs
// no analysis — it renders findings and acts through the Actor interface (§12 invariant).
package tui

import (
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"counterspy/internal/model"
)

type focusMode int

const (
	focusList focusMode = iota
	focusModal
	focusHelp
	focusFilter
)

// palette mirrors the report tier scheme as tcell colors.
var (
	colAccent      = tcell.NewRGBColor(90, 208, 168)  // mint
	colDim         = tcell.NewRGBColor(102, 120, 138) // slate
	colQuarantine  = tcell.NewRGBColor(255, 107, 107) // red
	colInvestigate = tcell.NewRGBColor(255, 180, 84)  // amber
	colMonitor     = tcell.NewRGBColor(124, 142, 160) // gray
	colText        = tcell.NewRGBColor(196, 208, 220)
)

// Model is the pure UI state. No I/O touches it.
type Model struct {
	Assessments []model.Assessment
	Gaps        []string
	Selected    int    // index into visible()
	Filter      string
	SortByRec   bool   // false = sort by score desc
	ShowMonitor bool
	Focus       focusMode
	Pending     model.Assessment // the item shown in the confirm modal
	Done        map[string]bool  // Subject.Key() of quarantined items
	Toast       string
}

func New(assessments []model.Assessment, gaps []string) Model {
	return Model{Assessments: assessments, Gaps: gaps, Done: map[string]bool{}}
}

func recRank(r model.Recommendation) int {
	switch r {
	case model.RecQuarantine:
		return 0
	case model.RecInvestigate:
		return 1
	default:
		return 2
	}
}

// visible applies filter + monitor-collapse + sort. Pure.
func (m Model) visible() []model.Assessment {
	out := make([]model.Assessment, 0, len(m.Assessments))
	for _, a := range m.Assessments {
		if !m.ShowMonitor && a.Recommendation == model.RecMonitor {
			continue
		}
		if m.Filter != "" && !strings.Contains(strings.ToLower(a.Subject.Display()), strings.ToLower(m.Filter)) {
			continue
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if m.SortByRec {
			if recRank(out[i].Recommendation) != recRank(out[j].Recommendation) {
				return recRank(out[i].Recommendation) < recRank(out[j].Recommendation)
			}
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func (m Model) counts() (q, inv, mon int) {
	for _, a := range m.Assessments {
		switch a.Recommendation {
		case model.RecQuarantine:
			q++
		case model.RecInvestigate:
			inv++
		default:
			mon++
		}
	}
	return
}
```

- [ ] **Step 5: Run tests, verify pass; commit**

Run: `go test ./internal/tui/ && go vet ./...`
Expected: PASS.
```bash
git add go.mod go.sum internal/tui/
git commit -m "feat(tui): tcell dep + pure Model (visible/counts)"
```

---

### Task 2: update() — navigation (pure)

**Files:**
- Create: `internal/tui/update.go`
- Modify: `internal/tui/model_test.go` (add nav tests) or new `update_test.go`

**Interfaces:**
- Produces: `type Cmd struct { Op string; A model.Assessment }` (Op ∈ `"quarantine"`,`"restore"`,`"quit"`); `func update(m Model, key tcell.Key, r rune) (Model, []Cmd)`.
- Consumes: `Model`, `visible()`.

- [ ] **Step 1: Write the failing test**

`internal/tui/update_test.go`:
```go
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

func TestUpdate_NavDownStopsAtBottom(t *testing.T) {
	m := threeQ()
	for i := 0; i < 5; i++ {
		m, _ = update(m, tcell.KeyRune, 'j')
	}
	if m.Selected != 2 {
		t.Fatalf("selected should clamp at 2, got %d", m.Selected)
	}
}

func TestUpdate_NavUpStopsAtTop(t *testing.T) {
	m := threeQ()
	m.Selected = 1
	m, _ = update(m, tcell.KeyRune, 'k')
	m, _ = update(m, tcell.KeyRune, 'k')
	if m.Selected != 0 {
		t.Fatalf("selected should clamp at 0, got %d", m.Selected)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/tui/ -run Update`
Expected: FAIL — `undefined: update`.

- [ ] **Step 3: Write `internal/tui/update.go`**

```go
package tui

import (
	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Cmd is an effect the event loop must perform (Run executes it). update stays pure.
type Cmd struct {
	Op string // "quarantine" | "restore" | "quit"
	A  model.Assessment
}

// update is the pure state transition: a key event → new Model + effects.
func update(m Model, key tcell.Key, r rune) (Model, []Cmd) {
	n := len(m.visible())
	switch key {
	case tcell.KeyDown:
		return moveSel(m, +1, n), nil
	case tcell.KeyUp:
		return moveSel(m, -1, n), nil
	case tcell.KeyRune:
		switch r {
		case 'j':
			return moveSel(m, +1, n), nil
		case 'k':
			return moveSel(m, -1, n), nil
		}
	}
	return m, nil
}

func moveSel(m Model, d, n int) Model {
	if n == 0 {
		m.Selected = 0
		return m
	}
	m.Selected += d
	if m.Selected < 0 {
		m.Selected = 0
	}
	if m.Selected > n-1 {
		m.Selected = n - 1
	}
	return m
}
```

- [ ] **Step 4: Run tests, verify pass; commit**

Run: `go test ./internal/tui/ && go vet ./...`
```bash
git add internal/tui/
git commit -m "feat(tui): pure update — navigation + Cmd effects"
```

---

### Task 3: update() — filter, sort, monitor toggle, quit (pure)

**Files:**
- Modify: `internal/tui/update.go`, `internal/tui/update_test.go`

**Interfaces:**
- Consumes/extends `update`. No new exported symbols.

- [ ] **Step 1: Write the failing tests**

Append to `internal/tui/update_test.go`:
```go
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
	m, _ = update(m, tcell.KeyRune, '/') // enter filter mode
	if m.Focus != focusFilter {
		t.Fatal("/ should enter filter focus")
	}
	m, _ = update(m, tcell.KeyRune, 'a') // type
	if m.Filter != "a" {
		t.Fatalf("filter should be 'a', got %q", m.Filter)
	}
	m, _ = update(m, tcell.KeyEsc, 0) // clear + exit
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
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/tui/ -run Update`
Expected: FAIL.

- [ ] **Step 3: Extend `update`**

Replace the body of `update` in `internal/tui/update.go` with:
```go
func update(m Model, key tcell.Key, r rune) (Model, []Cmd) {
	// Filter capture mode: keys build the filter string until Esc/Enter.
	if m.Focus == focusFilter {
		switch key {
		case tcell.KeyEsc:
			m.Filter, m.Focus, m.Selected = "", focusList, 0
		case tcell.KeyEnter:
			m.Focus = focusList
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if m.Filter != "" {
				m.Filter = m.Filter[:len(m.Filter)-1]
			}
			m.Selected = 0
		case tcell.KeyRune:
			m.Filter += string(r)
			m.Selected = 0
		}
		return m, nil
	}

	if key == tcell.KeyCtrlC {
		return m, []Cmd{{Op: "quit"}}
	}
	n := len(m.visible())
	switch key {
	case tcell.KeyDown:
		return moveSel(m, +1, n), nil
	case tcell.KeyUp:
		return moveSel(m, -1, n), nil
	case tcell.KeyRune:
		switch r {
		case 'j':
			return moveSel(m, +1, n), nil
		case 'k':
			return moveSel(m, -1, n), nil
		case 's':
			m.SortByRec = !m.SortByRec
		case 'm':
			m.ShowMonitor = !m.ShowMonitor
			m.Selected = 0
		case '/':
			m.Focus = focusFilter
		case 'Q':
			return m, []Cmd{{Op: "quit"}}
		}
	}
	return m, nil
}
```

- [ ] **Step 4: Run tests, verify pass; commit**

Run: `go test ./internal/tui/`
```bash
git add internal/tui/
git commit -m "feat(tui): update — filter/sort/monitor/quit"
```

---

### Task 4: update() — quarantine modal + restore (pure effects)

**Files:**
- Modify: `internal/tui/update.go`, `internal/tui/update_test.go`

**Interfaces:**
- Extends `update`: `q` opens the modal, Enter-in-modal emits `Cmd{Op:"quarantine"}`, `u` emits `Cmd{Op:"restore"}`. Adds `markDone(key string)` behavior handled by `Run` (update only emits the Cmd).

- [ ] **Step 1: Write the failing tests**

Append to `internal/tui/update_test.go`:
```go
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
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/tui/ -run 'Modal|Restore'`
Expected: FAIL.

- [ ] **Step 3: Extend `update`**

In `internal/tui/update.go`, add a modal branch at the very top of `update` (before the filter branch):
```go
	if m.Focus == focusModal {
		switch key {
		case tcell.KeyEnter:
			m.Focus = focusList
			return m, []Cmd{{Op: "quarantine", A: m.Pending}}
		case tcell.KeyEsc:
			m.Focus = focusList
		}
		return m, nil
	}
```
And in the `tcell.KeyRune` switch, add `q` and `u` cases:
```go
		case 'q':
			v := m.visible()
			if len(v) > 0 && v[m.Selected].Recommendation != model.RecMonitor {
				m.Pending = v[m.Selected]
				m.Focus = focusModal
			}
		case 'u':
			return m, []Cmd{{Op: "restore"}}
```

- [ ] **Step 4: Run tests, verify pass; commit**

Run: `go test ./internal/tui/`
```bash
git add internal/tui/
git commit -m "feat(tui): update — quarantine modal + restore effects"
```

---

### Task 5: view() — render via SimulationScreen

**Files:**
- Create: `internal/tui/view.go`, `internal/tui/view_test.go`

**Interfaces:**
- Produces: `func view(m Model, s tcell.Screen)`; internal `drawText(s, x, y, style, text) int`.
- Consumes: `Model`, `visible()`, `counts()`, palette.

- [ ] **Step 1: Write the failing test**

`internal/tui/view_test.go`:
```go
package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"counterspy/internal/model"
)

func screenText(s tcell.SimulationScreen) string {
	cells, w, h := s.GetContents()
	var b strings.Builder
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r := cells[y*w+x].Runes
			if len(r) > 0 && r[0] != 0 {
				b.WriteRune(r[0])
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestView_RendersSummaryAndHidesMonitor(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	m := New([]model.Assessment{
		mk("evil.updater", model.RecQuarantine, 14),
		mk("zoom", model.RecMonitor, 2),
	}, nil)
	view(m, s)
	s.Show()
	out := screenText(s)
	if !strings.Contains(out, "CounterSpy") || !strings.Contains(out, "evil.updater") {
		t.Fatalf("summary/finding missing:\n%s", out)
	}
	if strings.Contains(out, "zoom") {
		t.Fatalf("monitor item should be hidden by default:\n%s", out)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/tui/ -run View`
Expected: FAIL — `undefined: view`.

- [ ] **Step 3: Write `internal/tui/view.go`**

```go
package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"counterspy/internal/model"
)

func drawText(s tcell.Screen, x, y int, style tcell.Style, text string) int {
	for _, r := range text {
		s.SetContent(x, y, r, nil, style)
		x++
	}
	return x
}

func tierColor(r model.Recommendation) tcell.Color {
	switch r {
	case model.RecQuarantine:
		return colQuarantine
	case model.RecInvestigate:
		return colInvestigate
	default:
		return colMonitor
	}
}

// view draws the whole UI to the screen. tcell I/O only — no state changes.
func view(m Model, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	def := tcell.StyleDefault.Foreground(colText)
	q, inv, mon := m.counts()

	// Header + summary.
	drawText(s, 2, 0, def.Foreground(colAccent).Bold(true), "CounterSpy")
	drawText(s, 2, 1, def.Foreground(colQuarantine), fmt.Sprintf("● %d Quarantine", q))
	drawText(s, 20, 1, def.Foreground(colInvestigate), fmt.Sprintf("▲ %d Investigate", inv))
	drawText(s, 40, 1, def.Foreground(colMonitor), fmt.Sprintf("· %d Monitor", mon))
	row := 2
	for _, g := range m.Gaps {
		drawText(s, 2, row, def.Foreground(colInvestigate), "⚠ "+g)
		row++
	}

	// Left: findings table. Right: detail.
	split := w / 2
	vis := m.visible()
	listTop := row + 1
	for i, a := range vis {
		y := listTop + i
		if y >= h-1 {
			break
		}
		st := def.Foreground(tierColor(a.Recommendation))
		if i == m.Selected {
			st = st.Reverse(true)
		}
		name := a.Subject.Display()
		if m.Done[a.Subject.Key()] {
			name = "✓ " + name
		}
		line := fmt.Sprintf(" %-11s %-28s %5d", strings.ToUpper(string(a.Recommendation)), truncate(name, 28), a.Score)
		drawText(s, 0, y, st, truncate(line, split-1))
	}
	if len(vis) == 0 {
		drawText(s, 2, listTop, def.Foreground(colDim), "no findings match")
	}

	// Detail pane for the selection.
	if len(vis) > 0 && m.Selected < len(vis) {
		drawDetail(s, split+2, listTop, w-split-3, vis[m.Selected])
	}

	// Footer.
	drawText(s, 2, h-1, def.Foreground(colDim),
		"j/k move · q quarantine · u restore · m monitor · s sort · / filter · ? help · Q quit")

	// Toast.
	if m.Toast != "" {
		drawText(s, 2, h-2, def.Foreground(colAccent), m.Toast)
	}

	// Modal on top.
	if m.Focus == focusModal {
		drawModal(s, m.Pending)
	}
}

func drawDetail(s tcell.Screen, x, y, wdt int, a model.Assessment) {
	def := tcell.StyleDefault.Foreground(colText)
	drawText(s, x, y, def.Bold(true), truncate(a.Subject.Display(), wdt))
	drawText(s, x, y+1, def.Foreground(colDim), truncate(a.Category+" · score "+itoa(a.Score), wdt))
	drawText(s, x, y+3, def, truncate(a.Verdict, wdt))
	if a.Tripwire != "" {
		drawText(s, x, y+5, def.Foreground(colQuarantine), truncate("⚠ tripwire: "+a.Tripwire, wdt))
	}
	ey := y + 7
	drawText(s, x, ey, def.Foreground(colDim), "EVIDENCE")
	for i, e := range a.Evidence {
		drawText(s, x, ey+1+i, def, truncate(string(e.Kind)+"  "+e.Summary, wdt))
	}
}

func drawModal(s tcell.Screen, a model.Assessment) {
	w, h := s.Size()
	bw, bh := 60, 8
	x0, y0 := (w-bw)/2, (h-bh)/2
	box := tcell.StyleDefault.Foreground(colText).Background(tcell.NewRGBColor(20, 26, 33))
	for y := y0; y < y0+bh; y++ {
		for x := x0; x < x0+bw; x++ {
			s.SetContent(x, y, ' ', nil, box)
		}
	}
	drawText(s, x0+2, y0+1, box.Bold(true), truncate("Quarantine "+a.Subject.Display()+"?", bw-4))
	drawText(s, x0+2, y0+3, box.Foreground(colAccent), "↺ reversible — moves, never deletes; undo with restore")
	drawText(s, x0+2, y0+5, box.Foreground(colQuarantine), "[Enter] Quarantine")
	drawText(s, x0+24, y0+5, box.Foreground(colDim), "[Esc] Cancel")
}

func truncate(s string, n int) string {
	if n < 0 {
		n = 0
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
```

- [ ] **Step 4: Run tests, verify pass; commit**

Run: `go test ./internal/tui/ && go vet ./...`
```bash
git add internal/tui/
git commit -m "feat(tui): view — tcell render, tested via SimulationScreen"
```

---

### Task 6: Actor interface + Run() event loop

**Files:**
- Create: `internal/tui/run.go`, `internal/tui/run_test.go`

**Interfaces:**
- Produces: `type Actor interface { Quarantine(a model.Assessment) (string, error); Restore(manifest string) error }`; `func Run(s tcell.Screen, m Model, actor Actor) error`.
- Consumes: `update`, `view`, `Cmd`.

- [ ] **Step 1: Write the failing test**

`internal/tui/run_test.go`:
```go
package tui

import (
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"counterspy/internal/model"
)

type fakeActor struct {
	quarantined []string
	restored    int
}

func (f *fakeActor) Quarantine(a model.Assessment) (string, error) {
	f.quarantined = append(f.quarantined, a.Subject.Label)
	return "/tmp/manifest.json", nil
}
func (f *fakeActor) Restore(string) error { f.restored++; return nil }

func TestRun_QuarantineFlow(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	fa := &fakeActor{}
	m := New([]model.Assessment{mk("evil", model.RecQuarantine, 14)}, nil)

	done := make(chan error, 1)
	go func() { done <- Run(s, m, fa) }()

	// q → Enter (confirm quarantine) → Q (quit)
	time.Sleep(20 * time.Millisecond)
	s.InjectKey(tcell.KeyRune, 'q', tcell.ModNone)
	time.Sleep(10 * time.Millisecond)
	s.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
	time.Sleep(10 * time.Millisecond)
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit on quit")
	}
	if len(fa.quarantined) != 1 || fa.quarantined[0] != "evil" {
		t.Fatalf("quarantine not called for 'evil': %v", fa.quarantined)
	}
}
```

- [ ] **Step 2: Run, verify fail**

Run: `go test ./internal/tui/ -run Run`
Expected: FAIL — `undefined: Run`.

- [ ] **Step 3: Write `internal/tui/run.go`**

```go
package tui

import (
	"github.com/gdamore/tcell/v2"
	"counterspy/internal/model"
)

// Actor performs the mutating effects (satisfied by internal/act via a main adapter).
type Actor interface {
	Quarantine(a model.Assessment) (string, error)
	Restore(manifest string) error
}

// Run drives the event loop until quit. The screen is injected so tests can pass a
// SimulationScreen. The caller Inits/Finis the screen.
func Run(s tcell.Screen, m Model, actor Actor) error {
	var lastManifest string
	view(m, s)
	s.Show()
	for {
		ev := s.PollEvent()
		ek, ok := ev.(*tcell.EventKey)
		if !ok {
			view(m, s) // resize/other → just redraw
			s.Show()
			continue
		}
		next, cmds := update(m, ek.Key(), ek.Rune())
		m = next
		for _, c := range cmds {
			switch c.Op {
			case "quit":
				return nil
			case "quarantine":
				mp, err := actor.Quarantine(c.A)
				if err != nil {
					m.Toast = "stopped — partial state recorded: " + err.Error()
				} else {
					m.Done[c.A.Subject.Key()] = true
					lastManifest = mp
					m.Toast = "quarantined " + c.A.Subject.Display()
				}
			case "restore":
				if lastManifest == "" {
					m.Toast = "nothing quarantined this session"
					break
				}
				if err := actor.Restore(lastManifest); err != nil {
					m.Toast = "restore issue: " + err.Error()
				} else {
					m.Done = map[string]bool{}
					m.Toast = "restored (reloads at next login)"
				}
			}
		}
		view(m, s)
		s.Show()
	}
}
```

- [ ] **Step 4: Run tests, verify pass; commit**

Run: `go test ./internal/tui/ && go vet ./...`
```bash
git add internal/tui/
git commit -m "feat(tui): Actor interface + Run event loop"
```

---

### Task 7: `counterspy tui` subcommand — snapshot/live + no-TTY guard + adapter

**Files:**
- Modify: `main.go`
- Create: `testdata/tui_snapshot.json`, `main_test.go` additions

**Interfaces:**
- Consumes: `tui.New`, `tui.Run`, `tui.Actor`; existing `collectAll`, `score.Score`, `interpret.Assess`, `filterAllowed`, `plannedActions`, `act.Quarantine`, `act.Restore`.
- Produces: a `cliActor` (in `main`) implementing `tui.Actor`; a `loadSnapshot(path string) ([]model.Assessment, error)`.

- [ ] **Step 1: Write the failing test**

Add to `main_test.go`:
```go
func TestLoadSnapshot(t *testing.T) {
	as, err := loadSnapshot("testdata/tui_snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Subject.Label != "com.evil.updater" {
		t.Fatalf("snapshot decode wrong: %+v", as)
	}
}

func TestCliActor_Quarantine(t *testing.T) {
	tmp := t.TempDir()
	orig := filepath.Join(tmp, "beacon")
	os.WriteFile(orig, []byte("x"), 0o644)
	a := model.Assessment{Finding: model.Finding{Subject: model.Subject{Path: orig, Label: "com.evil"},
		Evidence: []model.Evidence{{Kind: model.KindPersistence, Facts: map[string]string{"plist": orig}}}}}
	ca := &cliActor{root: filepath.Join(tmp, "q"), ts: "t"}
	// resolve symlinks so the actor's canonical check passes on macOS temp dirs
	real, _ := filepath.EvalSymlinks(orig)
	a.Subject.Path = real
	a.Evidence[0].Facts["plist"] = real
	if _, err := ca.Quarantine(a); err != nil {
		t.Fatalf("cliActor.Quarantine: %v", err)
	}
	if _, err := os.Stat(real); !os.IsNotExist(err) {
		t.Fatal("file should have moved to quarantine")
	}
}
```

- [ ] **Step 2: Create the fixture** `testdata/tui_snapshot.json`:
```json
[
  {
    "Subject": {"Path": "/Users/me/Library/.hidden/beacon", "PID": 0, "Label": "com.evil.updater"},
    "Score": 14, "Tripwire": "unsigned binary with persistence and a live network listener",
    "Kinds": ["persistence", "codesign", "process"],
    "Evidence": [
      {"Subject": {"Label": "com.evil.updater"}, "Kind": "persistence", "Summary": "user-level LaunchAgent", "Weight": 1, "Facts": {"plist": "/Users/me/Library/LaunchAgents/com.evil.updater.plist"}},
      {"Subject": {"Label": "com.evil.updater"}, "Kind": "codesign", "Summary": "binary is unsigned", "Weight": 3, "Facts": {"signed": "false"}}
    ],
    "Verdict": "com.evil.updater is an unsigned binary, installed for persistence, and listening for inbound connections.",
    "Category": "backdoor", "Recommendation": "Quarantine"
  }
]
```

- [ ] **Step 3: Run, verify fail**

Run: `go test . -run 'Snapshot|CliActor'`
Expected: FAIL — `undefined: loadSnapshot`.

- [ ] **Step 4: Add the subcommand + adapter to `main.go`**

Add `"tui"` to the `run` switch, and these functions:
```go
// in run()'s switch:
	case "tui":
		return runTUI(args[1:], stdout)
```

```go
func runTUI(flags []string, stdout io.Writer) int {
	from := flagValue(flags, "--from")
	var assessments []model.Assessment
	var gaps []string
	if from != "" {
		as, err := loadSnapshot(from)
		if err != nil {
			fmt.Fprintln(stdout, "tui: cannot read snapshot:", err)
			return 1
		}
		assessments = as
	} else {
		ev, g := collectAll()
		assessments = filterAllowed(interpret.Assess(score.Score(ev)), userAllowlist())
		gaps = g
	}

	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stdout, "TUI needs a terminal — use `counterspy scan` (or `--json`).")
		return 2
	}
	screen, err := tcell.NewScreen()
	if err != nil {
		fmt.Fprintln(stdout, "tui: cannot open screen:", err)
		return 1
	}
	if err := screen.Init(); err != nil {
		fmt.Fprintln(stdout, "tui: cannot init screen:", err)
		return 1
	}
	defer screen.Fini() // ALWAYS restore the terminal

	home, _ := os.UserHomeDir()
	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	actor := &cliActor{root: filepath.Join(home, "CounterSpyQuarantine", ts), ts: ts}
	if err := tui.Run(screen, tui.New(assessments, gaps), actor); err != nil {
		screen.Fini()
		fmt.Fprintln(stdout, "tui:", err)
		return 1
	}
	return 0
}

func loadSnapshot(path string) ([]model.Assessment, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var as []model.Assessment
	return as, json.Unmarshal(b, &as)
}

// cliActor adapts internal/act to the tui.Actor interface, capturing the run root+ts.
type cliActor struct {
	root, ts string
}

func (c *cliActor) Quarantine(a model.Assessment) (string, error) {
	a.Actions = plannedActions(a.Finding)
	if _, err := act.Quarantine(c.root, c.ts, a); err != nil {
		return "", err
	}
	return filepath.Join(c.root, "manifest.json"), nil
}
func (c *cliActor) Restore(manifest string) error { return act.Restore(manifest) }

func flagValue(flags []string, name string) string {
	for i, f := range flags {
		if f == name && i+1 < len(flags) {
			return flags[i+1]
		}
		if strings.HasPrefix(f, name+"=") {
			return strings.TrimPrefix(f, name+"=")
		}
	}
	return ""
}
```
Add imports to `main.go`: `"encoding/json"`, `"github.com/gdamore/tcell/v2"`, `"counterspy/internal/tui"` (plus existing `time`, `io`, `filepath`, `strings`).

- [ ] **Step 5: Run tests + vet + build; smoke**

Run: `go test ./... && go vet ./... && go build -o /tmp/counterspy .`
Then confirm the fixture renders (in a real terminal): `/tmp/counterspy tui --from testdata/tui_snapshot.json` (press `q`, `Enter`... actually `Q` to quit). Non-TTY: `/tmp/counterspy tui --from testdata/tui_snapshot.json | cat` prints the "TUI needs a terminal" guidance.

- [ ] **Step 6: Commit**

```bash
git add main.go main_test.go testdata/tui_snapshot.json go.mod go.sum
git commit -m "feat(tui): counterspy tui subcommand — snapshot/live, no-TTY guard, act adapter"
```

---

### Task 8: Help overlay + README/architext update

**Files:**
- Modify: `internal/tui/update.go` (`?` toggles help), `internal/tui/view.go` (help overlay), `README.md`, `docs/architext/data/*` (add the tui node + subcommand)

**Interfaces:** none new.

- [ ] **Step 1: Write the failing test**

Append to `internal/tui/update_test.go`:
```go
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
```

- [ ] **Step 2: Run, verify fail; then implement**

Add a help branch at the top of `update` (after the modal branch):
```go
	if m.Focus == focusHelp {
		if key == tcell.KeyEsc || (key == tcell.KeyRune && r == '?') {
			m.Focus = focusList
		}
		return m, nil
	}
```
And add `case '?': m.Focus = focusHelp` to the rune switch. In `view.go`, add a
`drawHelp` function and call it from `view` when `m.Focus == focusHelp` (after the modal
check):
```go
// in view(): replace the modal block's tail with both overlays
	if m.Focus == focusModal {
		drawModal(s, m.Pending)
	}
	if m.Focus == focusHelp {
		drawHelp(s)
	}

func drawHelp(s tcell.Screen) {
	rows := []string{
		"Keys",
		"",
		"j / k, ↑/↓   move selection",
		"q            quarantine (confirm)",
		"u            restore this session's quarantine",
		"m            show / hide Monitor tier",
		"s            sort by score / recommendation",
		"/            filter by name   ·   esc clears",
		"?            toggle this help",
		"Q, Ctrl-C    quit",
	}
	w, h := s.Size()
	bw, bh := 52, len(rows)+2
	x0, y0 := (w-bw)/2, (h-bh)/2
	box := tcell.StyleDefault.Foreground(colText).Background(tcell.NewRGBColor(20, 26, 33))
	for y := y0; y < y0+bh; y++ {
		for x := x0; x < x0+bw; x++ {
			s.SetContent(x, y, ' ', nil, box)
		}
	}
	for i, r := range rows {
		st := box
		if i == 0 {
			st = box.Foreground(colAccent).Bold(true)
		}
		drawText(s, x0+2, y0+1+i, st, truncate(r, bw-4))
	}
}
```

- [ ] **Step 3: Run tests; update docs**

Run: `go test ./...`
- README: add `counterspy tui [--from <json|->]` to the Use section and a one-line description.
- architext: add a `mod-tui` node (type module, sourcePaths internal/tui/*, depends mod-model + mod-act, relatedFlows scan-pipeline+quarantine) and a `counterspy tui` interface on `counterspy-cli`; run `architext validate`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(tui): help overlay + docs (README, architext)"
```

---

## Post-plan verification (before tagging)

Run the full gate and a real snapshot render:
```bash
go test ./... && go vet ./... && gofmt -l . && architext validate
go build -o /tmp/counterspy .
sudo /tmp/counterspy scan --json > /tmp/s.json   # produce a real snapshot
/tmp/counterspy tui --from /tmp/s.json            # drive it in a real terminal
```
Then the swarm's confirming pass (like the CLI): fan out reviewers on the tui diff, then a
targeted re-check that `internal/tui` imports no `score`/`collect`/`interpret` (the §12
invariant) and that `screen.Fini()` always runs (terminal never left corrupted).
