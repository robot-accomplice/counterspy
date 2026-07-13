# Egress Group Zoom Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `z` "zoom" action to the Exfiltration view that opens a full-screen, btm-style dashboard for one app group: a braille throughput graph over its PIDs, a selectable PID table (rates, total, %-of-group share) you can inspect from, plus destinations and group-meta panels.

**Architecture:** A new modal state `EgressModel.Zoom` (pure, like `Inspection`), rendered by a new `internal/tui/egresszoom.go`, driven by a new pure braille line-graph primitive `internal/tui/braillegraph.go`. All rendering stays in `internal/tui` (imports only `model` + `mark`); the one non-tui change is widening the per-PID history ring in `internal/egress`. Inspect stacks on top of zoom via the existing `InspectReq` → `Inspection` flow.

**Tech Stack:** Go, tcell v2 (SimulationScreen for tests), braille Unicode (U+2800 block).

## Global Constraints

- `internal/tui` imports ONLY `internal/model` and `internal/mark` (enforced by `TestDecouplingInvariant`). The zoom must not add other cross-package imports.
- No new external dependencies. No new data collector (network-only; CPU%/Mem% deferred per spec §11).
- Modal precedence in `egressUpdate`: `Inspection` (if open) → else `Zoom` (if open) → else tree.
- Reuse existing helpers: `drawHRule`, `drawText`, `truncate`, `human`, `busiestConn`, `middleEllipsis`, `detailLines`, `trendMode`/`trendGlyph`/`trendWord`, the `col*` palette.
- Match the source's style: small pure functions, table-driven tests, comments that state WHY (Rule 10).

---

### Task 1: Widen the per-PID history ring (graph depth)

**Files:**
- Modify: `internal/egress/monitor.go:14` (`sparkLen`)
- Test: `internal/egress/monitor_test.go` (existing ring tests still pass)

**Interfaces:**
- Consumes: nothing new.
- Produces: no API change — `Spark`/`InSpark` slices simply retain more samples.

- [ ] **Step 1: Widen the constant**

`sparkLen` is currently `24` (≈48s at the 2s cadence). The zoom graph wants ~60s of width; a 2× braille canvas over ~50 cols wants ~100 sub-columns, so keep more history and let downsampling handle wide terminals.

```go
const sparkLen = 60 // recent rate samples kept per ring (~2min at the 2s cadence) — wide enough
// for the zoom graph; the tree's small sparklines downsample this to their column width.
```

- [ ] **Step 2: Run the egress suite**

Run: `go test ./internal/egress/ -race`
Expected: PASS (existing ring/prune tests are length-agnostic; if any hard-codes 24, update it to `sparkLen`).

- [ ] **Step 3: Commit**

```bash
git add internal/egress/monitor.go internal/egress/monitor_test.go
git commit -m "feat(egress): widen the rate-history ring for the zoom graph"
```

---

### Task 2: Braille line-graph renderer (pure)

**Files:**
- Create: `internal/tui/braillegraph.go`
- Test: `internal/tui/braillegraph_test.go`

**Interfaces:**
- Produces:
  - `type graphSeries struct { values []uint64; color tcell.Color; emphasized bool }`
  - `type graphCell struct { r rune; color tcell.Color }`
  - `func plotSeries(series []graphSeries, cols, rows int, maxY uint64) [][]graphCell` — returns a `rows`×`cols` grid; empty cells are `graphCell{r: ' '}`. `maxY == 0` means auto-scale to the max value across all series. Newest sample is right-aligned. Emphasized series are plotted last so they win a shared cell's color.

- [ ] **Step 1: Write the failing test**

```go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
)

func gridHasBraille(grid [][]graphCell) bool {
	for _, rowCells := range grid {
		for _, c := range rowCells {
			if c.r >= 0x2800 && c.r <= 0x28FF && c.r != 0x2800 {
				return true
			}
		}
	}
	return false
}

func TestPlotSeries_RisingLineClimbs(t *testing.T) {
	// A monotonically rising series must light higher (nearer the top row) on the right than the left.
	vals := []uint64{0, 1, 2, 3, 4, 5, 6, 7}
	grid := plotSeries([]graphSeries{{values: vals, color: tcell.ColorRed}}, 4, 3, 0)
	if len(grid) != 3 || len(grid[0]) != 4 {
		t.Fatalf("grid must be rows×cols = 3×4, got %dx%d", len(grid), len(grid[0]))
	}
	if !gridHasBraille(grid) {
		t.Fatal("a non-empty series must light braille dots")
	}
	topLit := func(col int) int { // topmost row index with a lit cell in this column, or len if none
		for r := 0; r < len(grid); r++ {
			if grid[r][col].r != ' ' && grid[r][col].r != 0x2800 {
				return r
			}
		}
		return len(grid)
	}
	if topLit(3) > topLit(0) {
		t.Fatalf("rising series must reach higher on the right: left top=%d right top=%d", topLit(0), topLit(3))
	}
}

func TestPlotSeries_EmphasizedWinsColor(t *testing.T) {
	// Two flat series at the same level share cells; the emphasized one is drawn last and wins.
	flat := []uint64{5, 5, 5, 5}
	grid := plotSeries([]graphSeries{
		{values: flat, color: tcell.ColorGray},
		{values: flat, color: tcell.ColorRed, emphasized: true},
	}, 2, 2, 10)
	sawRed := false
	for _, rowCells := range grid {
		for _, c := range rowCells {
			if c.r != ' ' && c.r != 0x2800 && c.color == tcell.ColorRed {
				sawRed = true
			}
		}
	}
	if !sawRed {
		t.Fatal("emphasized series must win the shared cell color")
	}
}

func TestPlotSeries_EmptyIsBlankNoPanic(t *testing.T) {
	grid := plotSeries(nil, 3, 2, 0)
	if len(grid) != 2 || len(grid[0]) != 3 {
		t.Fatalf("empty input must still return a 2×3 grid, got %dx%d", len(grid), len(grid[0]))
	}
	if gridHasBraille(grid) {
		t.Fatal("no series → no lit dots")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tui/ -run TestPlotSeries`
Expected: FAIL (`plotSeries` undefined).

- [ ] **Step 3: Implement the renderer**

```go
package tui

import "github.com/gdamore/tcell/v2"

// A braille cell is a 2×4 dot grid; dot bit values (U+2800 base). brailleBit[col][row] is the bit
// for the sub-pixel at (col∈{0,1}, row∈{0,1,2,3}).
var brailleBit = [2][4]byte{
	{0x01, 0x02, 0x04, 0x40}, // left column, top→bottom
	{0x08, 0x10, 0x20, 0x80}, // right column, top→bottom
}

type graphSeries struct {
	values     []uint64
	color      tcell.Color
	emphasized bool
}

type graphCell struct {
	r     rune
	color tcell.Color
}

// plotSeries rasterizes each series as a braille line into a rows×cols grid sharing one Y-axis
// scaled to maxY (0 = auto = the max across all series). Sub-resolution is 2×cols wide, 4×rows tall.
// The newest sample is right-aligned; where a value has no sample (short history) the column is
// blank. Non-emphasized series are plotted first so an emphasized (selected) line wins on overlap.
func plotSeries(series []graphSeries, cols, rows int, maxY uint64) [][]graphCell {
	subCols, subRows := cols*2, rows*4
	bits := make([][]byte, rows)      // accumulated dot bits per cell
	colr := make([][]tcell.Color, rows)
	for r := range bits {
		bits[r] = make([]byte, cols)
		colr[r] = make([]tcell.Color, cols)
	}

	if maxY == 0 {
		for _, s := range series {
			for _, v := range s.values {
				if v > maxY {
					maxY = v
				}
			}
		}
	}

	// emphasized last so it overwrites shared-cell color
	ordered := make([]graphSeries, 0, len(series))
	for _, s := range series {
		if !s.emphasized {
			ordered = append(ordered, s)
		}
	}
	for _, s := range series {
		if s.emphasized {
			ordered = append(ordered, s)
		}
	}

	// height in sub-rows for a value (0..subRows), measured from the bottom.
	height := func(v uint64) int {
		if maxY == 0 {
			return 0
		}
		h := int(v * uint64(subRows-1) / maxY)
		if h > subRows-1 {
			h = subRows - 1
		}
		return h
	}
	set := func(sx, sy int, c tcell.Color) { // light sub-pixel (sx,sy), sy measured from TOP
		cellRow, cellCol := sy/4, sx/2
		bits[cellRow][cellCol] |= brailleBit[sx%2][sy%4]
		colr[cellRow][cellCol] = c
	}

	for _, s := range ordered {
		n := len(s.values)
		if n == 0 {
			continue
		}
		vals := s.values
		if n > subCols { // more samples than sub-columns: average down to fit
			vals = downsample(vals, subCols)
			n = len(vals)
		}
		prev := -1
		for i := 0; i < n; i++ {
			sx := subCols - n + i // right-align newest
			if sx < 0 {
				continue
			}
			h := height(vals[i])
			syTop := subRows - 1 - h
			set(sx, syTop, s.color)
			// vertical fill toward the previous point so the line is continuous, not dotty
			if prev >= 0 {
				lo, hi := prev, h
				if lo > hi {
					lo, hi = hi, lo
				}
				for hh := lo; hh <= hi; hh++ {
					set(sx, subRows-1-hh, s.color)
				}
			}
			prev = h
		}
	}

	grid := make([][]graphCell, rows)
	for r := 0; r < rows; r++ {
		grid[r] = make([]graphCell, cols)
		for c := 0; c < cols; c++ {
			if b := bits[r][c]; b != 0 {
				grid[r][c] = graphCell{r: rune(0x2800 + int(b)), color: colr[r][c]}
			} else {
				grid[r][c] = graphCell{r: ' '}
			}
		}
	}
	return grid
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/tui/ -run TestPlotSeries`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tui/braillegraph.go internal/tui/braillegraph_test.go
git commit -m "feat(tui): braille line-graph renderer for the zoom dashboard"
```

---

### Task 3: Zoom state + pure transitions

**Files:**
- Modify: `internal/tui/egressmodel.go` (state, `egressUpdate` precedence, `z` key, share helper)
- Modify: `internal/tui/egressview.go:38` (`footerHint` gains `z zoom`)
- Test: `internal/tui/egresszoom_test.go` (new)

**Interfaces:**
- Consumes: `busiestConn`, `inspectTarget`, `trendMode`, `model.EgressGroup`/`EgressInstance`.
- Produces:
  - `type zoomState struct { app string; sel int; mode trendMode }`
  - field `Zoom *zoomState` on `EgressModel`
  - `func (m EgressModel) zoomGroup() (model.EgressGroup, bool)` — the current zoomed group by name.
  - `func zoomedMembers(g model.EgressGroup) []model.EgressInstance` — members sorted by OutRate desc, stable by PID.
  - `func pidShare(memberOut, groupOut uint64) int` — 0..100, 0 when groupOut==0.

- [ ] **Step 1: Write the failing transition tests**

```go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func zoomGroupFixture() model.EgressGroup {
	return model.EgressGroup{App: "claude", Trust: "notarized", Instances: 2,
		Members: []model.EgressInstance{
			{PID: 1802, Path: "/A/Claude Helper (GPU)", Trust: "notarized", OutRate: 1400, InRate: 120,
				Conns: []model.Conn{{PID: 1802, Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp", OutRate: 1400}}},
			{PID: 1990, Path: "/A/Claude Helper", Trust: "notarized", OutRate: 100, InRate: 2,
				Conns: []model.Conn{{PID: 1990, Endpoint: model.Endpoint{IP: "5.6.7.8", Port: 443}, Proto: "tcp", OutRate: 100}}},
		}}
}

func TestZoom_EnterSelectInspectExit(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m.Selected = 0 // app header row

	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	if m.Zoom == nil || m.Zoom.app != "claude" {
		t.Fatal("z must open the zoom for the selected row's group")
	}
	// down selects the second PID
	m, _ = egressUpdate(m, tcell.KeyDown, 0)
	if m.Zoom.sel != 1 {
		t.Fatalf("down should move PID selection to 1, got %d", m.Zoom.sel)
	}
	// t cycles the graph metric
	m, _ = egressUpdate(m, tcell.KeyRune, 't')
	if m.Zoom.mode != trendIn {
		t.Fatalf("t should cycle the metric to trendIn, got %v", m.Zoom.mode)
	}
	// i inspects the SELECTED pid's busiest conn
	m, _ = egressUpdate(m, tcell.KeyRune, 'i')
	if m.InspectReq == nil || m.InspectReq.pid != 1990 {
		t.Fatalf("i must request inspect for the selected PID 1990, got %+v", m.InspectReq)
	}
	// z / esc exits back to the tree
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	if m.Zoom != nil {
		t.Fatal("z must close the zoom")
	}
}

func TestZoom_SelectionClamps(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m, _ = egressUpdate(m, tcell.KeyRune, 'z')
	m, _ = egressUpdate(m, tcell.KeyUp, 0) // already at 0
	if m.Zoom.sel != 0 {
		t.Fatalf("up at top clamps to 0, got %d", m.Zoom.sel)
	}
	for i := 0; i < 5; i++ {
		m, _ = egressUpdate(m, tcell.KeyDown, 0)
	}
	if m.Zoom.sel != 1 {
		t.Fatalf("down past the end clamps to last PID (1), got %d", m.Zoom.sel)
	}
}

func TestPidShare(t *testing.T) {
	if got := pidShare(1400, 1500); got != 93 {
		t.Fatalf("share 1400/1500 = %d, want 93", got)
	}
	if got := pidShare(5, 0); got != 0 {
		t.Fatalf("divide-by-zero group rate must be 0%%, got %d", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tui/ -run 'TestZoom|TestPidShare'`
Expected: FAIL (`Zoom`, `zoomState`, `pidShare` undefined).

- [ ] **Step 3: Add state + helpers**

In `internal/tui/egressmodel.go`, add the field to `EgressModel` (near `Inspection`):

```go
	Zoom *zoomState // group-zoom dashboard is open (nil = closed); rendered under any Inspection
```

Add the type + helpers (near the other egress helpers):

```go
// zoomState is the open group-zoom dashboard: the group (re-resolved by name each frame so live
// samples flow in), the selected PID index within the sorted members, and the graph metric mode.
type zoomState struct {
	app  string
	sel  int
	mode trendMode
}

// zoomedMembers returns a group's members sorted by out-rate desc (loud talkers first), stable by
// PID — the order the PID panel and the graph's colored lines share.
func zoomedMembers(g model.EgressGroup) []model.EgressInstance {
	ms := append([]model.EgressInstance(nil), g.Members...)
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].OutRate != ms[j].OutRate {
			return ms[i].OutRate > ms[j].OutRate
		}
		return ms[i].PID < ms[j].PID
	})
	return ms
}

// zoomGroup resolves the currently-zoomed group by name from the live groups. ok=false if it has
// vanished between ticks (the caller then closes the zoom).
func (m EgressModel) zoomGroup() (model.EgressGroup, bool) {
	if m.Zoom == nil {
		return model.EgressGroup{}, false
	}
	for _, g := range m.orderedGroups() {
		if g.App == m.Zoom.app {
			return g, true
		}
	}
	return model.EgressGroup{}, false
}

// pidShare is a member's percentage of the group's total out-rate (0..100), 0 when the group is idle.
func pidShare(memberOut, groupOut uint64) int {
	if groupOut == 0 {
		return 0
	}
	return int(memberOut * 100 / groupOut)
}
```

Ensure `sort` is imported in `egressmodel.go` (it already is if `orderedGroups` sorts; add if missing).

- [ ] **Step 4: Wire the transitions with correct precedence**

In `egressUpdate`, immediately AFTER the `if m.Inspection != nil { ... }` modal block and BEFORE `m.Status = ""`, add the zoom modal block:

```go
	// The zoom dashboard is modal under any inspection: it owns keys until dismissed. `i` here
	// requests inspection for the SELECTED pid (which then stacks on top).
	if m.Zoom != nil {
		g, ok := m.zoomGroup()
		if !ok { // the group vanished between ticks — fall back to the tree
			m.Zoom = nil
			return m, false
		}
		members := zoomedMembers(g)
		switch {
		case key == tcell.KeyEscape, r == 'z':
			m.Zoom = nil
		case key == tcell.KeyUp, r == 'k':
			m.Zoom = m.Zoom.withSel(clamp(m.Zoom.sel-1, len(members)))
		case key == tcell.KeyDown, r == 'j':
			m.Zoom = m.Zoom.withSel(clamp(m.Zoom.sel+1, len(members)))
		case r == 't':
			m.Zoom = m.Zoom.withMode((m.Zoom.mode + 1) % 3)
		case r == 'i':
			if m.Zoom.sel < len(members) {
				mem := members[m.Zoom.sel]
				if c := busiestConn(mem.Conns); c != nil {
					m.InspectReq = &inspectTarget{app: g.App, pid: mem.PID, trust: mem.Trust, conn: *c}
				}
			}
		case r == 'Q':
			return m, true
		}
		return m, false
	}
```

Add the small immutable setters (zoomState is behind a pointer, so copy-on-write keeps the update pure):

```go
func (z *zoomState) withSel(sel int) *zoomState  { c := *z; c.sel = sel; return &c }
func (z *zoomState) withMode(m trendMode) *zoomState { c := *z; c.mode = m; return &c }
```

Note: `clamp(x, n)` returns a value in `[0, n-1]` (existing helper — verify its semantics; it's used for `m.Selected`). If `clamp` allows `n` as an exclusive bound already, the calls above are correct.

Add the `z` entry from the tree. In the tree key switch (the `default`/rune area near the `i` inspect handler), add:

```go
		case r == 'z':
			if tgt, _ := resolveInspectTarget(rows, m.Selected); tgt != nil || m.Selected >= 0 {
				if m.Selected >= 0 && m.Selected < len(rows) {
					m.Zoom = &zoomState{app: rows[m.Selected].group.App, sel: 0, mode: m.Trend}
				}
			}
```

Simplify to the essential (any row resolves to its group):

```go
		case r == 'z':
			if m.Selected >= 0 && m.Selected < len(rows) {
				m.Zoom = &zoomState{app: rows[m.Selected].group.App, sel: 0, mode: m.Trend}
			}
```

- [ ] **Step 5: Add the footer hint**

`internal/tui/egressview.go:38` — add `z zoom` to `footerHint`:

```go
const footerHint = "j/k move · ↵/→ expand · ← collapse · z zoom · y copy · i inspect · t trend · s sort · / filter · p pause · Q quit"
```

- [ ] **Step 6: Run to verify pass**

Run: `go test ./internal/tui/ -run 'TestZoom|TestPidShare'`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/tui/egressmodel.go internal/tui/egressview.go internal/tui/egresszoom_test.go
git commit -m "feat(tui): zoom state + pure transitions (enter/select/inspect/exit)"
```

---

### Task 4: Zoom dashboard render (four panels)

**Files:**
- Create: `internal/tui/egresszoom.go`
- Test: `internal/tui/egresszoom_test.go` (append render smoke tests)

**Interfaces:**
- Consumes: `plotSeries`, `graphSeries`, `zoomedMembers`, `pidShare`, `drawText`, `truncate`, `human`, `middleEllipsis`, `detailLines`, `trendGlyph`/`trendWord`, `mark.TrustLabel`, the `col*` palette.
- Produces:
  - `func drawEgressZoom(s tcell.Screen, m EgressModel)` — full-screen render of `m.Zoom`'s group.
  - `func drawBox(s tcell.Screen, x, y, w, h int, title string)` — a single-line box with a title in the top border (panel-divider color).
  - `func seriesValues(mem model.EgressInstance, mode trendMode) []uint64` — the PID's samples for the active metric (out / in / out+in).
  - `func pidLineColor(i int) tcell.Color` — a stable per-index line color, matched between graph and table.

- [ ] **Step 1: Write the failing render smoke test**

```go
func TestDrawEgressZoom_RendersPanelsAndSelection(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	g := zoomGroupFixture()
	g.Members[0].Spark = []uint64{100, 400, 800, 1200, 1400}
	g.Members[0].InSpark = []uint64{10, 40, 80, 100, 120}
	m := NewEgress().withGroups([]model.EgressGroup{g})
	m.Zoom = &zoomState{app: "claude", sel: 0, mode: trendOut}
	drawEgressZoom(s, m)
	s.Show()
	out := screenTextEgress(s) // reuse the egress test's screen-dump helper (or simContains)
	for _, want := range []string{"claude", "PIDs", "destinations", "1802", "1990", "%GRP"} {
		if !simContains(s, want) {
			t.Fatalf("zoom must render %q\n%s", want, out)
		}
	}
}

func TestDrawEgressZoom_TinyTerminalNoPanic(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(40, 10)
	m := NewEgress().withGroups([]model.EgressGroup{zoomGroupFixture()})
	m.Zoom = &zoomState{app: "claude", sel: 0, mode: trendOut}
	drawEgressZoom(s, m) // must not panic
	s.Show()
}
```

(If `screenTextEgress` doesn't exist, drop the `out` dump and rely on `simContains` — already used across the tui tests.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tui/ -run TestDrawEgressZoom`
Expected: FAIL (`drawEgressZoom` undefined).

- [ ] **Step 3: Implement the render**

Create `internal/tui/egresszoom.go`. The layout: top row split into the graph panel (left, ~62%) and the PIDs panel (right); bottom row split into destinations (left) and this-group+hints (right). Every panel is boxed with `drawBox`; content is drawn inside the border. Guard tiny terminals by bailing to a single "terminal too small" line (mirror `egressView`).

```go
// internal/tui/egresszoom.go
package tui

import (
	"fmt"
	"sort"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/mark"
	"counterspy/internal/model"
)

// pidPalette is the stable set of per-PID line colors, matched between the graph and the PID table.
var pidPalette = []tcell.Color{colInvestigate, colAccent, colQuarantine, colMonitor, colWarn, colText}

func pidLineColor(i int) tcell.Color { return pidPalette[i%len(pidPalette)] }

// seriesValues returns a PID's samples for the active metric.
func seriesValues(mem model.EgressInstance, mode trendMode) []uint64 {
	switch mode {
	case trendIn:
		return mem.InSpark
	case trendCombined:
		out, in := mem.Spark, mem.InSpark
		n := len(out)
		if len(in) > n {
			n = len(in)
		}
		sum := make([]uint64, n)
		for i := 0; i < n; i++ {
			var a, b uint64
			if i < len(out) {
				a = out[len(out)-n+i]
			}
			if i < len(in) {
				b = in[len(in)-n+i]
			}
			sum[i] = a + b
		}
		return sum
	default:
		return mem.Spark
	}
}

// drawBox draws a single-line box [x,x+w)×[y,y+h) with a title in the top border (divider color).
func drawBox(s tcell.Screen, x, y, w, h int, title string) {
	if w < 2 || h < 2 {
		return
	}
	st := tcell.StyleDefault.Foreground(colDivider)
	for i := 1; i < w-1; i++ {
		s.SetContent(x+i, y, '─', nil, st)
		s.SetContent(x+i, y+h-1, '─', nil, st)
	}
	for j := 1; j < h-1; j++ {
		s.SetContent(x, y+j, '│', nil, st)
		s.SetContent(x+w-1, y+j, '│', nil, st)
	}
	s.SetContent(x, y, '┌', nil, st)
	s.SetContent(x+w-1, y, '┐', nil, st)
	s.SetContent(x, y+h-1, '└', nil, st)
	s.SetContent(x+w-1, y+h-1, '┘', nil, st)
	if title != "" {
		drawText(s, x+2, y, tcell.StyleDefault.Foreground(colDim), truncate(" "+title+" ", w-4))
	}
}

// drawEgressZoom renders the full-screen zoom dashboard for m.Zoom's group.
func drawEgressZoom(s tcell.Screen, m EgressModel) {
	s.Clear()
	w, h := s.Size()
	g, ok := m.zoomGroup()
	if !ok || w < 40 || h < 12 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	members := zoomedMembers(g)
	sel := m.Zoom.sel
	if sel >= len(members) {
		sel = len(members) - 1
	}

	topH := (h - 1) / 2
	if topH < 5 {
		topH = 5
	}
	leftW := w * 62 / 100

	drawZoomGraph(s, 0, 0, leftW, topH, g, members, sel, m.Zoom.mode)
	drawZoomPIDs(s, leftW, 0, w-leftW, topH, g, members, sel)
	botY, botH := topH, h-1-topH
	drawZoomDests(s, 0, botY, leftW, botH, g)
	drawZoomMeta(s, leftW, botY, w-leftW, botH, g, m.Selected)
}
```

Add the four panel drawers below. Graph panel: build one `graphSeries` per member (emphasized = the selected one), plot into the box interior, blit, and draw simple Y/X axis labels + a live `↑out ↓in` line:

```go
func drawZoomGraph(s tcell.Screen, x, y, w, h int, g model.EgressGroup, members []model.EgressInstance, sel int, mode trendMode) {
	title := fmt.Sprintf("%s · egress · %d pid(s) · %s", g.App, len(members), trendWord(mode))
	drawBox(s, x, y, w, h, title)
	ix, iy, iw, ih := x+1, y+1, w-2, h-2 // interior
	if iw < 8 || ih < 3 {
		return
	}
	labelW := 6 // room for a "1.4M┤" axis gutter
	plotCols, plotRows := iw-labelW, ih-1 // last interior row = X-axis labels
	if plotCols < 2 || plotRows < 1 {
		return
	}
	var series []graphSeries
	var maxY uint64
	for i, mem := range members {
		vals := seriesValues(mem, mode)
		for _, v := range vals {
			if v > maxY {
				maxY = v
			}
		}
		series = append(series, graphSeries{values: vals, color: pidLineColor(i), emphasized: i == sel})
	}
	grid := plotSeries(series, plotCols, plotRows, maxY)
	for r := 0; r < plotRows; r++ {
		for c := 0; c < plotCols; c++ {
			cell := grid[r][c]
			if cell.r != ' ' {
				s.SetContent(ix+labelW+c, iy+r, cell.r, nil, tcell.StyleDefault.Foreground(cell.color))
			}
		}
	}
	// Y-axis: peak at the top row, 0 at the bottom plot row.
	drawText(s, ix, iy, tcell.StyleDefault.Foreground(colDim), truncate(human(maxY), labelW-1))
	drawText(s, ix, iy+plotRows-1, tcell.StyleDefault.Foreground(colDim), truncate("0", labelW-1))
	// X-axis labels on the last interior row + live totals on the right.
	drawText(s, ix, iy+ih-1, tcell.StyleDefault.Foreground(colDim), "60s")
	totals := fmt.Sprintf("↑%s ↓%s", human(g.OutRate), human(g.InRate))
	drawText(s, ix+iw-len([]rune(totals)), iy+ih-1, tcell.StyleDefault.Foreground(colDim), totals)
}
```

PIDs panel: a table with a color swatch, PID, OUT↑, IN↓, %GRP + share bar, trust glyph, highlighting the selected row:

```go
func drawZoomPIDs(s tcell.Screen, x, y, w, h int, g model.EgressGroup, members []model.EgressInstance, sel int) {
	drawBox(s, x, y, w, h, "PIDs")
	ix, iy, iw := x+2, y+1, w-4
	if iw < 10 {
		return
	}
	drawText(s, ix, iy, tcell.StyleDefault.Foreground(colDim), truncate("   PID    OUT↑    IN↓  %GRP", iw))
	for i, mem := range members {
		row := iy + 1 + i
		if row >= y+h-1 {
			break
		}
		share := pidShare(mem.OutRate, g.OutRate)
		bar := shareBar(share, 4)
		line := fmt.Sprintf("  %5d  %6s  %5s  %s%3d%%", mem.PID, human(mem.OutRate), human(mem.InRate), bar, share)
		st := tcell.StyleDefault.Foreground(colText)
		if i == sel {
			st = st.Background(colSelBg).Bold(true)
			s.SetContent(x+1, row, '▸', nil, tcell.StyleDefault.Foreground(colSelBar))
		}
		drawText(s, ix, row, st, truncate(line, iw))
		// color swatch matching the graph line
		s.SetContent(x+1+0, row, ' ', nil, tcell.StyleDefault) // keep marker column clean when unselected
		drawText(s, ix, row, tcell.StyleDefault.Foreground(pidLineColor(i)), "■")
	}
}

// shareBar renders an n-cell block bar for a 0..100 percentage.
func shareBar(pct, n int) string {
	full := pct * n / 100
	b := make([]rune, n)
	for i := range b {
		if i < full {
			b[i] = '▇'
		} else {
			b[i] = ' '
		}
	}
	return string(b)
}
```

Destinations panel: aggregate `g.Conns` by endpoint, out-rate + share, sorted desc:

```go
func drawZoomDests(s tcell.Screen, x, y, w, h int, g model.EgressGroup) {
	drawBox(s, x, y, w, h, "destinations")
	ix, iy, iw := x+2, y+1, w-4
	type dest struct {
		ep   string
		rate uint64
	}
	agg := map[string]uint64{}
	for _, c := range g.Conns {
		agg[fmt.Sprintf("%s:%d", c.Endpoint.IP, c.Endpoint.Port)] += c.OutRate
	}
	ds := make([]dest, 0, len(agg))
	for ep, r := range agg {
		ds = append(ds, dest{ep, r})
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].rate > ds[j].rate })
	for i, d := range ds {
		row := iy + i
		if row >= y+h-1 {
			break
		}
		share := pidShare(d.rate, g.OutRate)
		drawText(s, ix, row, tcell.StyleDefault.Foreground(colText),
			truncate(fmt.Sprintf("%-24s ↑%6s %3d%%", middleEllipsis(d.ep, 24), human(d.rate), share), iw))
	}
}
```

Meta panel + key hints on the bottom border:

```go
func drawZoomMeta(s tcell.Screen, x, y, w, h int, g model.EgressGroup, treeSel int) {
	drawBox(s, x, y, w, h, "this group")
	ix, iy, iw := x+2, y+1, w-4
	lines := []string{
		fmt.Sprintf("%s · %s · cadence: %s", g.Trust, bgLabel(g.Background), g.Cadence),
	}
	if len(g.Capabilities) > 0 {
		lines = append(lines, model.Clean("can access  "+joinDot(g.Capabilities)))
	}
	for i, ln := range lines {
		row := iy + i
		if row >= y+h-1 {
			break
		}
		drawText(s, ix, row, tcell.StyleDefault.Foreground(colDim), truncate(ln, iw))
	}
	// key hints live on the bottom border (like the tree footer)
	drawText(s, x+2, y+h-1, tcell.StyleDefault.Foreground(colDim),
		truncate(" i inspect · ↑/↓ pid · t out/in · z back ", w-4))
}
```

Add small helpers if not already present: `joinDot(ss []string) string` (join with ` · `) — or reuse the exact idiom from `detailLines` (`strings.Join(x, " · ")`). Use `strings.Join(g.Capabilities, " · ")` directly and import `strings` to avoid a new helper. Confirm `bgLabel` is accessible (it's used by `detailLines` in the same package — yes).

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/tui/ -run TestDrawEgressZoom`
Expected: PASS.

- [ ] **Step 5: gofmt + full tui suite**

Run: `gofmt -w internal/tui/ && go test ./internal/tui/ -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/tui/egresszoom.go internal/tui/egresszoom_test.go
git commit -m "feat(tui): render the btm-style group zoom dashboard (4 panels)"
```

---

### Task 5: Console wiring (draw + key routing)

**Files:**
- Modify: `internal/tui/console.go` (draw switch + Tab guard)
- Test: `internal/tui/console_test.go` or the existing RunConsole e2e test file

**Interfaces:**
- Consumes: `drawEgressZoom`, `em.Zoom`.
- Produces: no new API; the zoom becomes reachable in the running console.

- [ ] **Step 1: Write the failing e2e test**

Mirror `TestRunConsole_InspectEndToEnd`: Tab to Exfiltration, expand nothing, press `z` on the app row, assert the zoom renders (`simContains "PIDs"`), press `i` to inspect (assert the inspector was called / verdict renders), `esc` back to the zoom, `z` back to the tree.

```go
func TestRunConsole_ZoomAndInspect(t *testing.T) {
	s := simInit(t)
	fi := &fakeInspector{view: model.InspectView{Verdict: "plaintext — readable", Coverage: model.InspectPlaintext, Sent: "GET /x"}}
	sampler := fakeSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}
	tick := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- RunConsole(s, New(nil, nil), &fakeActor{}, sampler, fi, tick, nil) }()
	step := func() { time.Sleep(35 * time.Millisecond) }

	s.InjectKey(tcell.KeyTab, 0, tcell.ModNone) // → Exfiltration
	step()
	s.InjectKey(tcell.KeyRune, 'z', tcell.ModNone) // zoom the selected group
	step()
	if !simContains(s, "PIDs") {
		t.Fatal("z should open the zoom dashboard")
	}
	s.InjectKey(tcell.KeyRune, 'i', tcell.ModNone) // inspect the selected pid
	step()
	if fi.calls.Load() == 0 {
		t.Fatal("i in the zoom must trigger a capture")
	}
	s.InjectKey(tcell.KeyEscape, 0, tcell.ModNone) // inspection → back to zoom
	step()
	if !simContains(s, "PIDs") {
		t.Fatal("closing inspect should return to the zoom, not the tree")
	}
	s.InjectKey(tcell.KeyRune, 'z', tcell.ModNone) // zoom → tree
	step()
	if !simContains(s, "Exfiltration") {
		t.Fatal("z should return to the tree")
	}
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunConsole did not exit")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tui/ -run TestRunConsole_ZoomAndInspect`
Expected: FAIL (zoom never drawn — no "PIDs").

- [ ] **Step 3: Wire draw + Tab guard**

In `console.go` `draw()`, add a zoom case BELOW inspection and ABOVE the mode split:

```go
		switch {
		case em.Inspection != nil: // full-screen inspection pane replaces everything
			drawInspect(s, em.Inspection, em.Reveal)
		case em.Zoom != nil: // group-zoom dashboard replaces the tree
			drawEgressZoom(s, em)
		case mode == modeFindings:
			view(m, s)
			drawConsoleTabs(s, mode, m.ReadOnly)
		default:
			egressView(em, s)
			drawConsoleTabs(s, mode, m.ReadOnly)
		}
```

Update the Tab guard so faces don't switch while zoomed (or inspecting):

```go
		if em.Inspection == nil && em.Zoom == nil && (ev.Key() == tcell.KeyTab || ev.Key() == tcell.KeyBacktab) {
```

The `InspectReq` capture block already converts a zoom-issued inspect request into `em.Inspection` — no change needed; when the inspection closes, `em.Zoom` is still set, so `draw()` falls to the zoom case. 

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/tui/ -run TestRunConsole_ZoomAndInspect -race`
Expected: PASS.

- [ ] **Step 5: Full verify + commit**

```bash
gofmt -w internal/tui/
go vet ./... && go test ./... -race
git add internal/tui/console.go internal/tui/*_test.go
git commit -m "feat(tui): wire the zoom dashboard into the console (draw + key routing)"
```

---

### Task 6: Docs — Architext + help

**Files:**
- Modify: `internal/tui/view.go` help rows (add `z` to the egress-side hints if a shared help lists them) — SKIP if the egress view has no separate help screen (it uses the footer only).
- Modify: `docs/architext/data/**` — record the new zoom view/flow if the egress view is represented there.

- [ ] **Step 1: Update Architext if the egress view is modeled**

Run: `grep -ril "egress\|exfil\|inspect" docs/architext/data/` — if the TUI egress view is a documented node/flow, add the zoom as a sub-view/flow (a new `workflow` view or a node note), then:

Run: `architext validate` — Expected: OK. If Architext doesn't model the TUI at this granularity, note that in the commit message and skip.

- [ ] **Step 2: Commit**

```bash
git add docs/
git commit -m "docs: record the egress group zoom dashboard"
```

---

## Notes for the implementer

- **`clamp` semantics:** confirm `clamp(i, n)` returns `[0, n-1]` (it's used for `m.Selected`). The zoom selection reuses it identically.
- **`human`** formats a byte/rate count (e.g. `1.4M`); it already handles the rate values on `OutRate`/`InRate`.
- **Color reuse:** the PID line palette deliberately reuses the existing `col*` values so no new palette constants leak into the model layer; keep it in `egresszoom.go` (view layer).
- **Live data:** the zoom re-resolves its group by name every frame (`zoomGroup`), so `EventInterrupt` sample refreshes flow straight into the graph and rates while zoomed — no extra plumbing.
- **Decoupling:** run `go test ./internal/tui/ -run TestDecouplingInvariant` after Task 4; `egresszoom.go` must import only `model` + `mark` + tcell/stdlib.

## Self-review notes

- Spec §4 panels → Tasks 4 (all four). Spec §5 braille graph → Task 2. Spec §6 history → Task 1 + share math in Task 3. Spec §7 state/decoupling → Task 3 + Task 4 note. Spec §8 degradation → Task 4 tiny-terminal test + `zoomGroup` vanish guard in Task 3. Spec §9 tests → each task's TDD steps. Spec §10 interaction → Task 3. Spec §11 deferrals → unchanged (not built).
- Types are consistent across tasks: `zoomState{app,sel,mode}`, `graphSeries{values,color,emphasized}`, `graphCell{r,color}`, `pidShare`, `zoomedMembers`, `seriesValues`, `drawEgressZoom`.
