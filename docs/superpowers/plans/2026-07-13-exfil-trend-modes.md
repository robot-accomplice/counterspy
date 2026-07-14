# Exfil Trend Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `t` toggle on the Exfiltration `TREND` column cycling out-only / in-only / combined, with share-of-peak temperature coloring and green→amber direction coloring, plus a contextual legend.

**Architecture:** Add a parallel in-rate history ring at each level the monitor already tracks out-rate (app/PID/conn), thread `InRate`/`InSpark` through `Instance`→`Aggregate`→`model`, then rework the TUI sparkline: a session `trendMode` on `EgressModel` picks which series to plot and which color axis to use; a per-frame peak drives relative temperature.

**Tech Stack:** Go 1.26, `github.com/gdamore/tcell/v2`, existing `internal/egress` (nettop/lsof polling) + `internal/tui` (SimulationScreen tests).

## Global Constraints

- Display-only: NO change to scoring, `Concern`, `ExfilRisk`, `Candidate`, sorting, the actor, or any collector command (`nettop`/`lsof`/`ps` invocations unchanged). Verbatim from spec §1/§7.
- `nettop` is already invoked with `-J bytes_in,bytes_out`; both bytes are parsed. No new external calls.
- Temperature ramp reuses the existing `heatColor`/`heatStops` (blue→red). Direction ramp is new (green→amber).
- `s` sort still sorts by out-rate in every mode. Spec §2.
- `sparkLen = 24` samples per ring; in-rings mirror out-rings exactly (advance once/tick, prune dead keys).

---

### Task 1: Model — in-rate + in-history fields

**Files:**
- Modify: `internal/model/egress.go`
- Test: `internal/model/egress_test.go` (compile-only; struct fields need no behavior test)

**Interfaces:**
- Produces: `model.Conn.InRate uint64`, `model.Conn.InSpark []uint64`, `model.EgressInstance.InSpark []uint64`, `model.EgressGroup.InSpark []uint64` — consumed by Tasks 3–4 (populate) and 6–9 (render).

- [ ] **Step 1: Add the fields**

In `internal/model/egress.go`, add to `Conn` (after `Spark`):
```go
	InRate   uint64   // bytes/sec inbound for this connection
	InSpark  []uint64 // per-connection recent in-rate history
```
Add to `EgressInstance` (after `Spark`):
```go
	InSpark  []uint64 // per-PID recent in-rate history
```
Add to `EgressGroup` (after `Spark`):
```go
	InSpark      []uint64 // per-app recent in-rate history (summed across instances)
```

- [ ] **Step 2: Build**

Run: `go build ./internal/model/`
Expected: PASS (pure field additions).

- [ ] **Step 3: Commit**

```bash
git add internal/model/egress.go
git commit -m "feat(model): in-rate + in-history fields on egress Conn/Instance/Group"
```

---

### Task 2: RateIn helper

**Files:**
- Modify: `internal/egress/rate.go`
- Test: `internal/egress/rate_test.go`

**Interfaces:**
- Consumes: `egress.Bytes{Out, In uint64}`, existing `RateOut(prev, cur Bytes, intervalSec float64) uint64`.
- Produces: `RateIn(prev, cur Bytes, intervalSec float64) uint64` — used by Task 3.

- [ ] **Step 1: Write the failing test**

In `internal/egress/rate_test.go` add:
```go
func TestRateIn(t *testing.T) {
	// 2000 inbound bytes over 2s = 1000 B/s.
	if got := RateIn(Bytes{In: 100}, Bytes{In: 2100}, 2.0); got != 1000 {
		t.Fatalf("RateIn = %d, want 1000", got)
	}
	// A counter reset (cur < prev) yields 0, never a huge spike (mirrors RateOut).
	if got := RateIn(Bytes{In: 5000}, Bytes{In: 10}, 1.0); got != 0 {
		t.Fatalf("RateIn on reset = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/egress/ -run TestRateIn`
Expected: FAIL — `undefined: RateIn`.

- [ ] **Step 3: Implement**

In `internal/egress/rate.go`, mirror `RateOut` exactly but on the `In` field. Read the existing `RateOut` first and copy its reset/interval handling; the body is identical with `.In` substituted for `.Out`:
```go
// RateIn is RateOut for the inbound counter: bytes/sec, clamped to 0 on a counter reset.
func RateIn(prev, cur Bytes, intervalSec float64) uint64 {
	if cur.In < prev.In || intervalSec <= 0 {
		return 0
	}
	return uint64(float64(cur.In-prev.In) / intervalSec)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/egress/ -run TestRateIn`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/egress/rate.go internal/egress/rate_test.go
git commit -m "feat(egress): RateIn helper (mirror of RateOut on the inbound counter)"
```

---

### Task 3: Monitor — compute in-rates + advance in-rings

**Files:**
- Modify: `internal/egress/monitor.go` (the `Monitor` struct fields, `New`, and `Sample`)
- Test: `internal/egress/monitor_test.go`

**Interfaces:**
- Consumes: `RateIn` (Task 2); `Instance.InRate` (already a field, currently set to 0); the three existing out-rings `spark`/`sparkPID`/`sparkConn`.
- Produces: three in-rings `sparkIn`/`sparkInPID`/`sparkInConn map[...]...[]uint64`; populates `Conn.InRate`, `Conn.InSpark`, `Instance.InRate`; passes `sparkIn` to `Aggregate` (Task 4) and attaches per-PID `InSpark` to members.

- [ ] **Step 1: Write the failing test**

Read `internal/egress/monitor_test.go` for the existing fake-seam harness first (it injects `runNettop`/`runLsof` bytes and calls `Sample()` twice to get non-zero rates). Add a test that a PID with growing inbound bytes gets a non-zero `InRate` and a populated `InSpark` on its instance row. Model it on the existing out-rate test in that file — same two-tick pattern, asserting `InRate`/`InSpark` instead of `OutRate`/`Spark`:
```go
func TestSample_InRateAndInSpark(t *testing.T) {
	m := newTestMonitor(t) // reuse whatever the existing tests use to build a seam-injected Monitor
	m.Sample()             // tick 1: establishes the cumulative baseline (rates are 0)
	groups := m.Sample()   // tick 2: now inbound delta → a real in-rate
	g := findGroup(t, groups, "backuptool")
	if g.InRate == 0 {
		t.Fatal("group in-rate must be computed, not hardcoded 0")
	}
	if len(g.InSpark) == 0 {
		t.Fatal("group must carry in-rate history")
	}
	if g.Members[0].InRate == 0 || len(g.Members[0].InSpark) == 0 {
		t.Fatal("instance must carry in-rate + in-history")
	}
}
```
(If the existing test file has no `newTestMonitor`/`findGroup` helpers, inline the fixture the same way the nearest out-rate test does — do NOT invent new seams.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/egress/ -run TestSample_InRateAndInSpark`
Expected: FAIL — `g.InRate == 0` (in-rate is hardcoded 0 today).

- [ ] **Step 3: Add the in-ring fields**

In `internal/egress/monitor.go`, add to the `Monitor` struct beside the out-rings:
```go
	sparkIn     map[string][]uint64 // per-app in-rate history
	sparkInPID  map[int][]uint64    // per-PID in-rate history
	sparkInConn map[string][]uint64 // per-connKey in-rate history
```
In `New`, initialize them beside the out-rings:
```go
		sparkIn:     map[string][]uint64{},
		sparkInPID:  map[int][]uint64{},
		sparkInConn: map[string][]uint64{},
```

- [ ] **Step 4: Compute per-conn in-rate + ring (in Sample, first/second conn passes)**

In `Sample`, the first conn pass advances `sparkConn` from `RateOut(prev, curConn[k], ...)`. Alongside it, compute the in-rate and advance `sparkInConn`. Add an in-rate map beside `rateOf`:
```go
	rateOf := make(map[string]uint64, len(curConn))
	rateInOf := make(map[string]uint64, len(curConn)) // NEW
```
Inside the first pass, after the existing `rateOf[k] = rate` / `m.sparkConn` block, add:
```go
			var rin uint64
			if prev, ok := m.prevConn[k]; ok {
				rin = RateIn(prev, curConn[k], m.interval)
			}
			rateInOf[k] = rin
			si := append(m.sparkInConn[k], rin)
			if len(si) > sparkLen {
				si = si[len(si)-sparkLen:]
			}
			m.sparkInConn[k] = si
```
In the second pass, beside `cs[i].OutRate = rateOf[k]` / `cs[i].Spark = m.sparkConn[k]`, add:
```go
			cs[i].InRate = rateInOf[k]
			cs[i].InSpark = m.sparkInConn[k]
```
After the existing `m.sparkConn` prune loop, prune `sparkInConn` the same way:
```go
	for k := range m.sparkInConn {
		if !liveConn[k] {
			delete(m.sparkInConn, k)
		}
	}
```

- [ ] **Step 5: Compute per-PID in-rate + set Instance.InRate**

In the `insts = append(...)` loop, the existing code computes `rate = RateOut(m.prev[pid], cur[pid], ...)` and sets `InRate: 0`. Compute the in-rate too and set it:
```go
		var rateIn uint64
		if prev, ok := m.prev[pid]; ok {
			rateIn = RateIn(prev, cur[pid], m.interval)
		}
```
Change the struct literal field `InRate: 0,` to `InRate: rateIn,`.

- [ ] **Step 6: Advance per-app and per-PID in-rings**

After the existing `summed`/`m.spark` app-ring loop, add a summed-in loop keyed identically:
```go
	summedIn := map[string]uint64{}
	for _, in := range insts {
		k := in.Path
		if k == "" {
			k = in.App
		}
		summedIn[k] += in.InRate
	}
	for k, r := range summedIn {
		s := append(m.sparkIn[k], r)
		if len(s) > sparkLen {
			s = s[len(s)-sparkLen:]
		}
		m.sparkIn[k] = s
	}
```
In the existing per-PID `livePID` loop, beside `m.sparkPID[in.PID]`, advance the in-ring:
```go
		si := append(m.sparkInPID[in.PID], in.InRate)
		if len(si) > sparkLen {
			si = si[len(si)-sparkLen:]
		}
		m.sparkInPID[in.PID] = si
```
After the `sparkPID` prune loop, prune `sparkInPID`:
```go
	for pid := range m.sparkInPID {
		if !livePID[pid] {
			delete(m.sparkInPID, pid)
		}
	}
```

- [ ] **Step 7: Pass in-spark to Aggregate + attach per-PID InSpark**

Change the `Aggregate` call (Task 4 changes its signature) to pass `m.sparkIn`:
```go
	groups := Aggregate(insts, m.spark, m.sparkIn)
```
In the `for i := range groups` member loop, beside `groups[i].Members[j].Spark = m.sparkPID[...]`, add:
```go
			groups[i].Members[j].InSpark = m.sparkInPID[groups[i].Members[j].PID]
```

- [ ] **Step 8: Run the test to verify it passes** (after Task 4 compiles Aggregate)

Run: `go test ./internal/egress/ -run TestSample_InRateAndInSpark`
Expected: PASS. (If Aggregate's new signature isn't in yet, do Task 4 Step 3 first — they compile together.)

- [ ] **Step 9: Commit**

```bash
git add internal/egress/monitor.go internal/egress/monitor_test.go
git commit -m "feat(egress): compute in-rates + advance in-rate rings (conn/PID/app)"
```

---

### Task 4: Aggregate — thread in-spark to the group

**Files:**
- Modify: `internal/egress/aggregate.go`
- Test: `internal/egress/aggregate_test.go`

**Interfaces:**
- Consumes: `Instance.InRate` (already summed today via `g.InRate += in.InRate`); a new `inSpark map[string][]uint64` from Task 3.
- Produces: `Aggregate(insts []Instance, spark, inSpark map[string][]uint64) []model.EgressGroup`, setting `g.InSpark = inSpark[key]` and each member's `InSpark` left for the monitor (Task 3 Step 7) — consumed by the view.

- [ ] **Step 1: Write the failing test**

In `internal/egress/aggregate_test.go`, extend the nearest existing aggregate test (or add) to pass an `inSpark` map and assert it lands on the group. Read the existing test's `Aggregate(...)` call and mirror its `insts`/`spark` construction:
```go
func TestAggregate_InSpark(t *testing.T) {
	insts := []Instance{{PID: 1, App: "x", Path: "/x", OutRate: 10, InRate: 40}}
	spark := map[string][]uint64{"/x": {1, 2, 3}}
	inSpark := map[string][]uint64{"/x": {7, 8, 9}}
	g := Aggregate(insts, spark, inSpark)[0]
	if g.InRate != 40 {
		t.Fatalf("in-rate must aggregate, got %d", g.InRate)
	}
	if len(g.InSpark) != 3 || g.InSpark[2] != 9 {
		t.Fatalf("in-history must attach to the group, got %v", g.InSpark)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/egress/ -run TestAggregate_InSpark`
Expected: FAIL — too few arguments to `Aggregate` / no `InSpark`.

- [ ] **Step 3: Implement**

Change the signature:
```go
func Aggregate(insts []Instance, spark, inSpark map[string][]uint64) []model.EgressGroup {
```
In the final `for _, key := range order` loop, beside `g.Spark = spark[key]`, add:
```go
		g.InSpark = inSpark[key]
```
(The existing `g.InRate += in.InRate` already aggregates the current in-rate — no change there.)

- [ ] **Step 4: Fix the other caller**

`grep -rn "Aggregate(" internal/ | grep -v _test` — the only non-test caller is `monitor.go` (updated in Task 3 Step 7). Update any remaining call to the 3-arg form.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/egress/`
Expected: PASS (all egress tests, including Task 3's).

- [ ] **Step 6: Commit**

```bash
git add internal/egress/aggregate.go internal/egress/aggregate_test.go
git commit -m "feat(egress): Aggregate threads in-rate history onto the group"
```

---

### Task 5: EgressModel — trendMode + `t` toggle

**Files:**
- Modify: `internal/tui/egressmodel.go`
- Test: `internal/tui/egressmodel_test.go`

**Interfaces:**
- Produces: `EgressModel.Trend` of type `trendMode` (values `trendOut`, `trendIn`, `trendCombined`); `t` cycles out→in→combined→out in `egressUpdate`. Consumed by Tasks 8–9.

- [ ] **Step 1: Write the failing test**

In `internal/tui/egressmodel_test.go`:
```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run TestEgressUpdate_TrendToggle`
Expected: FAIL — `undefined: trendOut` / `m.Trend`.

- [ ] **Step 3: Implement**

In `internal/tui/egressmodel.go`, add the type + constants near the top (beside `egressSort`):
```go
type trendMode int

const (
	trendOut trendMode = iota // sparkline plots out-rate (temperature = share-of-peak volume)
	trendIn                   // sparkline plots in-rate
	trendCombined             // height = in+out, color = green→amber direction
)
```
Add a field to `EgressModel`:
```go
	Trend trendMode // which series/coloring the TREND column shows (cycled by `t`)
```
In `egressUpdate`'s `case tcell.KeyRune:` switch, add:
```go
		case 't':
			m.Trend = (m.Trend + 1) % 3
```
(`NewEgress` needs no change — the zero value `trendOut` is the default.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/ -run TestEgressUpdate_TrendToggle`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tui/egressmodel.go internal/tui/egressmodel_test.go
git commit -m "feat(tui): trend mode state + t toggle (out/in/combined)"
```

---

### Task 6: Colors — share-of-peak temperature + green→amber direction

**Files:**
- Modify: `internal/tui/egressview.go` (rework `absIntensity` usage; add `directionColor`)
- Test: `internal/tui/egressview_test.go`

**Interfaces:**
- Consumes: existing `heatColor(frac float64) tcell.Color` (blue→red), `heatStops`.
- Produces: `tempColor(rate, peak uint64) tcell.Color` (share-of-peak, replaces absolute `absIntensity`), and `directionColor(out, in uint64) tcell.Color` (green→amber by `out/(out+in)`). Consumed by Task 8.

- [ ] **Step 1: Write the failing tests**

In `internal/tui/egressview_test.go`:
```go
func TestTempColor_ShareOfPeak(t *testing.T) {
	// A flow at the frame peak is hot (red end); a trickle is cold (blue end).
	hot := tempColor(1000, 1000)
	cold := tempColor(1, 1000)
	if hot == cold {
		t.Fatal("peak and trickle must differ")
	}
	if hot != heatColor(1.0) || cold != heatColor(1.0/1000.0) {
		t.Fatalf("tempColor must be heatColor(rate/peak): hot=%v cold=%v", hot, cold)
	}
	// Zero peak (no traffic) must not divide by zero.
	_ = tempColor(0, 0)
}

func TestDirectionColor(t *testing.T) {
	amber := directionColor(1000, 0) // all out
	green := directionColor(0, 1000) // all in
	if amber == green {
		t.Fatal("all-out and all-in must differ (amber vs green)")
	}
	// all-out leans to the amber (frac=1) end; all-in to the green (frac=0) end.
	if amber != dirColor(1.0) || green != dirColor(0.0) {
		t.Fatalf("directionColor must map out/(out+in) through dirColor: amber=%v green=%v", amber, green)
	}
	_ = directionColor(0, 0) // no traffic — no divide-by-zero
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/tui/ -run 'TempColor|DirectionColor'`
Expected: FAIL — `undefined: tempColor` / `directionColor` / `dirColor`.

- [ ] **Step 3: Implement**

In `internal/tui/egressview.go`, add below `heatColor`:
```go
// tempColor is the volume temperature: a rate's share of the loudest flow in view (peak), mapped
// blue(cold)→red(hot). Replaces the old absolute log scale — an arbitrary anchor. peak==0 → cold.
func tempColor(rate, peak uint64) tcell.Color {
	if peak == 0 {
		return heatColor(0)
	}
	return heatColor(float64(rate) / float64(peak))
}

// dirStops is the direction ramp: green (all inbound / download) → amber (all outbound / exfil).
var dirStops = []struct {
	at      float64
	r, g, b int32
}{
	{0.00, 80, 200, 120},  // green — inbound / download
	{0.50, 210, 200, 90},  // muted yellow — balanced
	{1.00, 240, 170, 60},  // amber — outbound / exfil
}

// dirColor maps a 0..1 lean (0 = all in, 1 = all out) to a color along dirStops.
func dirColor(frac float64) tcell.Color {
	if frac <= 0 {
		s := dirStops[0]
		return tcell.NewRGBColor(s.r, s.g, s.b)
	}
	for i := 1; i < len(dirStops); i++ {
		hi := dirStops[i]
		if frac <= hi.at {
			lo := dirStops[i-1]
			t := (frac - lo.at) / (hi.at - lo.at)
			return tcell.NewRGBColor(
				lo.r+int32(t*float64(hi.r-lo.r)),
				lo.g+int32(t*float64(hi.g-lo.g)),
				lo.b+int32(t*float64(hi.b-lo.b)),
			)
		}
	}
	s := dirStops[len(dirStops)-1]
	return tcell.NewRGBColor(s.r, s.g, s.b)
}

// directionColor colors a combined cell by which way it leans: out/(out+in) → dirColor. Balanced/
// empty → mid.
func directionColor(out, in uint64) tcell.Color {
	total := out + in
	if total == 0 {
		return dirColor(0.5)
	}
	return dirColor(float64(out) / float64(total))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tui/ -run 'TempColor|DirectionColor'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tui/egressview.go internal/tui/egressview_test.go
git commit -m "feat(tui): share-of-peak temperature + green→amber direction color ramps"
```

---

### Task 7: Generalize the sparkline renderer

**Files:**
- Modify: `internal/tui/egressview.go` (`drawSparkline`)
- Test: `internal/tui/egressview_test.go`

**Interfaces:**
- Consumes: existing `downsample(vals []uint64, width int) []uint64`, `sparkGlyphs`, `colSelBg`.
- Produces: `drawTrend(s tcell.Screen, x, y int, heights []uint64, colors []tcell.Color, width int, selected bool)` — heights drive glyph height (relative to their own max), colors is a parallel per-cell color slice. Consumed by Task 8. The current `drawSparkline` becomes a thin caller of `drawTrend` (out-only, temperature) so unrelated callers keep working until Task 8.

- [ ] **Step 1: Write the failing test**

```go
func TestDrawTrend_HeightsAndColors(t *testing.T) {
	s := simScreen(t) // reuse the existing sim-screen helper in this test file
	heights := []uint64{0, 100}
	colors := []tcell.Color{heatColor(0), heatColor(1)}
	drawTrend(s, 0, 0, heights, colors, 2, false)
	s.Show()
	cells, _, _ := s.GetContents()
	// cell 0 = lowest glyph, cell 1 = highest glyph (height relative to max)
	if cells[0].Runes[0] != sparkGlyphs[0] {
		t.Fatalf("min height should be the lowest glyph, got %q", cells[0].Runes[0])
	}
	if cells[1].Runes[0] != sparkGlyphs[len(sparkGlyphs)-1] {
		t.Fatalf("max height should be the tallest glyph, got %q", cells[1].Runes[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run TestDrawTrend_HeightsAndColors`
Expected: FAIL — `undefined: drawTrend`.

- [ ] **Step 3: Implement**

Read the current `drawSparkline` first. Add `drawTrend` (the generalized core) and rewrite `drawSparkline` to delegate:
```go
// drawTrend renders heights[i] as a sparkline glyph (height relative to heights' own max) colored
// by colors[i] at (x+i, y). heights and colors are pre-downsampled to width and equal length.
func drawTrend(s tcell.Screen, x, y int, heights []uint64, colors []tcell.Color, width int, selected bool) {
	if len(heights) == 0 {
		return
	}
	var max uint64
	for _, v := range heights {
		if v > max {
			max = v
		}
	}
	for i, v := range heights {
		idx := 0
		if max > 0 {
			idx = int(v * uint64(len(sparkGlyphs)-1) / max)
		}
		st := tcell.StyleDefault.Foreground(colors[i])
		if selected {
			st = st.Background(colSelBg)
		}
		drawText(s, x+i, y, st, string(sparkGlyphs[idx]))
	}
}

// drawSparkline plots vals as an out-rate trend colored by absolute-free share-of-its-own-max
// temperature. Retained for callers not yet mode-aware; the tree uses drawTrend directly (Task 8).
func drawSparkline(s tcell.Screen, x, y int, vals []uint64, width int, selected bool) {
	ds := downsample(vals, width)
	colors := make([]tcell.Color, len(ds))
	var peak uint64
	for _, v := range ds {
		if v > peak {
			peak = v
		}
	}
	for i, v := range ds {
		colors[i] = tempColor(v, peak)
	}
	drawTrend(s, x, y, ds, colors, width, selected)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tui/`
Expected: PASS (existing sparkline render tests still pass via the delegating `drawSparkline`).

- [ ] **Step 5: Commit**

```bash
git add internal/tui/egressview.go internal/tui/egressview_test.go
git commit -m "refactor(tui): drawTrend core (heights + per-cell colors); drawSparkline delegates"
```

---

### Task 8: Render the tree per trend mode

**Files:**
- Modify: `internal/tui/egressview.go` (`egressView`, `drawEgressRow`)
- Test: `internal/tui/egressview_test.go`

**Interfaces:**
- Consumes: `EgressModel.Trend` (Task 5), `tempColor`/`directionColor` (Task 6), `drawTrend`/`downsample` (Task 7), model `Spark`/`InSpark` at each level (Tasks 1–4).
- Produces: mode-aware TREND rendering. Adds `framePeak(rows []egressRow, mode trendMode) uint64` and `trendSeries(out, in []uint64, mode trendMode, peak int, width int) (heights []uint64, colors []tcell.Color)`.

- [ ] **Step 1: Write the failing test**

```go
func TestEgressView_CombinedTrendUsesDirectionColor(t *testing.T) {
	s := simScreen(t)
	g := eg("uploader", model.Elevated, 900)
	g.Spark = []uint64{100, 200, 300}   // out
	g.InSpark = []uint64{0, 0, 0}       // all out → amber end
	m := NewEgress().withGroups([]model.EgressGroup{g})
	m.Trend = trendCombined
	egressView(m, s)
	s.Show()
	cells, w, _ := s.GetContents()
	// find a colored trend cell and assert it's on the direction (green→amber) ramp, not the
	// blue→red temperature ramp — i.e. its foreground equals directionColor for an all-out cell.
	wantFg, _, _ := tcell.StyleDefault.Foreground(directionColor(300, 0)).Decompose()
	found := false
	for i := 0; i < w*3; i++ {
		fg, _, _ := cells[i].Style.Decompose()
		if fg == wantFg {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("combined mode must color the trend on the direction ramp")
	}
}
```
(If matching exact colors is brittle against the sim palette, assert instead that the group's own `visibleRows()` trend for combined mode produces `heights[i] == out[i]+in[i]` via a direct `trendSeries` unit test — include BOTH; the `trendSeries` unit test is the reliable one:)
```go
func TestTrendSeries_Combined(t *testing.T) {
	out := []uint64{100, 200}
	in := []uint64{50, 0}
	heights, colors := trendSeries(out, in, trendCombined, 250, 2)
	if heights[0] != 150 || heights[1] != 200 {
		t.Fatalf("combined height must be out+in, got %v", heights)
	}
	if colors[0] != directionColor(100, 50) || colors[1] != directionColor(200, 0) {
		t.Fatal("combined color must be directionColor(out,in)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/tui/ -run 'TrendSeries|CombinedTrend'`
Expected: FAIL — `undefined: trendSeries` / `framePeak`.

- [ ] **Step 3: Implement the series/peak helpers**

In `internal/tui/egressview.go`:
```go
// framePeak is the loudest relevant rate across all visible rows this frame — the share-of-peak
// denominator for temperature coloring. For combined mode temperature isn't used, so 0 is fine.
func framePeak(rows []egressRow, mode trendMode) uint64 {
	var peak uint64
	consider := func(vals []uint64) {
		for _, v := range vals {
			if v > peak {
				peak = v
			}
		}
	}
	for _, row := range rows {
		out, in := rowSpark(row)
		switch mode {
		case trendOut:
			consider(out)
		case trendIn:
			consider(in)
		}
	}
	return peak
}

// rowSpark returns the (out, in) history for whichever tree level this row is.
func rowSpark(row egressRow) (out, in []uint64) {
	switch {
	case row.conn != nil:
		return row.conn.Spark, row.conn.InSpark
	case row.member != nil:
		return row.member.Spark, row.member.InSpark
	default:
		return row.group.Spark, row.group.InSpark
	}
}

// trendSeries builds the (heights, colors) a row's TREND cell renders for the mode: out/in plot
// that direction with share-of-peak temperature; combined plots out+in with direction color.
func trendSeries(out, in []uint64, mode trendMode, peak, width int) (heights []uint64, colors []tcell.Color) {
	switch mode {
	case trendIn:
		h := downsample(in, width)
		c := make([]tcell.Color, len(h))
		for i, v := range h {
			c[i] = tempColor(v, uint64(peak))
		}
		return h, c
	case trendCombined:
		ov, iv := downsample(out, width), downsample(in, width)
		h := make([]uint64, len(ov))
		c := make([]tcell.Color, len(ov))
		for i := range ov {
			var inv uint64
			if i < len(iv) {
				inv = iv[i]
			}
			h[i] = ov[i] + inv
			c[i] = directionColor(ov[i], inv)
		}
		return h, c
	default: // trendOut
		h := downsample(out, width)
		c := make([]tcell.Color, len(h))
		for i, v := range h {
			c[i] = tempColor(v, uint64(peak))
		}
		return h, c
	}
}
```

- [ ] **Step 4: Wire the mode through egressView → drawEgressRow**

`egressView` currently computes `rows := m.visibleRows()` and loops `drawEgressRow(s, cols, w, y, row, ...)`. Before the loop, compute the peak once:
```go
	peak := int(framePeak(rows, m.Trend))
```
Thread `m.Trend` and `peak` into `drawEgressRow` (add two params). Inside `drawEgressRow`, replace the existing `drawSparkline(s, cols.trendX, y, spark, trendW, selected)` call with:
```go
	out, in := rowSpark(row)
	heights, colors := trendSeries(out, in, mode, peak, trendW)
	drawTrend(s, cols.trendX, y, heights, colors, trendW, selected)
```
(Delete the now-unused per-branch `spark = ...` assignments in `drawEgressRow`; `rowSpark(row)` replaces them. Keep everything else — marker/label/trust/rate/dest — unchanged.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/tui/`
Expected: PASS (including the existing egress render tests — out mode still renders, now via `drawTrend`).

- [ ] **Step 6: Commit**

```bash
git add internal/tui/egressview.go internal/tui/egressview_test.go
git commit -m "feat(tui): render TREND per mode (out/in temperature, combined direction)"
```

---

### Task 9: Header indicator, footer hint, and the contextual legend

**Files:**
- Modify: `internal/tui/egressview.go` (`egressView` — header label, footer, new legend line)
- Test: `internal/tui/egressview_test.go`

**Interfaces:**
- Consumes: `EgressModel.Trend`, `heatColor`, `dirColor`, `sparkGlyphs`.
- Produces: TREND header shows `↑`/`↓`/`⇅`; footer gains `t trend`; a `drawTrendLegend(s, y, w, mode)` line above the footer that recolors to the mode.

- [ ] **Step 1: Write the failing test**

```go
func TestEgressView_TrendLegendAndHeader(t *testing.T) {
	s := simScreen(t)
	m := NewEgress().withGroups([]model.EgressGroup{eg("x", model.Low, 10)})
	m.Trend = trendCombined
	egressView(m, s)
	s.Show()
	if !simContains(s, "⇅") {
		t.Fatal("combined mode header must show the ⇅ glyph")
	}
	if !simContains(s, "download") || !simContains(s, "exfil") {
		t.Fatal("combined legend must label the direction ramp (download → exfil)")
	}
	if !simContains(s, "t trend") {
		t.Fatal("footer must advertise the t toggle")
	}
	// out mode legend labels volume, not direction.
	m.Trend = trendOut
	egressView(m, s)
	s.Show()
	if !simContains(s, "quiet") || !simContains(s, "loud") {
		t.Fatal("out legend must label the volume ramp (quiet → loud)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run TestEgressView_TrendLegendAndHeader`
Expected: FAIL — no `⇅`, no legend, no `t trend`.

- [ ] **Step 3: Implement the header glyph + footer**

In `egressView`, the TREND header currently draws `truncate("TREND", trendW)`. Replace with a mode label:
```go
	trendLabel := "TREND ↑"
	switch m.Trend {
	case trendIn:
		trendLabel = "TREND ↓"
	case trendCombined:
		trendLabel = "TREND ⇅"
	}
	drawText(s, cols.trendX, headerY, tcell.StyleDefault.Foreground(colDim), truncate(trendLabel, trendW))
```
Update `footerHint` (the package const) to include `· t trend`:
```go
const footerHint = "j/k move · ↵/→ expand · ← collapse · y copy · i inspect · t trend · s sort · / filter · p pause · Q quit"
```

- [ ] **Step 4: Implement the legend line**

Add `drawTrendLegend` and call it. The legend renders a real gradient of `sparkGlyphs` colored by the active ramp, with end labels:
```go
// drawTrendLegend draws a one-line, self-coloring key for the active trend mode at row y: the
// glyphs use the SAME ramp the sparklines do, so it's correct by construction.
func drawTrendLegend(s tcell.Screen, y, w int, mode trendMode) {
	def := tcell.StyleDefault.Foreground(colDim)
	x := marginX
	label, left, right := "TREND ↑ out  ", "quiet ", " loud"
	ramp := func(frac float64) tcell.Color { return heatColor(frac) }
	switch mode {
	case trendIn:
		label = "TREND ↓ in   "
	case trendCombined:
		label, left, right = "TREND ⇅      ", "◀ in·download ", " out·exfil ▶"
		ramp = func(frac float64) tcell.Color { return dirColor(frac) }
	}
	x = drawText(s, x, y, def, label)
	x = drawText(s, x, y, def, left)
	n := len(sparkGlyphs)
	for i := 0; i < n; i++ {
		frac := float64(i) / float64(n-1)
		drawText(s, x, y, tcell.StyleDefault.Foreground(ramp(frac)), string(sparkGlyphs[i]))
		x++
	}
	drawText(s, x, y, def, right)
	_ = w
}
```
In `egressView`, the layout computes `footerY := h - 1` and a detail block above it. Reserve one row for the legend directly above the footer: change the footer/detail math to place the legend at `footerY-… ` — concretely, draw the legend at `legendY := footerY - 1` and shift `tableBottom` up by 1 so the tree never overwrites it:
```go
	legendY := footerY - 1
	drawTrendLegend(s, legendY, w, m.Trend)
```
and reduce `tableBottom` by one row (it currently is `footerY - 1 - len(detail)`) → `footerY - 2 - len(detail)`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/tui/`
Expected: PASS. Manually eyeball nothing — the SimulationScreen assertions cover header/legend/footer.

- [ ] **Step 6: Commit**

```bash
git add internal/tui/egressview.go internal/tui/egressview_test.go
git commit -m "feat(tui): TREND mode header glyph + contextual legend + t footer hint"
```

---

### Task 10: Full-suite gate + Architext

**Files:**
- Verify only; possibly `docs/architext/data/**` if a flow/node changed materially (this is display-only, so likely no Architext change — confirm).

- [ ] **Step 1: Full suite + race + vet + gofmt**

Run:
```bash
go build ./... && go vet ./... && go test ./... && gofmt -l $(git ls-files '*.go') | grep -v '^vendor/'
```
Expected: all pass; gofmt prints nothing (non-vendor).

- [ ] **Step 2: Decoupling invariant still holds**

Run: `go test ./internal/tui/ -run TestDecouplingInvariant`
Expected: PASS (no new imports beyond model+mark; the feature is view-local + model fields).

- [ ] **Step 3: Architext check**

This change is display-only (no new data movement, trust boundary, or module responsibility). Run `architext validate` and confirm no failures; do NOT invent a diagram change. If validation is clean, no Architext edit is needed.

- [ ] **Step 4: Commit any residue**

```bash
git commit -am "chore: trend-modes suite gate" --allow-empty
```

---

## Self-Review

**Spec coverage:**
- §2 toggle (`t`, out→in→combined, header `↑↓⇅`, footer, sort unchanged) → Tasks 5, 8, 9. ✓
- §3 two color axes: temperature share-of-peak (replaces absolute) → Task 6 (`tempColor`) + Task 7/8; green→amber direction → Task 6 (`directionColor`). ✓
- §3.1 share-of-peak denominator = loudest flow in view → Task 8 (`framePeak`). ✓
- §4 contextual recoloring legend → Task 9 (`drawTrendLegend`). ✓
- §5 in-rate history ring + `InSpark` on Group/Instance/Conn, populated in Aggregate → Tasks 1–4. ✓ (Note: also fixes `InRate` being hardcoded 0 — Task 3.)
- §6 `trendMode` + drawSparkline generalization + mode series → Tasks 5, 7, 8. ✓
- §7 display-only, no second column, per-frame peak → Global Constraints + Task 8. ✓
- §8 testing (Aggregate InSpark, toggle cycle, directionColor ends, relative tempColor, per-mode render) → Tasks 4, 5, 6, 8, 9. ✓

**Placeholder scan:** none — every code step shows real code; test bodies are concrete.

**Type consistency:** `trendMode`/`trendOut/In/Combined` (Task 5) used verbatim in 8/9; `tempColor(rate,peak uint64)` and `directionColor(out,in uint64)` (Task 6) consumed with matching signatures in 7/8; `drawTrend(...heights []uint64, colors []tcell.Color...)` (Task 7) called with those types in 8; `rowSpark`/`trendSeries`/`framePeak` defined and used consistently in 8; `InSpark`/`InRate` field names consistent across model (1), monitor (3), aggregate (4), view (8).

One risk flagged for the executor: Tasks 3 and 4 compile together (the `Aggregate` signature change spans both) — do Task 4 Step 3 before running Task 3's test, or expect a transient compile error between them.
