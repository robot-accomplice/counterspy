# Egress Group Zoom Dashboard — Design

**Date:** 2026-07-13
**Status:** Draft for review
**Branch:** `spec/exfil-inspect-interceptor`

## 1. Goal

Add a **zoom** action to the Exfiltration (egress) view: from any row, press `z` to
"blow up" that row's app group into a full-screen, `btm`-style dashboard that shows,
for one group: network throughput over time, what each PID is consuming, and **each
PID's share of the group's total egress**. From inside the zoom, `i` inspects the
selected PID (reusing the existing capture/inspect path).

The reference model is `btm` (bottom): a multi-panel dashboard with a large braille
time-series graph, a selectable process table, and supporting stat panels — boxed.

## 2. What the user cares about (drives every panel)

1. **Network traffic** — throughput over time → the graph panel.
2. **Which PIDs are consuming what** — per-PID OUT↑/IN↓ rates and cumulative total.
3. **Which PID is sending what % of the group's data** — per-PID **share of group**,
   shown as a first-class `%GRP` column with a share bar.

CPU%/Mem% per PID are **out of scope for v1** (deferred, §11): they would require a
new `ps`-based collector and pull the tool into system-monitoring beyond network
egress. Revisit only if the layout has spare real estate and it proves pertinent.

## 3. Entry / exit and modality

- **Enter:** `z` on any egress row resolves to that row's group and opens the zoom.
- **Exit:** `z` or `esc` returns to the tree with prior selection/expansion intact.
- The zoom is a **full-screen modal** over the tree, exactly like the inspection
  overlay pattern (`EgressModel.Inspection`): a new `EgressModel.Zoom` state, driven
  off the pure `egressUpdate`. Sampling continues to refresh the underlying group data
  each tick, so the graph and rates are live while zoomed.
- **Inspect stacks on top:** `i` inside the zoom sets `InspectReq` for the selected
  PID's busiest connection (same resolution the tree uses). When the inspection overlay
  closes (`esc`/`i`), control returns to the zoom, not the tree. Precedence in
  `egressUpdate`: `Inspection` (if open) → else `Zoom` (if open) → else the tree.

## 4. Layout (four boxed panels, btm structure)

Target a 120×40 terminal; degrade gracefully (see §8).

```
┌ claude · egress · 3 pids ──────────────────────────┐┌ PIDs ──────────────────────┐
│ 1.4M┤        ╭·╮                                    ││ PID    OUT↑   IN↓  %GRP  T │
│     │   ╭╮  ╭╯ ╰·╮   ╭╮   per-PID colored lines     ││▸1802  1.4M   120K ▇▇▇ 78% ◆│ ← selected
│ 0.7M┤ ╭╯╰╮╭╯    ╰╮ ╭╯╰╮                             ││ 1990   32K     2K ▇   15% ◆│
│     │╭╯   ╰╯      ╰·╯  ╰··                          ││ 2044   16K     0B ▏    7% ◇│
│   0 ┼───────────────────────────────                │└────────────────────────────┘
│     60s                          0s  ↑1.4M ↓122K    │┌ destinations ──────────────┐
└─────────────────────────────────────────────────────┘│ 2600:1901::443   ↑1.1M 78% │
┌ this group ─────────────────────────────────────────┐│ 140.82.113.26    ↑300K 20% │
│ notarized · background daemon · cadence: steady      ││ 17.253.7.7:443   ↑ 12K  2% │
│ can access: screen · keystrokes                      │└────────────────────────────┘
└─ i inspect · ↑/↓ pid · t out/in · z back ───────────┘
```

Exact panel placement is a layout detail for the plan; the **content** of each panel:

### 4.1 Throughput graph (top-left, the CPU/Network analog)
- A **braille line chart** (§5): one color-matched line per PID, plotting the chosen
  metric (out-rate by default) over the retained history window.
- **Y-axis:** throughput labels (max, a midpoint, 0), scaled to the frame's peak.
- **X-axis:** time, oldest on the left to `0s` (now) on the right.
- **Overlaid stat:** the group's live `↑out ↓in` totals (like btm's RX/TX box).
- The **selected PID's line is emphasized** (bright/bold); the others are dimmed, so
  the graph and the PID table read as one selection.

### 4.2 PIDs panel (top-right, the Processes/CPU-Use analog)
- One row per PID (`EgressGroup.Members`), columns:
  `PID · OUT↑ · IN↓ · %GRP (share bar + number) · T (trust glyph)`.
- Each row carries a **color swatch matching its graph line**.
- **Selectable:** `↑/↓` or `j/k` move a highlighted selection (btm-style bar); the
  selection drives both the emphasized graph line and the `i` inspect target.
- Sorted by OUT↑ descending (loud talkers first — the exfil north-star), stable by PID.

### 4.3 destinations panel (the Disks analog)
- The group's destination endpoints (`EgressGroup.Conns` aggregated by `Endpoint`),
  columns: `endpoint · ↑out rate · % of group out`. Sorted by out-rate descending.
- Per-destination concern is **not** modeled today, so this panel shows rate + share,
  not a concern band (the group's overall concern already shows in the tree).

### 4.4 this-group panel (the Temperatures analog + footer)
- Group metadata: trust, background/daemon, cadence, and capabilities (reusing the
  `detailLines` facts already built for the tree's detail strip).
- The **key hints** live on this panel's bottom border:
  `i inspect · ↑/↓ pid · t out/in · z back`.

## 5. New component: braille line graph (`internal/tui`)

The only genuinely new primitive. A **pure** renderer, unit-testable without a screen.

- **Braille canvas:** each terminal cell is a 2×4 dot grid (base `U+2800`); a canvas of
  `cols×rows` cells addresses `2*cols × 4*rows` sub-pixels. Standard dot-bit layout.
- **API shape (finalized in the plan):**
  `plotSeries(series []graphSeries, cols, rows int, maxY uint64) [][]graphCell`
  where `graphSeries` = `{values []uint64, color tcell.Color, emphasized bool}` and
  `graphCell` = `{r rune, color tcell.Color}`. Returns a grid the panel blits with
  `drawText`/`SetContent`; axis labels are drawn by the panel around the grid.
- **Multi-series color rule (btm's):** a cell can hold only one color; series are
  plotted in order and the **emphasized (selected) series is drawn last** so it wins
  on overlap. Non-emphasized series use their dimmed color.
- **Scaling:** values map to sub-rows by `maxY` (the frame peak across all series, so
  lines share a Y-axis). Empty/short history left-pads (newest right-aligned).
- **Downsampling/upsampling:** reuse/extend the existing `downsample` when there are
  more samples than sub-columns; when fewer, plot at native density (btm looks sparse
  early too — acceptable and honest).

## 6. Data & history depth

- All per-PID data already exists: `EgressInstance.{PID,Path,Trust,OutRate,InRate,
  OutTotal,Spark,InSpark}`. `%GRP` = a member's `OutRate` ÷ the summed group `OutRate`
  (guard divide-by-zero → 0%). No new collector.
- **History ring:** today `sparkLen = 24` (≈48s at the 2s cadence). The graph wants a
  wider window; bump the per-PID rings to give the graph real depth (target ~60s → ~30
  samples; final value set in the plan). The existing small sparklines already
  `downsample` to their column width, so a longer ring only makes them smoother — no
  regression. This is the one change in `internal/egress`; everything else is `tui`.

## 7. State & the decoupling invariant

- New pure state on `EgressModel`: `Zoom *zoomState { app string; sel int; mode
  trendMode }` (selected PID index + graph metric mode, reusing the existing
  `trendMode` out/in/combined enum). `nil` = not zoomed.
- `TestDecouplingInvariant` must still hold: `internal/tui` imports only `model` +
  `mark`. The zoom reads `model.EgressGroup`/`EgressInstance` — already in `model`. No
  new cross-package dependency.
- All zoom transitions (`z` enter/exit, `↑/↓` select, `t` mode, `i` inspect-request)
  are pure functions of `(EgressModel, key, rune)` in `egressUpdate`, matching the
  existing modal pattern — so they're testable without a screen.

## 8. Degradation & edge cases

- **Narrow/short terminal:** below a threshold, drop panels in priority order
  (graph + PIDs are essential; destinations and meta drop first), and shrink the graph;
  never overprint a panel border. Mirror the tree view's existing "terminal too small"
  guard for the extreme case.
- **Single PID:** the graph shows one line; `%GRP` is 100%; panels still render.
- **A PID/endpoint disappears between ticks:** the zoom re-resolves the group by app
  name each frame; if the group is gone entirely, exit the zoom back to the tree.
- **Selection clamps** to the current PID count each frame (a vanished selected PID
  clamps to the nearest valid row).

## 9. Testing (Rule 10 — encode WHY)

- **braille graph (pure):** a known series renders the expected dot pattern; the
  emphasized series wins on overlap; two series share the Y-axis by the frame peak;
  empty history renders blank without panic.
- **`%GRP` math:** shares sum to 100% (±rounding) across members; divide-by-zero group
  rate → 0%, no panic.
- **transitions:** `z` opens/closes the zoom; `↑/↓` moves + clamps the PID selection;
  `t` cycles the metric; `i` sets `InspectReq` to the selected PID's busiest conn;
  precedence (Inspection > Zoom > tree) holds.
- **render smoke (SimulationScreen):** a populated group renders all four panel titles,
  the selected row is highlighted, and the graph area contains braille glyphs;
  tiny-terminal renders without panic and without overprinting borders.

## 10. Interaction summary

| Key        | In zoom                                             |
|------------|-----------------------------------------------------|
| `z` / `esc`| exit to the tree (restores prior selection)         |
| `↑`/`↓`, `j`/`k` | move the PID selection                        |
| `i`        | inspect the selected PID's busiest connection       |
| `t`        | cycle graph metric: out → in → combined             |
| `Q`        | quit                                                |

`z` from the tree enters the zoom for the selected row's group.

## 11. Deferred (justified — Rule 16)

- **CPU%/Mem% per PID:** needs a new `ps -axo %cpu,%mem` collector and widens the PID
  table; deferred to keep v1 network-focused and avoid system-monitoring scope creep.
  Add only if the PID panel has spare width and it proves pertinent in use.
- **Per-destination concern band:** not modeled today; would need destination-level
  scoring. Deferred; the destinations panel shows rate + share for now.
- **Historical persistence across runs:** the ring is in-memory only (as today); the
  graph starts empty on launch and fills over ~a minute. Acceptable, matches btm.

## 12. Out of scope

No changes to the tree view, the inspection engine, scoring, or the Architext data
beyond documenting the new view. The zoom is additive.
