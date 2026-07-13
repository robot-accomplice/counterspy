# Exfiltration trend modes — in / out / combined, with relative coloring

**Date:** 2026-07-13
**Status:** Design (approved in brainstorming) — for spec review
**Feature:** a `t` toggle on the Exfiltration `TREND` column: out-only · in-only · combined
**Depends on:** the Exfiltration view (per-app/instance/conn sparklines, shipped) and the
bidirectional insight from the inspection feature (a flow can be upload-shaped or download-shaped).

## 1. Purpose

The Exfiltration view exists to spot **data leaving** the machine. Today the `TREND` sparkline plots
only the *out*-rate, so a loud **download** (high in) and a loud **upload/exfil** (high out) are
indistinguishable at a glance — and the one that matters is the uploader. This adds a per-view toggle
to plot the in-rate, the out-rate, or a **combined** trend whose color tells you which way a flow
leans, so "who is uploading" reads instantly. Display-only: it changes nothing about scoring,
verdicts, sorting, or the actor.

## 2. The toggle

A new key **`t`** cycles the trend mode for the whole view: **out → in → combined → out**. The mode
persists for the session (like sort/pause). The `TREND` column header shows the active mode:
`TREND ↑` (out) · `TREND ↓` (in) · `TREND ⇅` (combined). The footer gains `t trend`. Sorting is
unaffected — `s` still sorts by out-rate (the exfil focus) in every mode.

## 3. Color model — two independent axes (no cross-mode ambiguity)

The core rule: a color family always means the same thing, so toggling never re-purposes a color.

- **Volume → temperature (cold blue → hot red).** Used in **out-only** and **in-only** modes. The
  sparkline's *height* is that direction's rate over time (relative to the row's own recent max, as
  today), and its *color* is the flow's magnitude **relative to the total volume across all visible
  flows in the current sample** — the loudest talkers glow red, minor flows stay blue. This
  **replaces** the current `absIntensity` absolute (fixed bytes/sec) scale, which is an arbitrary
  anchor that conveys nothing about what's loud *right now*.
- **Direction → green → amber.** Used in **combined** mode. Height = **total (in+out)** rate over
  time; color = the flow's lean, `out / (in + out)`, on a **green (inbound / download) → amber
  (outbound / exfil)** ramp. A tall amber bar = a loud uploader (the hunt target); a tall green bar
  = a big download; short bars = quiet either way.

Temperature *always* answers "how much," green↔amber *always* answers "which way." Combined never
uses temperature and single-direction modes never use green↔amber.

### Relative-volume reference
"Relative to total volume" is computed per rendered frame: the color denominator is the summed rate
across all visible rows for that sample (a flow doing a large share of all current traffic is hot).
The existing per-row height normalization (relative to the row's own window max) is unchanged — only
the *color* basis moves from absolute to share-of-total.

## 4. The legend (contextual, colored)

A one-line legend renders just above the footer and **recolors + relabels itself to the active mode**,
showing the *actual* gradient glyphs (real terminal colors), not a description:

- `TREND ↑ out` → `quiet ▁▂▃▅▇ loud` on the blue→red temperature ramp
- `TREND ↓ in`  → `quiet ▁▂▃▅▇ loud` on the blue→red temperature ramp
- `TREND ⇅ combined` → `◀ in · download  ▁▂▃▅▇  upload · exfil ▶` on the green→amber ramp

Because it draws the same ramp the sparklines use, the legend is self-consistent by construction. It
is scoped to the sparkline encoding; the TRUST/`internal/mark` glyphs keep their own legend in help.

## 5. Data

`InRate` (current) is already parsed from `nettop`'s `bytes_in` and aggregated. Missing is the in-rate
**history** and the cross-flow total needed for relative color.

- **In-rate history ring:** the egress monitor already keeps a per-group out-rate ring feeding
  `Spark`; add a parallel in-rate ring feeding a new `InSpark`. No new external calls.
- **Model:** add `InSpark []uint64` to `EgressGroup`, `EgressInstance`, and `Conn` (mirroring the
  existing `Spark`). `Aggregate` populates it from the in-rate spark map, exactly like `Spark`.
- **Combined series** (total = in+out per sample) is derived in the view from `Spark` + `InSpark`
  (element-wise sum) — not stored.

## 6. View

- `EgressModel` gains `trendMode` (`trendOut | trendIn | trendCombined`), cycled by `t` in the pure
  `egressUpdate`.
- `drawSparkline` is generalized to take the series to plot and a color function; `egressView`
  computes the frame's cross-flow total once and picks `(series, colorFn)` per mode:
  out → (`Spark`, tempColor), in → (`InSpark`, tempColor), combined → (sum, directionColor).
- A `directionColor(out, in)` ramp (green→amber by `out/(in+out)`) is added alongside the reworked
  `tempColor` (blue→red by `rate/total`).
- Header mode indicator + footer hint + the contextual legend line.

## 7. Scope & non-goals

- Display-only. No change to scoring, `ExfilRisk`, sorting, the actor, or any collector command.
- No per-cell cross-flow total history is stored; the relative-color denominator is the current
  frame's total (cheap, recomputed each render).
- Not adding a second physical column — one toggled column keeps the one-line-per-row tree.

## 8. Testing

- `Aggregate` populates `InSpark` from the in-spark map (unit).
- Pure `egressUpdate`: `t` cycles out→in→combined→out (unit).
- `directionColor`: out-only → amber end, in-only → green end, 50/50 → mid (unit).
- Relative `tempColor`: a flow at the frame's max rate → hot, a trickle → cold (unit).
- `SimulationScreen`: each mode renders the right header glyph and the legend recolors/relabels;
  the combined series is the element-wise sum (render assertions).
