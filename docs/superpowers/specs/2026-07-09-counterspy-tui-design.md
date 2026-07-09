# CounterSpy TUI — Design Spec

**Date:** 2026-07-09
**Status:** Approved for planning
**Builds on:** the main design spec §12 (post-v1 TUI direction) + the swarm-reviewed mockup
(`docs/mockups/counterspy-tui.html`, v2).

## 1. Purpose

An interactive terminal UI for triaging CounterSpy findings: navigate ranked findings,
drill into the evidence story, and quarantine/restore with per-item confirmation — the
"master-detail triage" the CLI can only approximate. It is a **face over the existing
core**, not new analysis.

## 2. Locked decisions

- **Framework: `tcell`** (`github.com/gdamore/tcell/v2`). A mature, single-purpose,
  portable cell library — a far smaller dependency tree than the full Charm stack, chosen
  deliberately to limit the supply-chain surface of a root-run security tool. This is the
  first third-party dependency; it is pinned and vendored, and the next ABORT will
  scrutinize it.
- **Scope: full interactive** — navigate + detail pane + filter/sort + **quarantine
  (confirm modal) + restore**, via the hardened `internal/act` package.
- **Data source: live scan + `--from` snapshot** — `counterspy tui` runs a scan by
  default (sudo, live collectors); `counterspy tui --from <file>` (or stdin `-`) loads a
  `scan --json` snapshot (`[]model.Assessment`). The snapshot path makes the TUI testable
  and demoable without sudo, and composable (`scan --json | tui --from -`).

## 3. Architecture

New **`internal/tui`** package on the outer ring: depends inward on `model`, `interpret`,
`act`, and mirrors the tier color *scheme* from `report` (defined as `tcell.Color` values, since
tcell doesn't consume ANSI strings). **No changes to `score`,
`interpret`, or `collect`** (the §12 decoupling invariant). A new `counterspy tui`
subcommand wires it up.

```
counterspy tui [--from <json|->]
   ├─ --from ─▶ decode []model.Assessment
   └─ default ─▶ collectAll → score.Score → interpret.Assess → filterAllowed → []Assessment
                        │
                 tui.Run(assessments) ─▶ tcell screen + event loop
                        │
              quarantine/restore ─▶ act.Quarantine / act.Restore
```

`--from` consumes exactly what `report.RenderJSON` emits. Quarantine from a snapshot is
safe: `plannedActions` derives from the Assessment's evidence, and the actor's own guards
(`refuseUnsafe`, canonical-path, missing-file, occupied-destination) reject a stale or
tampered snapshot rather than acting blindly.

## 4. Components — pure core, tcell at the edge

Mirrors the project-wide discipline (pure logic, I/O at the edge):

- **`Model`** — pure app state: `Assessments []model.Assessment`, `Selected int`,
  `Filter string`, `Sort` (score|rec), `ShowMonitor bool`, `Focus` (list|modal|help|filter),
  `QuarantineRoot string`, transient `Toast string`, and a per-item `Done` set.
- **`update(m Model, ev Event) (Model, []Cmd)`** — a PURE transition: a key event maps to a
  new Model and zero-or-more effect requests (`Cmd`) such as "quarantine finding i" or
  "restore". No I/O in `update`.
- **`view(m Model, s tcell.Screen)`** — draws: summary header (tier counts + gap banner),
  findings table (left, colored by `Recommendation`, Monitor collapsed by default), detail
  pane (right: verdict, deduped evidence with ancestry/argv, planned actions), footer
  keybar + legend, confirm modal (reversibility pinned at top, exact planned actions),
  help overlay, toast.
- **`Run(assessments, act Actor)`** — the ONLY impure unit: init tcell, `PollEvent` loop →
  `update` → execute returned `Cmd`s against an `Actor` interface → `view`. The `Actor`
  interface (`Quarantine`, `Restore`) is satisfied by `internal/act` and stubbed in tests.

## 5. Interaction map (from mockup v2)

`j/k` + ↑/↓ navigate · `enter` expand detail · `q` quarantine (→ confirm modal) · `u`
restore selected · `m` toggle Monitor tier · `s` cycle sort · `/` filter · `?` help ·
`esc` close modal/clear filter · `Q` / `ctrl-c` quit. Color encodes tier (red Quarantine
/ amber Investigate / dim Monitor); the recommendation text is always shown too (not
color-only). Monitor tier collapsed by default. The confirm modal shows the exact
`bootout`/`move` actions and "reversible via restore" before the destructive step.

## 6. Error handling

- **No TTY** (stdout not a terminal / piped): do not launch; print
  "TUI needs a terminal — use `counterspy scan`" and exit non-zero.
- **Collector gaps:** surfaced as the same amber banner the CLI shows (fail-loud; §9).
- **Quarantine error / partial state:** shown in the status line/toast
  ("stopped — partial state recorded in manifest"), never a panic; tcell is restored
  (deferred `screen.Fini()`) so the terminal is never left corrupted.
- **Restore result:** honest messaging — "reloads at next login (or re-enabled now)".

## 7. Testing

- **Pure `update`** — table tests: navigation bounds (can't move past ends), filter
  narrows + resets selection, sort reorders, Monitor toggle, the modal state machine
  (open → confirm emits a Quarantine `Cmd` → Done marked; cancel emits nothing).
- **`view` via `tcell.SimulationScreen`** — drive real key events, assert rendered cells:
  the summary counts, that a Quarantine row renders its tier, that Monitor rows are hidden
  until `m`, that the confirm modal shows the reversibility line.
- **`Actor` stub** — the quarantine/restore effects are tested against a fake Actor
  (records calls), so the flow is verified without touching the filesystem; `internal/act`
  keeps its own round-trip tests.
- No test needs sudo or a live scan — every fixture is a `[]Assessment` JSON.

## 8. Success criteria

1. `counterspy tui --from testdata/snapshot.json` renders the ranked triage view in a real
   terminal; keys navigate and the detail pane tracks selection.
2. Quarantining an item in the TUI calls `act.Quarantine` and reflects Done state; the
   manifest is written; `restore` (in-TUI or CLI) reverses it.
3. The pure `update` and `SimulationScreen` view tests pass without sudo or a live scan.
4. `internal/tui` imports only `model`, `interpret`, `act`, `report` (colors), tcell, and
   stdlib — verified; no `score`/`collect` import, no analysis logic in the TUI.
5. Non-TTY invocation prints the guidance message and does not corrupt the terminal.

## 9. Out of scope (v1 TUI)

- Live auto-refresh / continuous monitoring (snapshot triage only — §12).
- Trend-across-scans history (a v3 idea).
- A WebUI (separate, later; the same `[]Assessment` contract makes it additive).
- Mouse support (keyboard-first; tcell gives mouse for free later if wanted).
