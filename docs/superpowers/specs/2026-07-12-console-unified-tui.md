# Console — unified TUI (Findings + Exfiltration)

**Date:** 2026-07-12
**Status:** Approved design (pre-implementation)
**Branch:** `feature/console-unified-tui` off `develop`

## 1. Purpose

Today CounterSpy has two separate full-screen apps: `counterspy tui` (findings
triage) and `counterspy egress` (outbound-traffic monitor). They are distinct
tcell programs — separate `Model`/`EgressModel`, separate `Run`/`RunEgress` event
loops, separate screen/signal/fini plumbing in `main.go`. This was meant to be one
interface. This change folds them into a single **`counterspy console`** that
hosts both modes and lets the user switch between them **inside** the running TUI.

## 2. Decisions (locked with maintainer)

- **One command:** `counterspy console`. The `tui` and `egress` subcommands are
  **removed entirely** (no aliases). `--from <snapshot>` (findings triage of a
  scan JSON) carries over to `console`.
- **Two modes, switched with `Tab` / `Shift-Tab`** (KeyTab/KeyBacktab — verified
  unused by both update loops, and filter-capture uses runes, so intercepting Tab
  at the console level never steals a keystroke a mode needs). Cycles
  **Findings ⇄ Exfiltration**.
- **User-facing rename:** the egress mode is presented as **"Exfiltration"** — the
  threat term (data being stolen out) matching CounterSpy's voice
  (quarantine/backdoor/spyware), not the neutral network term "egress". The
  internal `internal/egress` package keeps its name (accurate engineering term for
  the plumbing); only user-facing strings change.
- **Default mode:** Findings (the primary triage flow).
- **Lazy sampling:** the Exfiltration sampler (`nettop`/`lsof`) runs **only while
  Exfiltration is the visible mode** — the ticker starts on switch-to-Exfiltration
  (with an immediate first sample) and stops on switch-away. No background network
  sampling while triaging findings.

## 3. Architecture

New `tui.RunConsole(s tcell.Screen, m Model, actor Actor, sampler Sampler, clip func(string) error) error`
replaces the two loops. It owns:

- `active` mode: `viewFindings` (default) or `viewExfil`.
- `m Model` (findings) and `em EgressModel` (exfiltration), each updated by its
  existing pure `update`/`egressUpdate` and rendered by its existing
  `view`/`egressView`.
- One event loop:
  - **`KeyTab` / `KeyBacktab`** → toggle `active`; on entering Exfiltration, enable
    sampling + request an immediate sample; on leaving, disable sampling; redraw.
  - Otherwise route `EventKey` to the active mode's update (findings Cmds —
    quit/quarantine/restore/label — handled as in `Run`; exfil clipboard as in
    `RunEgress`).
  - `EventInterrupt` (a sample result) → `em = em.withGroups(...)` (ignored/paused
    per existing exfil rules).
  - `nil` event → return.
- **Lazy sampler:** one background goroutine with a ticker; a `sampling atomic.Bool`
  gates whether it calls the blocking `Sample()` (off the UI thread, posting results
  as `EventInterrupt` — the existing pattern). `sampling` is set true/false on mode
  switch. Switching to Exfiltration also posts one immediate sample so the view is
  warm.
- **Mode chrome:** each mode's header shows the active mode and the switch
  affordance (e.g. `Findings ⇄ Exfiltration  (⇥)`), and the footer keeps the
  switch hint. Rendered by threading the active mode into `view`/`egressView`
  (both are now console-only, so their signatures may change freely).

`main.go`:
- `runConsole(flags, stdout)` — one screen/signal/fini setup (merged from the two
  existing ones), builds the findings `Model` (+ `livenessFor`), the `Actor`
  (`cliActor`), and the `Sampler` (`newEgressMonitor`), then calls
  `tui.RunConsole`. Handles `--from` (findings snapshot, read-only) and the no-TTY
  guard (unchanged messaging, now naming `console`).
- Remove the `tui` and `egress` command cases, `runTUI`, and `runEgressTUI`.
- `usage()` documents `console` (and its `--from`) in place of `tui` + `egress`.

## 4. Scope boundaries / non-goals

- No change to the **CLI** report (`scan`), the scoring/interpret pipeline, or the
  static `egress --once/--json` *report* path — those non-TTY egress outputs move
  under `console --once/--json`? **No**: the non-interactive egress report/JSON
  stays reachable; see §5. Findings `scan --json` is unchanged.
- The `internal/egress` package is **not** renamed.
- No new marks/vocabulary; the Task-8 trust glyphs + `+`/`−` tree in the exfil view
  are unchanged.

## 5. The non-TTY egress report/JSON

`counterspy egress --once` / `--json` produced a static report/JSON for
piping/CI. Since `egress` is removed, that output moves to
**`counterspy console --once` / `--json`** in **Exfiltration** context — i.e.
`console` with `--once`/`--json` prints the Exfiltration report/JSON (no live TUI),
mirroring how `scan --json` works for findings. Findings JSON remains `scan --json`.
(Rationale: keep the machine-readable exfil output that existed; just rehome it
under the renamed command.)

## 6. Testing (TDD, no shell-out, ≥80%/pkg)

- `RunConsole` via `SimulationScreen`: starts in Findings (findings chrome shown);
  `Tab` switches to Exfiltration (exfil chrome, sampler enabled — assert via a fake
  Sampler that a sample is requested only after the switch); `Shift-Tab` returns to
  Findings (sampler disabled). A findings action (quarantine via `fakeActor`) still
  works in Findings mode; exfil clipboard still works in Exfiltration mode.
- Lazy-sampling: with a fake `Sampler` counting `Sample()` calls, assert **zero**
  samples while in Findings and samples begin after switching to Exfiltration.
- `main_test`: `console` launches (no-TTY guard path); `tui`/`egress` are now
  `unknown command`; `console --json`/`--once` prints the exfil report without a TTY.
- Existing `Run`/`RunEgress` tests are migrated to `RunConsole` (or removed with the
  functions they covered), preserving their behavioral assertions.

## 7. Quality process (swarm)

Implemented under the swarm: each checkpoint (RunConsole; main wiring + command
removal; docs/README/architext + screenshots) is committed test-first, then an
Antagonist + Audit read-only fan-out reviews the diff before advancing. Ships as
`feature/console-unified-tui → develop`, CI-gated (build+cgo, vet, gofmt,
test --race, ≥80% coverage).
