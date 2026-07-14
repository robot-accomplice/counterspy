# Liveness scoring (issue #23) — implementation plan

**Goal:** give findings a liveness dimension — **active** / **armed** / **dormant** — surfaced as a
glyph AND fed into scoring, so a dead persistence remnant (disabled `.bak` + missing target, the
`com.ironclad.agent` case) scores well below a live, loaded agent.

**Key architectural change:** liveness is today **display-only** (`internal/mark` `Classify`, computed
in `main.livenessFor` AFTER interpret) and **2-state** (▸ active / † vestigial). #23 needs it
**3-state** and available at **interpret time** so it can influence `recommend()`. So the run-state
must reach interpret. Reuse the existing run-state source (`collect.CollectRunningPaths`), pass it
into `interpret.Assess`, derive liveness once there, store it on `Assessment`, and have both scoring
and display read that one value (kills the DRY split with `mark.Classify`).

**Glyphs (note):** issue proposed ● ◐ ○, but ● = Apple-trust and ○ = unsigned (collision). Use the
existing liveness family: **▸ active · ◐ armed (new) · † dormant**.

## Tasks (each: implement → test → commit)

1. **model + mark foundation.**
   - `model.Assessment`: add `Liveness string` (`"active"|"armed"|"dormant"|""`).
   - `mark`: add `GlyphArmed = '◐'`; add legend row + regenerate README legend block (sync test).
   - `mark.LivenessGlyph(state string) rune` → ▸/◐/†/0.

2. **Derive liveness in interpret.**
   - `interpret.Assess(findings, running map[string]bool)` (add param).
   - `livenessState(f, running)`:
     - **dormant** — a `KindPersistence` finding whose target is missing/renamed (evidence
       "persistence target is missing/renamed") OR whose plist path is a disabled `.bak` variant.
     - **active** — a `KindProcess` finding, OR a persistence target present in `running`.
     - **armed** — `KindPersistence`, target exists on disk (not missing), not running.
     - else "".
   - Set `Assessment.Liveness`.

3. **Feed scoring.** In `recommend()`: a **dormant** persistence subject caps at `RecMonitor`
   (it cannot execute → low urgency) UNLESS a tripwire fires. Active/armed keep the score-based
   recommendation. (Down-weight the dead; do NOT up-weight the live — avoids false escalation.)
   Update `verdict()` copy to name the state ("dormant remnant — cannot execute").

4. **Wire + display.**
   - `main`: collect running paths once, pass into `interpret.Assess`; drop the now-redundant
     `mark.Classify` run-state derivation (or have `livenessFor` read `Assessment.Liveness`).
   - `internal/report` + `internal/tui`: render the liveness glyph from `Assessment.Liveness`.

5. **Tests (Rule 10).**
   - dormant remnant (missing target + `.bak`) → `Liveness=="dormant"` AND recommendation capped at
     Monitor even at a score that would otherwise Investigate (the ironclad regression).
   - live loaded agent (target running) → `active`, keeps its score-based recommendation.
   - armed (installed, target exists, not running) → `armed`.
   - glyph mapping; legend/README sync.

## Notes
- Reverses the `mark.go:188` "liveness never influences scoring" invariant — record in a decision
  (Architext `dec-liveness-scoring`) and update the `mark` comment.
- `launchctl`-precise "loaded" detection is a follow-up; the MVP uses signals already collected
  (target-missing, `.bak`, running-paths) — the ironclad case is fully covered.
