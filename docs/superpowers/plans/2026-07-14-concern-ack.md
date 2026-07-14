# Concern coloring + revisitable decision flags (issue #4) — implementation plan

**Goal:** make the Findings view legible — (1) a **concern** heuristic (trust × location ×
behavior → minimal/low/notable/elevated) colors rows so the ~300 com.apple Monitor rows recede and
non-Apple/unsigned ones stand out; (2) a local, revisitable **ack** ("reviewed / leave it") that
flags — never hides — a decided finding, re-flagged "reviewed · changed" if the finding changed.

**Confirmed design choices (user):** ack is a SEPARATE local `internal/ack` store (not folded into
the shareable feedback labels; g/b unchanged) bound to a new key `a`. Concern drives **color only**;
sorting by concern is opt-in (added under the existing `s` cycle). Reuse `model.ConcernLevel`
{Minimal,Low,Notable,Elevated} — do not invent a parallel enum.

**Decoupling invariant (hard):** `internal/tui` imports ONLY `model` + `mark` (TestDecouplingInvariant).
So `internal/ack` is imported by **main only**; the TUI receives plain bool maps (`Acked`,
`AckChanged`) and acts through the `Actor` interface (new `Ack`/`Unack`), exactly like quarantine/label.

## Part 1 — Concern heuristic + coloring

1. **model:** add `Concern ConcernLevel` to `Assessment` (types.go; ConcernLevel already in egress.go).
2. **interpret:** `concernOf(f, s signals) model.ConcernLevel`, set in `Assess`. Apple-namespace code
   (label `com.apple.*` or `/System/` path) floors at Minimal unless unsigned. Otherwise a small
   additive score (unsigned +2 / not-accepted +1; tmp|hidden +2 / user +1; listener +2 / connection
   +1; persistence +1; sensitive-TCC +1) → local `concernBand`. Tests pin: Apple system row → Minimal;
   unsigned user-path listener → Notable/Elevated; lone notarized quiet app → Low/Minimal.
3. **tui view:** color Monitor-tier rows by `concernColor(a.Concern)` (Minimal faint → Elevated amber),
   keeping tier color for actionable Q/I rows so the "review me" cue isn't weakened. Add `concernColor`
   to the palette.
4. **tui sort:** extend the `s` cycle to include a by-concern order (opt-in), Model flag.

## Part 2 — ack store + flags

5. **internal/ack:** `Fingerprint(a model.Assessment) string` (sha256 of score + sorted kind|summary,
   12 hex); `Store` (JSON, atomic temp+rename like feedback): `Load`, `Ack(key,fp,at)`, `Unack(key)`,
   `Get(key)`. Tests: fingerprint stable + changes when score/evidence changes; ack/unack round-trips.
6. **main:** `ackPaths()` under `invokingUserHome()/.config/counterspy/ack.json`; load store, build
   `acked`/`changed` maps (changed = stored fp != current Fingerprint(a)); pass into Model; `cliActor`
   implements `Ack`/`Unack` (persist).
7. **tui:** `Model.Acked`, `Model.AckChanged` (bool maps); `update` case `'a'` toggles (emit
   `ack`/`unack` Cmd); `applyFindingsCmd` runs it via Actor + updates the maps; row shows `✓ reviewed`
   or `⟳ reviewed · changed` and recedes (dim); footer + help mention `a`. `Actor` gains `Ack`/`Unack`.

## Verify
- `go test ./...` green; `go vet`; `gofmt`; `TestDecouplingInvariant` passes (no ack import in tui).
- Manual: an Apple Monitor row is faint; an unsigned user listener pops; `a` flags + persists; editing
  the finding's state flips the flag to "reviewed · changed"; `a` again clears it.

## Notes / deferrals
- Fingerprint is score+evidence-shape only (not full facts) — enough to detect a material change; a
  finer fingerprint is a follow-up (Rule 16: deferred for scope, the coarse hash covers the "changed"
  requirement the issue states).
- Concern thresholds are a first cut (Rule 15): pinned by tests at the endpoints, tunable later.
