# CounterSpy — Symbology & Legend Redesign

**Date:** 2026-07-11
**Status:** Approved design (pre-implementation)
**Branch (planned):** `feature/symbology-legend` off `develop`
**Closes:** T-4 (real exec path per PID), #23 (active-vs-vestigial liveness)
**Touches / flags:** PR #25 (native codesign) — trust-mark semantics coupling (see §8)

## 1. Purpose

CounterSpy's report and TUI currently mark findings on a single axis — concern
tier (`⚑`/`▲`/`·`). That hides two things a triager needs at a glance: **how
trusted the code's provenance is** (Apple vs notarized vs merely signed vs
unsigned vs revoked) and **whether the thing is live right now** (running,
holding a socket, or a dormant/vestigial persistence install). This redesign
adds a **trust axis** and a **liveness axis** as monospace glyph marks, renders
them in a uniformly-spaced cluster on every surface, documents the key both
in-app and in the README, and keeps the documented key from ever drifting from
the code via a golden test.

Non-emoji, monospace-safe glyphs only. **Color remains the concern axis** and is
never the sole carrier of trust/liveness (accessibility).

## 2. The vocabulary — three orthogonal axes

| Axis | Carried by | Glyphs (semantic order) | Meaning |
|---|---|---|---|
| **Concern** (tier) | color **+** glyph | `⚑` `▲` `·` | Quarantine / Investigate / Monitor |
| **Trust** (provenance) | glyph | `●` `◆` `◇` `○` `⊘` | Apple / notarized / signed-not-notarized / unsigned / revoked |
| **Liveness** | glyph | `▸` `†` `↔` | active (running) / vestigial (dormant install) / live socket |

Trust is a deliberate **filled → hollow → struck** gradient (`● ◆ ◇ ○ ⊘`) =
monotonically decreasing trust. Liveness: `▸` running (play), `†` dormant/dead
(dagger — a footnote to a past install), `↔` bidirectional network. Glyph choice
is semantically motivated, not arbitrary.

### 2.1 Data → mark mapping (populated from existing collector Facts)

Trust (from `internal/collect/codesign.go`):

| Evidence Facts | Mark |
|---|---|
| `signed:true` + `authority` is Apple (`Apple`, `Software Signing`) | `●` |
| `signed:true` + `authority` present (Developer ID) + Gatekeeper `accepted` | `◆` |
| `signed:true`, no `authority` (signed but not accepted) | `◇` |
| `signed:false` | `○` |
| `signed:revoked` | `⊘` |

Liveness (from the new correlation in §4):

| Condition | Mark |
|---|---|
| Subject correlates to a running process | `▸` |
| Persistence subject whose target is **not** running | `†` |
| Subject holds `listener:true` (LISTEN socket) | `↔` |

`▸` and `↔` can co-occur (a running process that also listens); the cluster
shows both in their fixed slots (see §3).

## 3. Rendering — uniform-cadence cluster (HARD INVARIANT)

The per-finding marks render as a fixed-position cluster of **four slots** —
liveness is two sub-slots (run-state and socket) so `▸` active and `↔` live-socket
can co-occur without breaking cadence:

```
[concern] [trust] [run-state] [socket]
  ⚑/▲/·   ●◆◇○⊘    ▸/†/blank   ↔/blank
```

**Invariant — uniform cadence.** Every slot occupies an identical fixed field,
and a single spacing constant separates every field. An **absent mark renders as
a blank field of the same width** — never omitted, never collapsed. There is
exactly one inter-mark spacing used on every row and every surface. It is never
the case that some clusters are spaced and others packed, or that one row's gaps
differ from another's.

Concretely (four slots, blanks hold their width):

```
⚑ ○ ▸ ↔   /tmp/xmrig               unsigned · running · live socket · LaunchDaemon
▲ ◇ †     ~/Library/…/helper       signed-not-notarized · vestigial (socket blank)
· ●       /Applications/Vendor.app  Apple, not running (run-state + socket blank)
```

### 3.1 Width safety (why this is non-trivial)

Measured East-Asian width of the glyphs: `⚑ ⊘ ▸ + −` are **narrow(1)**;
`▲ · ● ◆ ◇ ○ † ↔` are **Ambiguous** (1 cell in a Latin terminal, 2 in a
CJK/ambiguous-wide locale). Naive concatenation therefore misaligns row-to-row
in an ambiguous-wide terminal. Resolution — **structural fixed-slot cadence, no width library:**

- **One field width** (`markField` = 1 rune) and **one spacing constant**
  (`markGap` = one space), defined once in `internal/mark` and shared by all
  surfaces — no magic literals (project Rule 3). Each slot renders **exactly one
  glyph or one space**, slots joined by exactly one `markGap`.
- **Why no width library:** every glyph in the vocabulary is verified width-1 in
  a Latin terminal (narrow, or East-Asian-Ambiguous which resolves to 1). A
  measurement library (`uniseg`/`go-runewidth`) would **not** help the only case
  that could break — an ambiguous-wide locale — because those libraries also
  report Ambiguous as width 1 by default. So measurement adds a dependency and
  corrects nothing. Cadence is instead guaranteed **structurally** (one cell per
  slot) and **enforced by the golden cadence test** (§9), which also fails loudly
  if a future glyph is genuinely wide (W/F) — the real signal to worry about, and
  one the no-emoji rule already forbids.
- **TUI (`tcell`):** each mark drawn at an explicit column `x` (tcell reserves
  cells per rune); alignment holds by construction.
- **CLI (plain string):** each slot is one rune or one space, joined by
  `markGap`; the golden test asserts every row's cluster is identical width.

## 4. New correlation — T-4 + #23 (display-only)

Persistence evidence is path-keyed (`Subject{Path: target}`); process evidence
is deliberately PID-keyed with no path (the cp-8 anti-spoof-alias hardening). So
a LaunchAgent and its running process are different subject keys and never merge.
To classify active-vs-vestigial we correlate on real exec path:

1. **T-4 — paths referenced by running processes (ESC-1).** Build the set of
   filesystem paths any running process references — its executable AND every
   absolute-path argv token — from `ps -axo pid=,args= -ww`. This supersedes a
   `comm=`/`proc_pidpath` exec-path-only approach, which a swarm review proved
   unreliable: `comm=` follows argv0 (bare `node` never matches), and neither
   handles interpreter-wrapped persistence (`python3 /path/payload.py` — the T-7
   case, where the payload is an argv token, not the exec path). Argv correlation
   is sound here because liveness is DISPLAY-ONLY: a spoofed argv only mislabels a
   glyph, never suppresses a finding or changes a score. Parser is pure/tested;
   the `ps` call is the untested I/O edge. Known edge: space-containing paths are
   whitespace-split by `ps` and won't match as a single token.
2. **#23 — liveness classifier.** A **pure** function
   `Liveness(subjects, runningPaths) -> map[Subject.Key]LivenessMark`:
   - persistence subject whose `target` ∈ runningPaths → `▸ active`
   - persistence subject whose `target` ∉ runningPaths → `† vestigial`
   - subject with `listener:true` → `↔ live socket` (additive)

**Scope guard (YAGNI / do-not-perturb):** liveness is **display-only** this pass.
It feeds the glyph, **not** the scorer. The scorer's weights were carefully tuned
(cp-14) and are not touched here. Making vestigial-vs-active influence *scores* is
a separate, deliberate future tuning pass, out of scope (Rule 16: deferred because
it would perturb a tuned, verified scorer with no current requirement to do so).

## 5. Surfaces

- **CLI report** (`internal/report/report.go`): the cluster replaces the bare
  `glyph()`; summary tier counts switch from `●/▲/·` to `⚑/▲/·` to match the
  per-finding tier glyphs (see §6, collision 1). Color still gates on
  `color bool` from the tty — pure core, no tcell.
- **TUI findings table** (`internal/tui/view.go`): a cluster column; the
  `⚑`/`▲` summary already present.
- **Egress view** (`internal/tui/egressview.go`): the existing `Trust` text field
  becomes a trust glyph; tree toggle changes from `▸`/`▾` to **`+`/`−`** (see §6,
  collision 2).

## 6. Collision resolutions

1. **`●` (Apple) vs `●` (Quarantine count).** Today the summary header uses `●`
   for the Quarantine *count* while per-finding uses `⚑` — a pre-existing
   inconsistency. Fix: summary counts use the tier glyphs `⚑`/`▲`/`·`. This frees
   `●` for Apple-trust and makes summary/detail consistent.
2. **`▸` (active) vs `▸` (tree-expand).** The egress tree toggle becomes `+`/`−`
   (a universal disclosure idiom that needs no legend entry), freeing `▸`
   exclusively for the liveness "active" mark.

## 7. Legend & documentation (one source of truth, drift-proof)

- **Single Go definition:** a `Legend` table — `[]{glyph, axis, meaning}` — is the
  one source of truth for the vocabulary.
- **In-app:** the TUI `?` overlay and the CLI one-line footer **render from that
  table** (not hand-written strings). CLI footer is suppressed under `--json`.
- **README:** a new **"Reading the marks"** section documents all three axes — the
  canonical user-facing key.
- **Drift-proof golden test:** asserts the README key block matches a from-code
  rendering of `Legend`. A glyph can never exist in the app without a documented
  meaning, nor the docs describe a mark the app doesn't emit.
- **Honest legend:** the legend renders only marks the data can fill.

## 8. PR #25 coupling (flagged, not resolved here)

PR #25 (native Security.framework codesign) shifts `accepted` from
*Gatekeeper-notarized* to *signature-valid-in-process*, which would blur the
`◆ notarized` / `◇ signed-not-notarized` line. This redesign **makes that nuance
visible** but does not decide it. The trust mapping in §2.1 is written against
current `develop` (spctl-accepted) semantics. If PR #25 merges, the §2.1 mapping
must be revisited so `◆` still means "notarized/Gatekeeper-accepted," not merely
"signature parses." This is a human decision Jon has flagged; recorded here so the
coupling is explicit.

## 9. Testing (TDD, ≥80%/package, no shell-out)

- **Trust classification** table test: `(authority, accepted, signed)` → glyph.
- **Liveness classifier** test: active / vestigial / live-socket from fixtures
  (persistence targets × running-path set × listener facts).
- **T-4 path resolution:** fallback path parsing tested against `ps` fixtures; the
  `proc_pidpath` syscall edge is an untested I/O boundary (documented), the parser
  is pure and tested.
- **Uniform-cadence golden test:** across fixtures exercising every glyph, assert
  every rendered row's mark-region is the same display width **and** the inter-mark
  gaps are identical (cadence, not just total width). TUI `SimulationScreen` test
  asserts the label column starts at an identical `x` on every row.
- **Legend drift golden test:** README key block == from-code `Legend` render.
- **NO_COLOR / `--json`** paths: marks present without color; footer omitted under
  `--json`.

## 10. Scope boundaries / non-goals

- Liveness does **not** affect scoring (§4 scope guard).
- No new emoji; glyphs only.
- **Ambiguous-wide terminal locales** (CJK setups where Ambiguous glyphs render
  2 cells) are a documented edge: CLI cadence assumes ambiguous = 1 cell (the
  Latin-terminal majority); the TUI is unaffected (tcell measures per-cell). A
  width library wouldn't fix this (it also treats Ambiguous as 1), so no
  dependency is added; not worth a config knob for this audience now (Rule 16).
- PR #25 semantics not decided here (§8).
- No unrelated refactor of the scorer, collectors, or TUI event loop beyond the
  render/correlation surface named above.

## 11. Quality process (swarm)

Implemented under the `orchestrator+subagents` swarm: each reviewable unit is
committed, then a read-only **Antagonist + Audit** subagent fan-out reviews the
`git diff`, findings are voted, RCA is spawned on any confirmed failure, and only
then does the work advance — shipped as a gitflow branch → PR → `develop`, CI-gated
(build/vet/gofmt/`test --race` + ≥80% coverage). No `spawn_task` chips (that would
create a second writer, violating the single-writer rule).
