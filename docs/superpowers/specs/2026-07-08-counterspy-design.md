# CounterSpy — Design Spec

**Date:** 2026-07-08
**Status:** Approved for planning
**Author:** Jon + Claude (brainstorming session)

## 1. Purpose

CounterSpy is a macOS command-line tool that identifies suspicious, spyware-like
activity on a Mac, and — with per-item human approval — **isolates** it by disabling
its persistence and moving it to a reversible quarantine. It never permanently
deletes and never acts without consent.

The core problem is **triage, not signature-matching**: macOS spyware almost always
reveals itself through *persistence* (LaunchAgents/LaunchDaemons), *privilege*
(TCC grants like Accessibility / Screen Recording / Input Monitoring / Full Disk
Access), *identity* (unsigned / non-notarized binaries), and *behavior* (unexpected
processes and network listeners). CounterSpy gathers these signals, correlates them
against the same subject, and ranks what to look at.

## 2. Scope

### In scope (v1)
- Four evidence collectors: persistence, code-signing/notarization, TCC grants,
  process-tree + network.
- A **pure** weighted scoring engine with a correlation multiplier, a known-good
  allowlist, and hard "always-surface" tripwires.
- Read-only ranked report (default) and a `--json` machine-readable form.
- Interactive, per-item quarantine (disable + move) with a `manifest.json`.
- One-command restore (undo) from a manifest.

### Non-goals (v1)
- **No permanent deletion.** Quarantine only moves files. Deletion is a separate,
  explicit, human step outside this tool. *Deferred because:* irreversible destruction
  on a false positive is the single worst failure mode; move-only makes every action
  undoable. (Rule 16 justification.)
- **No baseline-diff detection.** Rejected for v1 because the user may already be
  infected, so a "known-clean" baseline would bake spyware in as normal.
- **No real-time daemon / continuous monitoring.** v1 is an on-demand scan.
- **No kernel extension / ESF event stream.** Userland tools only.

## 3. Constraints (locked)

- **Name:** CounterSpy. Binary `counterspy`, Go module `counterspy`.
- **Location:** `~/code/counterspy/`.
- **Language:** Go (single compiled binary; shells out to native macOS CLI tools for
  OS-specific evidence).
- **Automation posture:** quarantine-with-approval. `scan` is read-only; mutation
  requires `--interactive` **and** per-item `y`.
- **Privileges:** runs under `sudo` for full visibility. SIP still protects
  `/System/Library`, which is a desired safety limit, not an obstacle.
- **Construction methodology (bound at implementation):**
  - *clean-architecture* — dependency rule enforced: `model` at the center; collectors
    and actors on the outside; the scorer is pure and depends on nothing.
  - *clean-code* — small functions, intention-revealing names, **no magic numbers**
    (all weights/thresholds are named constants in `score/weights.go`).
  - *test-driven-development* — red→green→refactor; the pure scorer is written
    test-first from fixtures.
  - *architext* — generate LLM-ready architecture docs into `docs/architext/` after
    the spec, before/with the build.
  - *swarm* — the implementation vehicle (single-writer Coding session + Antagonist /
    RCA / Audit / Scribe reviewers). Stood up **after** spec + plan exist, because the
    reviewers need a plan to critique. Well-motivated here: the Antagonist and Audit
    roles exist to hammer the destructive code paths and reversibility.

## 4. Architecture

Strict three-phase pipeline; phases do not interleave:

```
COLLECT (read-only)      SCORE (pure)          ACT (mutating, consented)
  persistence  ─┐
  codesign      ├─▶  []Evidence ─▶ scorer ─▶ []Finding ─▶ interactive quarantine
  tcc           │    (group by      (weights +   (sorted    + manifest.json
  proctree+net ─┘     subject)       tripwires)   by score)   (undo + RCA trail)
```

- **COLLECT** — each collector is `Collect(ctx) ([]Evidence, error)`, no
  cross-dependencies, no judgments, no mutation. Shells out to `launchctl`,
  `codesign`, `spctl`, `sqlite3` (TCC db), `ps`, `lsof`.
- **SCORE** — a pure function `[]Evidence -> []Finding`. No I/O. The entire brain is
  unit-testable with fixtures and carries zero runtime risk.
- **ACT** — the only phase that touches the system. Interactive; every action is
  reversible.

### Layout
```
counterspy/
  main.go                     # flags, orchestrates the 3 phases
  internal/
    model/types.go            # Evidence, Finding, Subject, Action, Manifest
    collect/
      persistence.go
      codesign.go
      tcc.go
      proctree.go             # process forest + argv + network join
    score/
      score.go                # pure scorer (TDD centerpiece)
      weights.go              # ALL weights + thresholds + tripwires as named consts
      allowlist.go            # known-good signing authorities
    act/
      quarantine.go           # bootout + move + manifest
      restore.go              # undo from a manifest (ships in v1)
    report/
      report.go               # human ranked report + --json
  testdata/                   # fixtures: recorded CLI output + scorer cases
  docs/architext/             # generated architecture docs
```

## 5. Shared model (the one vocabulary)

```go
type SignalKind string // "persistence" | "codesign" | "tcc" | "process"

type Subject struct {
    Path  string // on-disk binary/plist if known
    PID   int    // live process if any
    Label string // e.g. com.evil.updater
}

type Evidence struct {
    Subject Subject
    Kind    SignalKind
    Summary string            // "unsigned binary", "holds Screen Recording"
    Weight  int
    Facts   map[string]string // exact captured detail for the RCA trail
}

type Finding struct {
    Subject  Subject
    Score    int
    Kinds    []SignalKind     // distinct signal types → correlation bonus
    Evidence []Evidence
    Tripwire string           // non-empty if a hard always-surface rule fired
    Actions  []Action         // what quarantine WOULD do (shown before y/n)
}

// A single reversible operation the actor will perform, in order.
// Kind is e.g. "bootout" | "move"; From/To are absolute paths.
type Action struct {
    Kind string
    From string
    To   string
}
```

## 6. Collectors

- **persistence.go** — walk LaunchAgents/LaunchDaemons in `~/Library`, `/Library`,
  `/System/Library`. Per plist extract `Label`, `ProgramArguments[0]` (target binary),
  `RunAtLoad`, `KeepAlive`. Emit evidence for hidden paths, user-level agents, and
  plists whose target is missing/renamed.
- **proctree.go** — build the **full process forest** from
  `ps -axo pid,ppid,user,lstart,command`; link each PID to its parent up to `launchd`
  (pid 1); capture **argv** (reveals the executed script, e.g.
  `python3 ~/Library/.../beacon.py`). Join `lsof -i -nP` listeners/established
  connections back to the owning PID so a listener is reported as its **whole
  ancestry**, never a lone PID. *(This process-provenance requirement is explicit: a
  rogue `python3` is only meaningful together with what spawned it and which script it
  runs.)*
- **codesign.go** — per subject path: `codesign --verify`, `spctl --assess`, extract
  signing authority. Unsigned / ad-hoc / revoked → weight; authority checked against
  `allowlist.go`.
- **tcc.go** — read user + system TCC databases for Accessibility, Screen Recording,
  Input Monitoring, Full Disk Access, keyed to app path so grants correlate with the
  other signals (e.g. Input Monitoring + Accessibility = keylogger shape).

## 7. Scoring model (Approach A — weighted + correlation + tripwires)

- Each `Evidence` contributes named-constant points (e.g. unsigned, hidden path,
  Input Monitoring, outbound to raw IP, parent-is-LaunchAgent).
- The scorer groups all evidence by `Subject` (match on Path, then PID), sums weights,
  and applies a **correlation multiplier** when ≥2 *distinct* `Kinds` (default,
  tunable in `weights.go`) hit the same subject — "one story told four ways."
- **Allowlist** suppresses known-good signing authorities (Apple + vendors the user
  actually runs) to kill obvious noise.
- **Tripwires** are hard rules that force a finding to surface regardless of score
  (e.g. *unsigned* AND *has persistence* AND *network listener*). They set
  `Finding.Tripwire` and never auto-act — they only guarantee visibility.

## 8. CLI surface & data flow

```
sudo counterspy scan                  # collect → score → ranked report (READ-ONLY)
sudo counterspy scan --interactive    # then walk findings top-down: y/n/skip/quit
sudo counterspy scan --json           # machine-readable (feeds architext/CI/tooling + the release gate)
sudo counterspy restore <manifest>    # undo a prior quarantine
```

`scan` alone never mutates. Interactive mode prints each finding as its **evidence
story** (ancestry chain, signature verdict, TCC grants, listener) with its score and
the **exact `Actions`** quarantine would take, then asks per item.

## 8.1 Synthesis & recommendations (never a raw evidence dump)

CounterSpy must not merely list everything it collected — it must **repackage** the
scored, correlated findings into something a human can act on. A pure `interpret` step
(no I/O; annotates `Finding`s) sits between `score` and `report`:

- **Verdict** — one plain-language sentence composed from the subject's combined
  signals, e.g. "unsigned binary holding Input Monitoring + Accessibility, launched by
  a hidden LaunchAgent, listening on :4444."
- **Category** — a heuristic label from the signal mix: `keylogger` (Input Monitoring
  + Accessibility), `backdoor` (unsigned + listener + persistence), `spyware-generic`,
  `persistence-only`, `unknown`.
- **Recommendation** — an enum derived from tier + tripwire + mix:
  `Quarantine` (tripwire, or high tier with an actionable target) · `Investigate`
  (mid band) · `Monitor` (low/single weak signal). Allowlisted subjects are suppressed,
  never shown.

The report leads with an **executive summary** (counts per recommendation tier) and
then the ranked findings, each as its verdict + recommendation + the evidence story
that supports it — highest-priority first, low-signal noise omitted. This synthesis is
**rule-based/deterministic** (Rule 6 — code, not the model, so verdicts are
reproducible and auditable by the §11 ABORT gate) and lives in the core so the CLI and
any future TUI/WebUI render the *same* recommendations (the §12 decoupling invariant).

## 9. Error handling & safety (Rule 13 — fail loud, never fail dangerous)

- A collector that errors (e.g. `lsof` denied) is reported as a **gap in the report**
  ("network signal unavailable — findings may be incomplete"), never swallowed.
  Missing evidence must never read as "clean."
- **Quarantine is transactional + reversible:** (1) `launchctl bootout` to stop
  respawn, (2) `mv` plist + target binary into `~/CounterSpyQuarantine/<ts>/`,
  (3) write `manifest.json` (original absolute paths, signatures, timestamps, ordered
  actions). On mid-way failure: stop and report partial state; do not leave a
  half-quarantined item.
- **Hard refusals:** never act on Apple-signed-and-allowlisted items; never touch
  `/System/Library` (SIP enforces this too); never delete — only move.
- **`manifest.json` is the RCA trail (Rule 14):** exact observed + done, in order,
  captured bytes — explainable and undoable.

## 10. Testing (TDD)

- **Scorer (test-first, the heart):** `Evidence` fixtures in `testdata/` →
  asserted `Finding` scores/order. Cases: single-signal weights, correlation
  multiplier, each tripwire, allowlist suppression. Tests encode *why* a combo is
  dangerous (Rule 10), not just arithmetic.
- **Collectors:** parse **recorded fixture output** of the real CLI tools
  (captured `ps`/`lsof`/`codesign`/plist/TCC blobs → parser → expected `[]Evidence`).
  No live spyware required.
- **Actor:** temp-sandbox dir with fake plists/binaries; **quarantine→restore must
  round-trip to a byte-identical tree**. This round-trip is the safety guarantee.

## 11. Final release gate — ABORT go/no-go

Before CounterSpy is made public, run the `/abort` skill: a disciplined GO/NO-GO
review that assumes the ship fails, red-teams it from five independent adversarial
lenses, ranks the failure modes, and forces an explicit verdict with a confidence
score and convertibility conditions. It is judgment layered **on top of** the
mechanical gate (`go test ./...`, `go vet`), not a replacement for it.

**Decision under review (to pin at gate time):** "Publish `counterspy` <version> as a
public tool that, under sudo, quarantines user-selected persistence/process items on
third parties' Macs." Blast radius: a false positive moves a legitimate item on a
stranger's machine — reversible via `restore`, but still disruptive. This blast
radius is exactly what ABORT's Attacker / Worst-Case-Customer / Domain-Integrity
lenses must hammer.

**Inputs the build guarantees ABORT (so it red-teams from evidence, not plausibility):**
- the real diff at a tagged commit + green mechanical gates (tests, vet);
- a written **threat model** (what CounterSpy defends against and explicitly does not);
- the **false-positive story** (allowlist + move-not-delete + `restore` round-trip test);
- **reproducible evidence** (`--json` output + `manifest.json` schema).

**Artifact:** ABORT writes its verdict to `docs/releases/<version>-abort.md` (that dir
is created at ship time). A NO-GO lists explicit convertibility conditions; met
conditions get appended as a `## Closure` section.

*Deferred to end-of-build because ABORT needs a finished artifact and real state to
judge — running it against this spec would produce the vague, evidence-free verdict
the skill itself forbids (Rule 16 justification). Recorded here as a committed exit
criterion.*

## 12. Future scope (post-v1, not built now)

Once the CLI engine is proven effective, likely additions — **reporting faces**, not
new logic:

- **TUI** (e.g. Bubble Tea) — interactive triage/quarantine over the same findings.
- **WebUI** — at least a reporting dashboard consuming the `--json` output.

*Deferred because the engine (collectors + pure scorer) is the risky, must-be-correct
part; UIs are low-risk and only worth building once the core is trusted (Rule 16
justification). Not started in v1.*

**Design invariant that keeps this cheap:** presentation logic must never leak into
`score` or `collect`. The scorer stays a pure `[]Evidence → []Finding`; every UI
(CLI, TUI, WebUI) is an outer-ring consumer that renders `model.Assessment` / the
`--json` form and depends inward only. Adding a UI later must require **zero** changes
to the core. The swarm's Audit role enforces this boundary.

**TUI design direction (post-v1).** Model it as an **interactive triage view**, not a
monitoring dashboard. `btm`/`bottom` is the reference for *interaction* quality —
master–detail layout, at-a-glance summary header, color that encodes meaning,
sortable table, keyboard-driven — but NOT for *metaphor*: CounterSpy is snapshot+act,
not a live resource monitor, so we deliberately DROP btm's sparkline time-series and
resource panels (they'd be decoration masquerading as signal — the opposite of §8.1).
Layout: left = the ranked `Assessment` table (sortable, colored by `Recommendation`,
Monitor-tier collapsed by default); right = the selected finding's verdict + evidence
story + the *exact* planned quarantine actions; footer = keybindings. The action
dimension (select → quarantine with confirm → restore) is CounterSpy-specific and has
no btm analog. Every action routes through the same `interpret`/`act` core the CLI
uses — the TUI adds interaction, never analysis.

**Ligature support (TUI requirement).** The TUI must render well when the user's
terminal font has programming ligatures (Fira Code, Cascadia Code, JetBrains Mono,
Monaspace, …) and remain fully readable when it doesn't. Terminals do not expose font
capabilities to the app, so this is achieved by *composition, not detection*:
- Compose text from **ASCII digraphs that ligate** — `->` for ancestry/flow arrows
  (not a hardcoded `→`), `>=`/`<=`/`!=`/`=>` where a comparison or mapping is shown —
  so a ligature font beautifies them and a plain mono still reads them literally.
- **Never split a digraph across two color runs.** ANSI color escapes inserted between
  the `-` and `>` prevent the font from forming the ligature, so the styling layer must
  color whole tokens; a digraph is always emitted inside a single styled span. This is
  the "style accordingly" discipline — a constraint on where color boundaries fall.
- Box-drawing (panel borders) uses Unicode box chars, which ligature fonts render fine;
  that is orthogonal to digraph ligatures.
- Provide `--glyphs=ascii|unicode` (default `ascii` digraphs) as an escape hatch for
  users who want to force real Unicode glyphs or plain ASCII.
The HTML mockup opts into ligatures via `font-feature-settings:"calt","liga"` and uses
`->` digraphs to demonstrate the intent (it can't bundle a ligature font — CSP blocks
font CDNs — so it ligates only where the viewer's own mono does).

## 13. Success criteria

1. `sudo counterspy scan` produces a ranked, correlated report on a real Mac without
   mutating anything.
2. The scorer's behavior is fully specified by passing fixture tests written before
   its implementation.
3. A planted fake persistence+unsigned+listener sample surfaces via tripwire and
   ranks at the top.
4. `quarantine` → `restore` round-trips to a byte-identical tree in the actor sandbox
   test.
5. No action is ever taken on an Apple-signed/allowlisted or `/System/Library` item.
6. Every collector failure appears as an explicit gap in the report, never as silence.
