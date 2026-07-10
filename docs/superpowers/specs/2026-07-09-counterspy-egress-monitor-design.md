# CounterSpy — Egress Monitor (v0.4.0) — Design

**Status:** approved (brainstorm), ready for implementation planning
**Date:** 2026-07-09
**Depends on:** v0.3.0 (feedback loop) architecture; reuses `internal/collect` (proctree, codesign) and the `internal/tui` pure-`update`/`view`/`Run` pattern.

## Problem

CounterSpy answers "is this app spyware?" — but the complementary risk is the apps it
*doesn't* flag: notarized, allowlisted software that is nonetheless over-collecting. The
egress monitor answers the second question — **"this app is trusted; what is it sending,
where, and how much?"** — as a live, per-app view of outbound traffic through CounterSpy's
trust and provenance lens.

## Non-goals (v0.4.0)

- No packet capture / payload inspection (roadmapped as v0.4.1 for real SNI/DNS names).
- No Network Extension / system extension (a different, entitlement-gated product).
- No baseline / consent-delta ("new destination since last time") — natural v0.4.1 follow-on.
- No blocking/filtering of traffic — observe-only.

## Mechanism (settled)

Sudo-CLI observation: poll native tools already available under sudo. No entitlements, no
app bundle, in-architecture. Sees **who → where** and **how much**, not payload contents.
- `nettop -P -L 1 -x` — per-process cumulative bytes in/out.
- `lsof -i -n -P` — current remote endpoints per PID.

## Operating model

`counterspy egress [--interval 2s]`:
- **TTY → live TUI** ("egress top"): continuously refreshing per-app egress, concern-colored.
- **non-TTY → windowed report**: observe a bounded window, print a per-app egress report
  (and `--json`). This falls out of the same pipeline and keeps the command scriptable.

## Data pipeline (mirrors collect → interpret → render)

Every tick (default 2s):

1. **Exec edge** (`internal/egress`, impure): run `nettop` + `lsof`.
2. **Pure parsers**:
   - `ParseNettop([]byte) map[int]Bytes` where `Bytes{Out, In uint64}` (cumulative).
   - `ParseLsofConns([]byte) map[int][]Endpoint` where `Endpoint{IP string; Port int}`
     (established remote peers; distinct from the existing `ParseLsof` listener parser).
3. **Aggregate** (`internal/egress`, pure given inputs): diff nettop vs. the previous
   sample → out/in **rate**; join destinations; join **process-tree provenance + codesign
   trust** from `internal/collect` (app name, path, ancestry, signed/notarized). Produce one
   `EgressRow` per process.
4. **Interpret**: a pure `Concern(EgressRow) → ConcernLevel`.

### Types (new, in `internal/model`)

```go
type Endpoint struct { IP string; Port int }

type EgressRow struct {
    PID          int
    App          string       // process/bundle display name
    Path         string       // on-disk path (provenance)
    Ancestry     string       // e.g. launchd → App → ...
    Trust        string       // "apple" | "notarized" | "signed" | "unsigned" | "unknown"
    OutRate      uint64       // bytes/sec this interval
    InRate       uint64
    OutTotal     uint64       // bytes since monitor start
    Conns        int
    Destinations []Endpoint
    Background   bool         // daemon/agent vs. a foreground/user app
    Concern      ConcernLevel
}

type ConcernLevel int // Minimal, Low, Notable, Elevated
```

## Egress concern heuristic

Pure, rule-based, deterministic (Rule 6). Inputs are signals we already have plus the new
egress data. First strong match wins; otherwise combine:

- **Sender trust** — unsigned/unknown ↑; Apple/notarized ↓.
- **Destination** — raw IP with no resolvable name ↑; many distinct destinations ↑; a
  resolved name whose registrable domain matches the sender's vendor ↓ (expected). This
  last rule is **best-effort and name-dependent**: in v1 most destinations are bare IPs
  (no name), so it simply doesn't fire then — it never *raises* concern, only lowers it
  when a matching name is actually present. (Fully realized by the v0.4.1 pcap path.)
- **Volume × nature** — sustained high outbound from a **background daemon** ↑↑ (a quiet
  uploader); the same from a foreground app you're using ↓ (expected).
- **Directionality** — heavily upload-skewed (out ≫ in) ↑.

`Background` is determined deterministically: a process is **foreground** if its executable
path lies within a `.app/Contents/MacOS/` bundle (a GUI-app proxy), otherwise **background**
(daemon/agent/helper). Rough but deterministic and testable; refineable later (e.g. Aqua
session membership).

Buckets: **Elevated** (e.g. unsigned background daemon, large upload, raw IP) → **Notable**
→ **Low** → **Minimal** (Apple/vendor-domain, expected). This is what makes
`Claude → api.anthropic.com` read *expected* while `.hidden/backuptool → raw-IP` reads
*elevated*.

## Live TUI

A new tick-driven model/view/run in `internal/tui` (still imports only `internal/model`;
the decoupling invariant holds). A ticker goroutine samples and `screen.PostEvent`s a
`tick` carrying fresh `[]EgressRow` into the pure `update`; `view` renders.

```
CounterSpy · Egress          ▲ 1 elevated  2 notable      sampling 2s   p pause · Q quit
  APP / PROCESS            TRUST       OUT↑        TOP DESTINATION            CONCERN
▎ com.acme.backuptool      unsigned    840 KB/s    198.51.100.7:443 (raw IP)  ELEVATED
  Claude                   notarized   1.2 MB/s    api.anthropic.com:443 (+3) expected
  Safari                   Apple       120 KB/s    12 destinations            low
DETAIL — com.acme.backuptool
  /sbin/launchd → /Users/.../.hidden/backuptool   unsigned, no Gatekeeper accept
  destinations:  198.51.100.7:443 · 198.51.100.9:443  (raw IP, no DNS)
  out 840 KB/s (52 MB since start) · in 3 KB/s · 2 conns · background daemon
```

- Sorted by **out-rate** (biggest talkers up top) by default; `s` cycles sort
  (rate / concern / app), `/` filter, `p` pause sampling, arrows + detail pane, `Q` quit.
- Rows concern-colored; reuse the existing tcell palette and provenance rendering.
- Sampling is stateless from the Model's view: the ticker owns the previous sample for
  rate diffing and passes finished `EgressRow`s in; the Model just holds the latest rows +
  selection/sort/filter (keeps `update` pure and `SimulationScreen`-testable).

## Architecture

- **New `internal/egress`**: exec edge + pure parsers + aggregate + `Concern`. Reuses
  `internal/collect` proctree/codesign (no second process enumerator — DRY).
- **`internal/tui`**: a sibling live view (`egressmodel.go` / `egressview.go` /
  `egressrun.go`) alongside the scan view; imports only `internal/model`.
- **`internal/report`**: a per-app egress report + `--json` for the non-TTY path.
- **`main.go`**: new `egress` subcommand; TTY → live TUI, else report; advertised in usage.

## Destination naming — v1 limit (honest)

`lsof` yields remote IPs; reverse-DNS is best-effort and often unhelpful on cloud IPs. v1
shows `IP:port` + reverse-DNS-if-available + a port→service hint (443→https, …), and says so.
Real SNI/DNS names need the packet-capture path (roadmap v0.4.1).

## Testing

- Pure parsers against captured `nettop` / `lsof` fixtures (real output shapes).
- Rate-diff logic (two cumulative samples → correct per-interval rate; handles counter
  reset / process exit).
- `Concern` per rule: expected (notarized → vendor) vs. elevated (unsigned daemon → raw IP);
  boundary cases.
- The tick → `update` → `view` loop via `SimulationScreen` with injected sample rows
  (no live network needed); decoupling invariant still passes.
- Non-TTY report + `--json` shape.

## Sequencing

New minor release **v0.4.0**. Build order (detailed in the plan): model types → egress
parsers (TDD, fixtures) → aggregate + rate diff → `Concern` → non-TTY report + `--json` →
live TUI (tick loop) → `main` wiring + usage → docs / architext node / Release Truth / tag.

## Future (roadmap)

- **v0.4.1 packet-capture enrichment** — real destination names + per-flow volume via
  pktap/tcpdump (root, no entitlement). Recorded in `roadmap.json`.
- **Baseline / consent-deltas** — remember per-app destinations; flag new ones
  ("app X now talks to Y — approve?").
