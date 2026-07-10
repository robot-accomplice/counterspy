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

- No packet capture (destination-name enrichment) — roadmapped v0.4.1.
- **No payload/content inspection** — reading *what bytes* leave requires TLS interception
  (a MITM trust anchor); invasive and spyware-shaped, roadmapped as a far-future, consent-
  gated item. v0.4.0 answers "what is being exfiltrated" by **inference** (capability ×
  egress), never by reading payloads.
- No Network Extension / system extension (a different, entitlement-gated product).
- No persistent cross-session profiling — v1 profiles cadence/volume within the session
  window only; the per-app baseline / consent-delta is the natural follow-on.
- No blocking/filtering of traffic — observe-only.

## Mechanism (settled)

Sudo-CLI observation: poll native tools already available under sudo. No entitlements, no
app bundle, in-architecture. Sees **who → where** and **how much**, not payload contents.
- `nettop -P -L 1 -x` — per-process cumulative bytes in/out (+ per-connection where available).
- `lsof -i -n -P` — current remote endpoints per PID, **with protocol** (TCP/UDP) and port.
- `lsof -p <pid>` (files) + the existing **TCC collector** — the sensitive resources each
  sender can read (screen, keystrokes/accessibility, contacts, photos, mic, camera, full
  disk) and which sensitive files/dirs it currently has open. Feeds the exfiltration
  *inference* (capability × egress) — no payloads read.

## Operating model

`counterspy egress [--interval 2s]`:
- **TTY → live TUI** ("egress top"): continuously refreshing per-app egress, concern-colored.
- **non-TTY → windowed report**: observe a bounded window, print a per-app egress report
  (and `--json`). This falls out of the same pipeline and keeps the command scriptable.

## Data pipeline (mirrors collect → interpret → render)

Every tick (default 2s):

1. **Exec edge** (`internal/egress`, impure): run `nettop` + `lsof`; join TCC grants.
2. **Pure parsers**:
   - `ParseNettop([]byte) map[int]Bytes` where `Bytes{Out, In uint64}` (cumulative).
   - `ParseLsofConns([]byte) map[int][]Conn` where `Conn{Endpoint; Proto string}`
     (established remote peers + protocol; distinct from the existing `ParseLsof` listener
     parser).
3. **Aggregate** (`internal/egress`, pure given inputs), in two levels:
   - Per **connection**: diff nettop vs. the previous sample → out/in **rate**; attach
     destination + protocol.
   - **Group by application** (binary/bundle identity, not PID): collapse every instance
     (multiple helper PIDs) and every connection (multiple ports / protocols / destinations)
     of the same app into one `EgressGroup`. Roll up out-rate/volume, distinct destinations,
     instance count, and the worst-case member trust/concern. Join **provenance + codesign
     trust** and **TCC capabilities** from `internal/collect`. Compute a session **cadence**
     (one-off / bursty / steady / periodic) from the app's out-rate history.
4. **Interpret** (pure): `Concern(EgressGroup) → ConcernLevel` and the exfiltration
   inference `Exfil(EgressGroup) → (ExfilRisk ConcernLevel, Candidate []string)`.

### Types (new, in `internal/model`)

```go
type Endpoint struct { IP string; Port int }

// Conn is one established outbound connection (a constituent of a group; revealed on expand).
type Conn struct {
    PID      int
    Endpoint Endpoint
    Proto    string   // "tcp" | "udp"
    OutRate  uint64
}

// EgressGroup aggregates ALL instances (PIDs) and connections (ports/protocols/destinations)
// of one application into a single collapsible row.
type EgressGroup struct {
    App          string       // application/bundle display name (the group key's display)
    Path         string       // representative on-disk path (provenance)
    Ancestry     string       // e.g. launchd → App → ...
    Trust        string       // "apple" | "notarized" | "signed" | "unsigned" | "unknown"
    Instances    int          // distinct PIDs collapsed into this group
    OutRate      uint64       // summed bytes/sec this interval
    InRate       uint64
    OutTotal     uint64       // bytes since monitor start
    Spark        []uint64     // recent summed out-rate samples (oldest→newest) → sparkline
    Cadence      string       // "one-off" | "bursty" | "steady" | "periodic"
    Destinations []Endpoint   // distinct destinations (summary)
    Conns        []Conn       // constituent connections (shown when the group is expanded)
    Background   bool         // daemon/agent vs. a foreground/user app
    Capabilities []string     // TCC grants: "screen" "keystrokes" "contacts" "photos" "mic" …
    Concern      ConcernLevel
    ExfilRisk    ConcernLevel // exfiltration-risk band (capability × egress)
    Candidate    []string     // INFERRED candidate exfiltrated data categories (never payloads)
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

## Exfiltration inference (capability × egress) — "what is being exfiltrated"

We cannot read TLS payloads, so we infer the *nature* of likely exfiltration by correlating
what an app can **read locally** with what it **sends out**. Pure `Exfil(EgressGroup) →
(ExfilRisk ConcernLevel, Candidate []string)`:

- **Capabilities** come from the existing TCC collector + `lsof` open files: `screen`,
  `keystrokes` (accessibility/input), `contacts`, `photos`, `mic`, `camera`, `messages`,
  `full-disk`.
- **ExfilRisk** rises with (sensitive capability present) × (sustained/periodic outbound
  volume) × (destination trust: raw IP / unfamiliar ↑) × (background daemon ↑). A notarized
  foreground app sending to its own vendor is low even with capabilities; an unsigned
  background daemon holding Screen Recording + Accessibility and steadily uploading to a raw
  IP is **Elevated**.
- **Candidate** names the data categories that *could* be leaving, derived from the
  capabilities that are present (e.g. Screen Recording → "screen"; Accessibility →
  "keystrokes"; Contacts → "contacts"). Always surfaced as **candidates/inference**, never
  as confirmed content — the copy says so ("candidate content, inferred from capability").

This is the honest form of "what is it exfiltrating": *"has screen + keystroke access and is
uploading steadily to a raw IP — candidate content: screen, keystrokes."*

## Live TUI

A new tick-driven model/view/run in `internal/tui` (still imports only `internal/model`;
the decoupling invariant holds). A ticker goroutine samples and `screen.PostEvent`s a
`tick` carrying fresh `[]EgressGroup` into the pure `update`; `view` renders.

**Layout (confirmed): a full-width "top" table + a bottom detail strip** — not the scan
TUI's left/right master-detail. Egress needs several columns and reads as a live-streaming
`top`/`nettop`-style view, so a wide table suits it better than a narrow master pane.

**Rows aggregate by application and collapse by default**: every instance (helper PID) and
every connection (port / protocol / destination) of one app is one line. A `▸` marker shows
a group is collapsible; **Enter / →** expands it to reveal its constituent connections,
**←** collapses. This keeps the default list one-line-per-app while the per-port/protocol
detail is a keystroke away.

```
CounterSpy · Egress
● 1 elevated   ▲ 1 notable   · 3 low   · 42 minimal          sampling 2s · p pause · Q quit
APP / PROCESS      TRUST       OUT↑      RATE      TOP DESTINATION              CONCERN
▾ backuptool       unsigned    840 KB/s  ▁▃▅▇█▆    198.51.100.7:443 raw ip +1  elevated   ← selected
    pid 4821  tcp  198.51.100.7:443     620 KB/s
    pid 4821  tcp  198.51.100.9:443     190 KB/s
    pid 4830  tcp  198.51.100.7:8443     30 KB/s
▸ node ⇢ helper    unsigned    60 KB/s   ▂▃▂▄▃▂    analytics.3rdparty.io +4    notable    (5 instances)
▸ Claude           notarized   1.2 MB/s  ▄▅▄▆▅▇    api.anthropic.com +3        low        (9 instances)
▸ Safari           apple       120 KB/s  ▁▂▁▃▂▁    12 destinations             minimal
  mDNSResponder    apple       3 KB/s    ▁▁▂▁▁▁     local + 2                  minimal
DETAIL — backuptool · 2 instances · 3 connections
  /sbin/launchd → /Users/jon/Library/.hidden/backuptool
  unsigned · no Gatekeeper accept · background daemon · cadence: periodic ~30s
  destinations  198.51.100.7:443  198.51.100.9:443  198.51.100.7:8443  (all raw IP — no DNS)
  volume        out 840 KB/s · 52 MB since start · in 3 KB/s
  can access    screen · keystrokes · full-disk            (TCC grants)
  exfil risk    elevated — candidate content: screen, keystrokes   (inferred from capability)
  concern       elevated — unsigned background daemon, sustained upload to raw IPs
```

- **Whole row tints by concern** (elevated red → notable amber → low gray → minimal very
  dim), so the one row that matters jumps out while Apple/vendor traffic recedes. Reuses
  the existing tcell palette; concern labels are lowercase (cleaner than the scan view's
  ALL-CAPS tiers — a deliberate, noted divergence for this new dimension).
- **RATE sparkline** per app (`▁▂▃▄▅▆▇█`, concern-colored): the ticker keeps a short
  bounded ring buffer of recent summed out-rates per app and passes the sequence in via
  `EgressGroup.Spark`; the pure `view` maps values → block glyphs. Model stays pure.
- **Detail strip** shows provenance, trust, cadence, destinations, volume, the sender's
  **capabilities** (TCC grants), and the **exfil-risk + candidate content** — always framed
  as *inferred from capability*, never confirmed payload.
- Sorted by **out-rate** (biggest talkers up top) by default; `s` cycles sort
  (rate / concern / exfil-risk / app), `/` filter, `p` pause sampling, `j/k`+arrows move the
  selection, **Enter/→ expand · ← collapse**, `Q` quit.
- Sampling is stateless from the Model's view: the ticker owns the previous byte sample
  (for rate diffing) and the per-app spark ring buffer, and passes finished `[]EgressGroup`
  in; the Model holds the latest groups + selection/sort/filter + the **expanded-set**
  (which app rows are open) — keeping `update` pure and `SimulationScreen`-testable.

## Architecture

- **New `internal/egress`**: exec edge + pure parsers + group-by-app aggregate + `Concern`
  + `Exfil` inference. Reuses `internal/collect` proctree/codesign **and TCC** (no second
  process enumerator or privacy-grant reader — DRY).
- **`internal/tui`**: a sibling live view (`egressmodel.go` / `egressview.go` /
  `egressrun.go`) alongside the scan view; imports only `internal/model`.
- **`internal/report`**: a per-app egress report + `--json` for the non-TTY path.
- **`main.go`**: new `egress` subcommand; TTY → live TUI, else report; advertised in usage.

## Destination naming — v1 limit (honest)

`lsof` yields remote IPs; reverse-DNS is best-effort and often unhelpful on cloud IPs. v1
shows `IP:port` + reverse-DNS-if-available + a port→service hint (443→https, …), and says so.
Real SNI/DNS names need the packet-capture path (roadmap v0.4.1).

## Testing

- Pure parsers against captured `nettop` / `lsof` fixtures (real output shapes, incl.
  protocol column).
- Rate-diff logic (two cumulative samples → correct per-interval rate; handles counter
  reset / process exit).
- **Group-by-app aggregation**: multiple PIDs + multiple connections (ports/protocols) of
  one app collapse to a single `EgressGroup` with the right rolled-up rate, distinct
  destinations, instance count, and worst-case trust/concern; the constituent `Conn`s are
  preserved for expand.
- **Cadence** classification (one-off / bursty / steady / periodic) from a rate history.
- `Concern` per rule: expected (notarized → vendor) vs. elevated (unsigned daemon → raw IP).
- **Exfil inference**: capability × egress → `ExfilRisk` + `Candidate` (e.g. screen+keystrokes
  capabilities + sustained raw-IP upload → elevated, candidates "screen","keystrokes"); a
  notarized foreground app with the same capabilities but vendor destination stays low.
- The tick → `update` → `view` loop via `SimulationScreen` with injected sample groups
  (no live network needed), including **expand/collapse** state; decoupling invariant passes.
- Non-TTY report + `--json` shape.

## Sequencing

New minor release **v0.4.0**. Build order (detailed in the plan): model types → egress
parsers (TDD, fixtures) → rate diff → **group-by-app aggregate (+ cadence)** → `Concern` →
**`Exfil` inference (TCC × egress)** → non-TTY report + `--json` → live TUI tick loop
(**+ expand/collapse**) → `main` wiring + usage → docs / architext node / Release Truth / tag.

## Future (roadmap)

- **v0.4.1 packet-capture enrichment** — real destination names (TLS SNI / DNS) + per-flow
  volume via pktap/tcpdump (root, no entitlement). Recorded in `roadmap.json`.
- **Payload / content inspection** (far future, consent-gated) — actually see *what bytes*
  leave, which requires TLS interception (a MITM trust anchor); invasive and spyware-shaped,
  so it stays inference-only until a very high consent bar is met. Recorded in `roadmap.json`.
- **Persistent baseline / consent-deltas** — remember per-app destinations across sessions;
  judge "regularly" over days; flag new destinations ("app X now talks to Y — approve?").
