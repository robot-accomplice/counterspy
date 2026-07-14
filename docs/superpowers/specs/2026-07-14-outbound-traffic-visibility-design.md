# Outbound traffic visibility & control — design

**Status:** approved for Phase 1 (brainstormed 2026-07-14). Phases 2–3 recorded as roadmap.

## Framing

CounterSpy today answers *"this app is trusted — what is it sending, and where?"* by **inference**:
destinations + volume + capability×egress candidates, never by reading payloads. This program moves
it from inference toward **direct revelation** of outbound content, and ultimately toward **control**
over it.

A deliberate stance the maintainer set during brainstorming: **these are all user-driven capabilities
running on the user's own hardware, looking at the user's own data.** Invasiveness/privacy are not
gating concerns here — every capability is gated behind the user's own explicit, per-run choice. What
we hold onto is *engineering* rigor: never corrupt traffic, make any trust-anchor install auditable
and reversible **as a feature**, and never fabricate output (show what we actually observed, mark the
gaps). This intentionally revises the earlier "we deliberately don't decrypt" posture — that honesty
principle now means *"reveal everything we truthfully can, and be honest about what we can't,"* rather
than *"don't try."*

This crosses one current invariant, and only in the final phase: the network path is **observe-only**
today (`TestEgressOnly`, "never remotely steerable"). Phase 3's proxy adds **active control** (redact
/ block outbound traffic), converting CounterSpy from passive triage into an active egress-control /
DLP tool. That is an intended redefinition, sequenced last so the passive-visibility foundation ships
first.

**Standing constraint:** no new command-line option/flag may be added without the maintainer's
explicit approval. Prefer automatic behavior on existing commands and existing TUI keybindings. Phase
1 introduces **no** new CLI options; any control surface a later phase needs (e.g. `--decrypt`,
`--proxy`) must be proposed and approved before implementation.

## The three phases

| Phase | Capability | New substrate | Observe-only? |
|---|---|---|---|
| **1 — Passive reveal** | Destination **names** (passive DNS) + **maximal cleartext extraction** in the on-demand inspector. | Continuous port-53 pcap + a shared, filter-parameterized bpf capture; a name cache; a cleartext decoder. | Yes |
| **2 — Key-log decryption** | Capture TLS session secrets apps export via `SSLKEYLOGFILE`; decrypt those flows from the pcap. No CA, no MITM. | Key-log reader + record decryptor layered on the Phase-1 capture. | Yes |
| **3 — Transparent proxy** | Consented root-CA MITM → broad TLS decryption, **plus active control**: redact sensitive fields from outbound payloads and/or block transmissions. | Local intercepting proxy, installable/reversible trust anchor, redaction+block rule engine. | **No — active control** |

Each phase reuses the prior phase's capture layer; revelation and capability rise together.

---

# Phase 1 — Passive reveal (detailed design)

**Goal:** show the **name** an app actually contacted (not a bare cloud IP) throughout the Exfiltration
views, and **decode as much cleartext content as possible** for a flow the user inspects — all without
any decryption.

## Scope

**In:**
- **Destination names.** A continuous passive **DNS-response** capture (UDP/TCP port 53) builds an
  `IP → hostname` cache. When the egress monitor builds a group's destinations, each `Endpoint` is
  annotated with the name the app resolved (e.g. `analytics.example.com`). Shown as `name (ip)` in the
  tree, zoom, and inspect header.
- **Maximal cleartext extraction.** In the **on-demand Inspect view**, deeply decode the inspected
  flow's plaintext: full HTTP request/response structure (method, host, path, headers, body preview)
  and other common cleartext protocols — replacing the current flat text-or-hexdump with a structured
  view (raw hexdump remains available as fallback).

**Out (deferred, with reasons):**
- **Always-on full-traffic capture** → the continuous tap stays **port-53-only** (DNS is low-volume);
  deep content decode runs **on-demand per inspected flow**. Full-traffic capture is deferred to Phase
  3's proxy, which terminates all traffic anyway — building it earlier adds an always-on full pcap for
  little gain before decryption exists.
- **Raw-IP concern scoring** → names are **display-only** in Phase 1. Activating the (currently inert)
  `allRawIP` concern bump is deferred; the maintainer deprioritized false-positive work for now.
- **Any decryption** → Phases 2–3.
- **SNI-as-name-source** → the existing `ClientHelloSNI` parser can later complement DNS for
  hardcoded-IP TLS; DNS alone is the Phase-1 source (broadest coverage, the name the app *chose*).

## Architecture & data flow

```
console launch (sudo) ─► DNS observer (goroutine, /dev/bpf, BPF filter: udp/tcp port 53)
                          parse DNS responses → IP→name cache  ─┐
                                                                 ▼
  nettop+lsof sampler ─► build EgressGroup ─► Resolver.Lookup(ip) ─► Endpoint{IP,Port,Name}
   (existing, ~3 Hz)                                                      ▼  (display only)
  Inspect (i) on a flow ─► existing per-flow /dev/bpf capture ─► cleartext decoder
                             (HTTP/proto structured content) ──► richer Inspect view
                          tree / zoom render  name (ip) ◄─────────────────┘
```

## Components

- **`internal/inspect` bpf generalization.** `OpenLiveCapture` today is host-scoped with a `maxWait`.
  Parameterize its BPF filter (existing host-scoped filter *or* a new `port 53` filter) and allow a
  long-lived run, so the DNS observer and the per-flow inspector share **one** capture implementation
  rather than a second bpf path. (Consumes: existing `bpf_darwin.go`, `buildFlowFilter`. Produces: a
  filter-spec parameter + a long-lived capture mode.)
- **`internal/netname` (new).**
  - `ParseDNSResponse([]byte) (records []struct{Name string; IP netip.Addr}, ok bool)` — tolerant DNS
    answer parser (A/AAAA, CNAME chains resolved to the queried name, multiple IPs). Skips malformed.
  - `Cache` — bounded reverse map `IP → most-recent hostname`, last-seen-wins, size-capped with
    oldest-eviction, mutex-guarded (observer writes, sampler reads).
  - `Observer` — owns the long-lived port-53 capture loop; feeds the cache; clean start/stop.
  - `Resolver` interface (`Lookup(ip string) (name string, ok bool)`) — injected into the egress
    monitor so it stays testable with a fake and never shells out. The `Cache` satisfies it.
- **`model.Endpoint.Name string`** — empty = unresolved.
- **`internal/inspect` cleartext decoder.** `DecodeCleartext(b []byte) Content` producing structured
  HTTP (request line / status, headers, path, body preview) or a typed fallback (other cleartext /
  binary→hexdump / empty). Keeps the existing secret-masking: sensitive headers (Authorization,
  Cookie, Set-Cookie, tokens) stay masked until the user presses `v`.
- **`internal/egress/monitor.go`** — accept a `netname.Resolver`; annotate each built `Endpoint.Name`.
- **`internal/tui`** — tree/zoom render `name (ip)`; the Inspect view renders the decoded structure.
  Decoupling invariant preserved (tui imports only `model` + `mark`; names/content arrive as data).

## Error handling / honest degradation

- No sudo / `bpf` open fails → observer doesn't start; destinations show IPs; a one-line
  "name resolution unavailable (needs sudo)" note (fail loud on the gap, Rule 13); never a crash.
- IP with no observed DNS (pre-existing connection, encrypted DNS, cache miss) → show the IP; never
  guess a name.
- Malformed/truncated DNS or HTTP → tolerant parsers skip/partial-decode and mark truncation.
- Cache bounded (size cap, oldest-evicted) — no unbounded memory; `-race`-clean under concurrent
  observer-write / sampler-read.
- Observer goroutine: starts at console open, stops on exit; no leaked fd/goroutine.

## Testing (all behind injectable seams — CI runs without sudo/pcap)

- **DNS parser:** fixtures for A/AAAA, CNAME chains, multi-IP answers, malformed/truncated packets.
- **Cache:** last-seen-wins, eviction at cap, concurrent read/write under `-race`.
- **Resolver injection:** egress monitor + fake resolver → `Endpoint.Name` populated; existing egress
  tests unaffected.
- **Cleartext decoder:** fixtures (GET/POST, headers, body, chunked, non-HTTP → hexdump fallback);
  sensitive-header masking held until reveal.
- **TUI:** tree/zoom render `name (ip)`; inspect renders decoded structure; `TestDecouplingInvariant`
  holds.

## Success criteria

1. In a live `console` (sudo), an app that resolves a hostname and connects shows `hostname (ip)` in
   the tree within a sample tick or two; an app dialing a hardcoded IP shows the bare IP.
2. Inspecting a cleartext HTTP flow shows a structured request/response (method/host/path/headers/body),
   with sensitive headers masked until `v`.
3. Without sudo, the views degrade to IPs + a stated gap; nothing crashes, no name is fabricated.
4. `go test ./...` green (incl. `-race` on `netname`), `architext validate` passes.

## Architext / roadmap updates (on implementation)

- `roadmap-egress-packet-capture` → refocused as Phase 1 (this design).
- new `roadmap-egress-keylog-decrypt` → Phase 2.
- `roadmap-egress-payload-inspection` → refocused as Phase 3 (proxy: decrypt + redact + block).
- New `internal/netname` node; `mod-inspect`/`mod-egress`/`mod-tui` responsibilities extended;
  `Endpoint.Name` in the egress data model; a capture/data-flow + trust-boundary note for the pcap tap.
