# Exfiltration Inspection — the tiered interceptor

**Date:** 2026-07-12
**Status:** Design spec (pre-implementation) — for review
**Feature:** `i` on an Exfiltration row → inspect what a flow is actually sending
**Depends on:** the Exfiltration view (per-connection rows + rates, already shipped)
**Feeds:** highlighting (keyword/regex + key heuristics — the next feature)

## 1. Purpose & the honest constraint

The Exfiltration view answers *"who is sending data out, and how much."* Inspection
answers the next question: ***"what is it sending?"*** — pressing `i` on a connection
row opens a view of that flow's actual content and metadata, so the user can see
whether their data is being smuggled out.

The hard reality, stated up front: **most traffic is TLS (`:443`) and therefore
encrypted.** There is **no single method** that reads every flow's plaintext. But
CounterSpy runs **on the endpoint, as root, on the user's own machine, with the
user's consent** — which is a fundamentally different (and legitimate) position than
a network man-in-the-middle. On the endpoint we can get *below* or *before* the
encryption through several techniques, each covering a different slice of flows. So
the design is not "decrypt everything" — it is a **tiered interceptor that applies
the best available technique per flow and reports honestly what it could and could
not see.** That per-flow coverage verdict is itself a signal: a process that is
hardened *and* refuses to reveal what it ships is one of the most interesting rows
on the screen.

### 1.1 The ethical boundary (what keeps it *counter*-spy)

Inspection is the user observing **their own machine's** outbound traffic, with
explicit consent — the same thing EDR, DLP, and developer proxies (Charles,
Proxyman, mitmproxy) do. It is **not** intercepting third parties' traffic, and it
is **not** silent. Concretely:

- Inspection is **off by default** and **opt-in per session** (a consent gate before
  any capture starts), mirroring the feedback loop's posture.
- The most invasive tier (a TLS-terminating proxy + a locally-installed root CA) is
  **never enabled silently** — it requires an explicit, separate consent step that
  states plainly that a CA will be installed and that pinned apps will break.
- Captured plaintext is **display-only and ephemeral** by default: held in memory
  for the inspection view, never written to disk unless the user explicitly exports,
  and redaction of the most obvious secrets is on by default (see §6).

## 2. The tiers

For a selected flow, the interceptor attempts techniques in decreasing order of what
the target allows, and records which one (if any) yielded plaintext.

| # | Tier | Yields | macOS mechanism | Reaches |
|---|------|--------|-----------------|---------|
| 0 | **Metadata** | SNI/host, cert (TLS 1.2), packet sizes/timing, JA3/JA3S, DNS names | BPF raw capture (`/dev/bpf`), parse ClientHello/handshake | **Always** (even fully-encrypted flows) |
| 1 | **Plaintext flows** | full payload | same BPF capture; the flow is unencrypted (plain HTTP, DNS, some IoT/malware C2) | plaintext protocols |
| 2 | **`SSL_write` hook** | plaintext *before* encryption (bypasses pinning) | **native** in-process interposition — a helper dylib via `DYLD_INSERT_LIBRARIES`, or `task_for_pid` + Mach injection, or `libdtrace` via cgo — NOT a shelled `dtrace`/`frida` child (native-first, §3) | non-hardened / non-SIP targets |
| 3 | **Key extraction → decrypt** | plaintext (post-hoc) | `SSLKEYLOGFILE` if the app honors it, or session-key scrape via `task_for_pid`; decrypt the BPF-captured ciphertext | apps that cooperate / are debuggable |
| 4 | **Terminating proxy + consented CA** | plaintext | install a root CA (explicit consent), transparently proxy, re-encrypt | broadest; **breaks pinned apps**, most invasive |

**Coverage limits are real and named per flow:** SIP, hardened runtime, and library
validation block tier 2 injection into Apple and hardened-notarized apps; cert
pinning defeats tier 4 (but *not* tier 2, which is below the socket); tier 3 needs a
cooperative app or a debuggable process. The view states the outcome for each flow
(§4).

## 3. Capture architecture

```
                         ┌───────────────────────────────────────────┐
  i on a conn row ──────▶│  inspect.Session (per selected flow)       │
   (pid, 4-tuple)        │   ├─ tier 0/1: BPF capture + parse         │──▶ InspectResult
                         │   ├─ tier 2: SSL hook (opt-in, spike-gated) │     { coverage, metadata,
                         │   ├─ tier 3: keylog/keyscrape (opt-in)      │       plaintext?, tierUsed,
                         │   └─ tier 4: proxy (explicit CA consent)    │       reason }
                         └───────────────────────────────────────────┘
```

- **Capture source: native BPF** (`/dev/bpf`, root) filtered to the selected flow's
  4-tuple — raw BPF via `syscall`/`golang.org/x/sys` (already in the module graph via
  tcell), no third-party dependency. **Native-first is a hard principle here**
  (maintainer decision): forking to an external process is a measure of last resort
  and a highly suspect choice for a counter-surveillance tool — a child `tcpdump`
  would itself be an odd new process spawning packet capture, exactly the shape we
  hunt. So **no `tcpdump`/`tshark` shell-out** and **no `gopacket` dependency**; the
  capture seam exists only so tests inject fixture bytes, not to swap in an external
  tool. (This matches the native Security.framework codesign direction.)
- **Parsers are pure and fixture-tested** (the codebase's contract): an
  Ethernet/IP/TCP framing parser and a **TLS ClientHello parser** (SNI, versions,
  JA3) over captured bytes. The BPF read is the untested I/O edge.
- **Correlation:** a captured flow is keyed by its 4-tuple; the Exfiltration row the
  user pressed `i` on already carries `(pid, remote endpoint)` and its local
  endpoint (from nettop/lsof), so the flow maps back to the row deterministically.
- **Lazy + scoped:** capture starts only when the user opens inspection on a row and
  runs only for that flow (a BPF filter program), not a firehose — bounded memory,
  and no capture at all until consented.

## 4. The inspection view (`i`)

`i` on a connection (or app/instance) row opens a full-screen inspection pane for
that flow:

- **Header:** app · pid · `local → remote` · proto · trust glyph (reuses
  `internal/mark`).
- **Coverage verdict (the honest line):** exactly one of
  - `plaintext (HTTP)` — here's the body
  - `decrypted via SSL_write hook` — pinning bypassed
  - `decrypted via keylog`
  - `decrypted via local proxy`
  - `ENCRYPTED — SNI: api.example.com · not decrypted (hardened runtime + pinned)`
    ← *this verdict is a finding*
- **Metadata block (always):** SNI/host, DNS names seen, cert subject/issuer (TLS
  1.2), JA3/JA3S, byte sizes & timing, destination.
- **Content pane (when a tier yielded plaintext):** the decoded payload, scrollable,
  control-char-sanitized (reuse `model.Clean`), with #4's highlighting applied.
- `esc`/`i` returns to the Exfiltration list; `q`/`Q` quits the console.

The interceptor lives in a new **`internal/inspect`** package (pure parsers + capture
seam + tier orchestration, importing `internal/model` + stdlib/x-sys); the view is a
new mode/overlay in `internal/tui` reached from the Exfiltration row. It stays off
the findings/scoring path entirely (observe-only, like the rest of egress).

## 5. Consent & lifecycle

1. First `i` in a session shows a **consent gate**: "Inspection captures this flow's
   packets on your own machine. Continue? [y/N]". Nothing is captured before `y`.
2. Tier 2 (process hooking) and tier 4 (CA + proxy) each require their **own**
   additional, explicit consent the first time they'd be used, naming the concrete
   risk (injecting into a process / installing a root CA that breaks pinned apps).
3. A **`--no-inspect`** flag and a config toggle disable inspection entirely for
   locked-down environments.
4. Capture stops when the inspection view closes; no background capture persists.

## 6. Security of the tool itself (handling captured plaintext)

Inspecting exfiltration means CounterSpy briefly holds the very secrets it's hunting.
Rules:

- **Ephemeral by default:** plaintext lives in memory for the view only; never
  written to disk unless the user runs an explicit export, which prints the target
  path and requires confirmation.
- **Redaction on by default:** obvious secrets (things matching the #4 key/secret
  heuristics — bearer tokens, `AKIA…`, private-key PEM headers, high-entropy blobs)
  are masked in the rendered view unless the user toggles "reveal", so a shoulder-
  surfer / screenshot doesn't leak them.
- **No exfiltration of the inspection:** captured content never leaves the machine
  through the feedback channel or anywhere else — inspection is local-only.
- **Least privilege:** the BPF filter is scoped to the single selected 4-tuple; we
  do not capture the whole interface.

## 7. Scope & phasing

The spec is the whole subsystem; implementation ships in independently-valuable,
reviewed increments (each its own PR under the swarm):

- **Phase A — inspect UI + tier 0/1 (metadata + plaintext).** BPF capture of the
  selected flow, the TLS ClientHello/SNI parser, the framing parser, the inspection
  view, the coverage verdict, consent gate. Ships real value (SNI/host + plaintext
  flows) and gives #4 a surface. *No process injection yet.*
- **Phase B — tier 2 (`SSL_write` hook), gated on a feasibility spike.** A throwaway
  `DYLD_INSERT_LIBRARIES`/`dtrace` interposer proving plaintext capture on a
  non-hardened target on this macOS **before** committing. If the spike fails, this
  tier is documented as unavailable and we lean on tiers 0/1/3/4.
- **Phase C — tier 3 (keylog/keyscrape) and tier 4 (proxy + CA).** The heaviest and
  most consent-sensitive; last.
- Highlighting (#4) layers on whatever plaintext any phase surfaces.

**Justified deferrals (Rule 16):** tiers 2–4 are deferred behind Phase A not for
convenience but because (a) tier 2's feasibility is genuinely unknown on hardened
macOS and must be spiked, and (b) tiers 3–4 carry the highest consent/security risk
and should follow the safe, always-available metadata tier.

## 8. Non-goals

- Not a network MITM of anyone else's traffic — endpoint + own-machine + consent only.
- Not silent: no capture without consent, no CA install without explicit consent.
- Not persistent surveillance: capture is per-flow, on-demand, and stops on close.
- No new third-party dependency unless review concludes a hand-rolled parser is worse.
- Does not change scoring/verdicts — inspection is observe-only.

## 9. Testing

- **Pure parsers** (framing, TLS ClientHello/SNI, JA3) fixture-tested against
  captured `.pcap`/hex fixtures — no root, CI-safe (the BPF read is the injected I/O
  edge, mocked).
- **Tier orchestration** tested with a fake capture source + fake tier providers:
  assert the coverage verdict picks the right tier and degrades honestly.
- **View** via `SimulationScreen`: `i` opens the pane, the verdict line renders, the
  metadata block shows SNI, esc returns.
- **Consent gate** tested: no capture is attempted before consent; `--no-inspect`
  disables it.
- Redaction tested: a bearer token / PEM header is masked by default.

## 10. Resolved decisions (maintainer review, 2026-07-12)

1. **Capture: native BPF, no shell-out.** Forking an external `tcpdump`/`tshark` is a
   last resort and a suspect choice for a counter-surveillance tool; native `/dev/bpf`
   only (§3).
2. **Tier 2: native interposition only** — a helper dylib / Mach injection / `libdtrace`
   via cgo, never a shelled `frida`/`dtrace` child (§2). The Phase-B spike targets the
   native mechanism.
3. **Redaction: mask secrets by default** with a "reveal" toggle (§6). Agreed.
4. **Native-first, narrowly relaxed for a pure-Go filter assembler (2026-07-12, Phase A).** The
   scoped kernel BPF filter (§6 least-privilege) is assembled with `golang.org/x/net/bpf` — a
   pure-Go instruction *assembler* with a VM that validates the filter program against fixture
   packets in CI (no root). This is NOT a capture dependency and involves no shell-out: packet
   capture stays native `/dev/bpf` via `x/sys/unix`. Hand-rolling the cBPF bytecode was judged
   *worse* (error-prone and untestable without root), so the "no third-party dependency" line in
   §3/§8 is relaxed for this one pure-computation assembler (pinned `v0.6.0` to avoid an `x/sys`
   upgrade cascade). The kernel filter is currently host+TCP scoped; remote-port scoping is a
   tracked refinement (userspace correlation already enforces the exact port).
