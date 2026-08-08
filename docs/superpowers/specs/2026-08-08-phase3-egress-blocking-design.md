# Phase 3 (MVP): Egress blocking (IP/port firewall, host-down reaction)

- Date: 2026-08-08
- Status: Design approved; awaiting spec review, then a feasibility smoke test (task 0), then an implementation plan
- Roadmap item: `roadmap-egress-active-controls` ("Phase 3 - Active egress controls: redact + block")
- Builds on: v0.7.0 (read-only TLS-intercepting decrypt mirror), shipped 2026-08-08

## Context

The outbound-visibility program has shipped Phases 1 and 2: passive destination
names (v0.6.0) and a consented, READ-ONLY TLS decrypt mirror (v0.7.0). Every
prior phase honors an observe-only network invariant: the proxy relays every
byte unmodified and never alters or drops traffic.

Phase 3 is the first phase to cross that invariant into active control. The
roadmap sequenced it after the read-only mirror earned a track record, "so a bug
can't silently mangle a user's request before interception is trustworthy."

## The staged vision (by effect)

Defined by the effect on outbound traffic, in order:

1. Now (this MVP): block outbound TCP and UDP by address and port, at the IP
   layer, by any means that actually works. The reaction the target app sees is
   an unresponsive server: the connection establishes and its data is ACKed at
   the transport level, but no application ever responds. Not app aware; a
   standalone egress control, independent of the intercept proxy.
2. Later: the block becomes fully stealthy and complete. Every matched flow
   disappears into a void indistinguishable from a genuinely unresponsive server,
   with no signal (timing, ICMP, or otherwise) that reveals a control is present,
   so software cannot detect it and route around it.
3. Finally: intercept and modify traffic in flight before letting it continue
   (format-preserving redaction). App-awareness and content return here, via the
   existing TLS proxy, not the L3/L4 firewall.

This spec covers stage 1. Stages 2 and 3 are documented as the trajectory so the
MVP does not foreclose them; they are NOT built here.

## The observe-only invariant crossing

Today's honesty invariant: the proxy never changes what crosses the wire. Phase 3
replaces it with a narrower one this MVP must hold:

> Traffic is either forwarded byte-for-byte unmodified (as today, for everything
> not matched) or sunk whole at an unresponsive local sink so the destination
> never receives it and never answers. Nothing is ever forwarded modified, and no
> block is ever hidden from the operator, only from the target app.

The MVP satisfies this by construction: a matched flow is sunk whole (the real
destination receives none of it; the app receives no application response), never
modified and never partially forwarded, and every block is logged and surfaced to
the operator.

## Block reaction: unresponsive, not refused and not host-down

The reaction to a blocked flow is an application that accepted the request and
then went silent, while the transport layer behaves normally:

- The TCP handshake COMPLETES (a SYN-ACK is returned) and the data the app sends
  is ACKed at the transport level, so from the client's stack the connection is
  established and its request was delivered.
- No application-level response is ever produced. The app's read blocks until its
  own application timeout.
- This is explicitly NOT host-down (SYN dropped, never establishes; software
  detects it and fails over immediately), NOT a TCP RST (refused), and NOT an
  ICMP administratively-prohibited (announces a filter). All three signal "try
  elsewhere." An accepted-but-silent connection gives software nothing to react
  to, the most benign-looking and least-detectable failure.

Mechanism implication (this is the hard part). Producing transport ACKs with no
application response means the matched flow must terminate at a LOCAL SINK that
accepts the connection, ACKs the data, and stays mute, rather than reaching the
real destination. That requires REDIRECTING matched local-outbound flows to that
sink (or forging the transport dance), which is exactly the local-outbound
redirection the pf `rdr` disproof (2026-07-16) showed does not work the obvious
way. So "unresponsive" is materially harder than a silent drop, and the
feasibility study (task 0) must prove we can SINK local outbound, not merely drop
it. A plain silent drop (host-down) is the cruder fallback if sinking proves
infeasible without a NetworkExtension, accepting it is more detectable.

Honesty split, silent to the app but loud to the operator: the target app must
perceive an unresponsive server, but CounterSpy's console and JSONL log MUST show
the active block with the matched rule, so the operator can always distinguish a
CounterSpy block from a genuinely slow/broken server and can RCA it. A block
hidden from the operator would be the dishonest failure this project forbids.

## Scope

In scope (stage 1 MVP):

- Block outbound TCP and UDP by `(address, port)` at the IP layer.
- Unresponsive-sink reaction (handshake completes, data ACKed, no application
  response); not host-down, not RST, not ICMP-prohibited. Silent drop (host-down)
  is a labeled fallback only if sinking proves infeasible without NE.
- Covers ALL outbound to a matched address/port, regardless of app or protocol
  inside (a real egress control, not the cooperative proxy path), subject to the
  mechanism task 0 proves out.
- Default-off, consented, reversible, with bulletproof teardown.
- Audit mode (log would-drop against live traffic without dropping) and enforce
  mode.
- Every drop and would-drop logged and surfaced to the operator. No silent-to-
  operator drops.

Explicitly out of scope:

- App-awareness. The MVP keys on address and port only. Per-app blocking needs
  either the cooperative proxy (proxy-honoring HTTPS only) or a NetworkExtension
  content filter (entitlement); neither is in this MVP.
- Content inspection or payload modification of any kind.
- Stage-2 stealth hardening (making the drop indistinguishable from a real
  outage beyond "no RST/ICMP"). The MVP aims for host-down; perfect
  indistinguishability is stage 2.
- Robust name-based rules. Rules are IP/CIDR + port; a hostname maps to rotating
  IPs, so name convenience (resolve + refresh) is a later addition.
- Default-deny / allowlist posture. Deny-rules over default-allow only.

## Design

### Rule model (pure engine)

A pure, I/O-free evaluator, unit-testable in isolation.

- A rule is `{ proto: "tcp"|"udp"|"any", addr: <ip-or-cidr>, port: <n>|"any", note? }`.
- `addr` matches the destination IP against an exact address or a CIDR
  (`203.0.113.7`, `203.0.113.0/24`). Both IPv4 and IPv6.
- `port` matches the destination port, or `any`.
- `proto` narrows to TCP or UDP, or `any`.
- First-match-wins over an ordered list; default is allow (deny-rules only).

Interface: `Decision(proto, destIP, destPort) -> Allow | Drop{rule, index}`. The
engine performs no lookups; the caller supplies the connection's 3-tuple.

Rationale for the pure split: the drop decision is the highest-consequence logic
in the phase (a wrong match silently breaks the user's connectivity or fails to
stop a leak). A pure function over an explicit 3-tuple is exhaustively table-
testable without root, pf, or live traffic, matching the project's mockable-seam
rule.

Name-to-address is out of the engine: if name-based rules are added later, name
resolution (and refresh, since a name maps to rotating IPs) happens at the config
layer and feeds resolved addresses into the same engine.

### Mechanism and the feasibility gate (task 0)

The unresponsive-sink reaction requires REDIRECTING matched local-outbound flows
to a local sink (accept the connection, ACK the data, never answer), a harder
capability than dropping. The pf `rdr` redirect was DISPROVED for locally-
originated outbound by the 2026-07-16 smoke test, and IP-layer sinking needs
exactly that redirect, so the mechanism is genuinely uncertain and must be proven
before the plan commits (Rule 17).

Task 0, a maintainer-run root smoke test (like the 2026-07-16 CONNECT test),
gates the mechanism. It must answer, for a chosen `(addr, port)` over TCP and UDP:
can we redirect this machine's own outbound flow into a local sink so the
handshake completes, the app's data is ACKed, and no application response is
returned, and is it cleanly removable?

Fallback ladder, best rung first, each proven or ruled out by task 0:

1. Local sink via a redirect/divert primitive: pf `divert-to` / divert sockets,
   or any macOS primitive that steers local outbound into a local socket without
   NE. This is the ideal (general, unresponsive) but unproven for local outbound;
   pf `rdr` is already disproved, so this is the first thing task 0 tests.
2. Cooperative HTTPS subset via the existing CONNECT proxy: for proxy-honoring
   apps the proxy already terminates the connection, so it can accept-and-hold-
   silent (tarpit) instead of relaying. A true unresponsive sink available today,
   but HTTPS-proxy-honoring only, not the general addr+port case.
3. NetworkExtension transparent proxy (`NEAppProxyProvider`): the OS-sanctioned
   way to intercept arbitrary local outbound and sink it, app-aware and all-
   transport. Needs the networkextension entitlement + signed/notarized app, the
   external/financial dependency scoped out of the current program.
4. Cruder fallback if no general sink is feasible without NE: a plain silent drop
   (pf `block drop` / blackhole, host-down). This abandons the unresponsive
   reaction, so it is an explicitly-labeled degradation, chosen only if a sink
   cannot be built.

The implementation plan is written against the rung task 0 validates. The spec
does not presume a mechanism; it presumes we will use whichever proven means
gives an address+port, unresponsive, reversible sink, degrading to a labeled
silent drop only if no sink is achievable without NE.

### Reversibility (safety-critical)

A leftover block rule silently breaks the user's networking, a worse footgun than
a leftover proxy setting. Teardown MUST be bulletproof:

- All rules live in a single dedicated CounterSpy pf anchor (or a tracked route
  set), never mixed into the user's ruleset, so teardown is a single scoped
  flush.
- Removed on every exit path: normal exit, panic, signal (SIGINT/SIGTERM),
  and `--uninstall`, with the signal handler registered FIRST (the intercept
  arm/disarm pattern).
- Belt-and-suspenders: teardown verifies the anchor is empty afterward and
  reports if a rule survived, rather than assuming success. On arm, a stale
  CounterSpy anchor from a crashed prior run is flushed before installing.

### Modes, consent, default-off

- Default-off. With no config or `mode: "off"`, nothing is installed; behavior is
  identical to today.
- `mode: "audit"`: evaluate the 3-tuple of observed flows and log would-drop, but
  install NO rules. Observe-only, so it cannot break connectivity; the way to
  validate a rule set before enforcing.
- `mode: "enforce"`: install the drop rules.
- Enabling enforce is surfaced in a consent prompt at arm time, so arming a
  configuration that will actively drop traffic is never silent.

### Rule source

A config file, `~/.config/counterspy/block.json`, resolved to the invoking user
even under sudo (the `feedback.json` pattern).

```jsonc
{
  "mode": "off",              // "off" (default) | "audit" | "enforce"
  "rules": [
    { "proto": "any", "addr": "203.0.113.7", "port": "any", "note": "kill this host" },
    { "proto": "udp", "addr": "203.0.113.0/24", "port": 443, "note": "no QUIC to this range" }
  ]
}
```

No new CLI flags. A future `counterspy block` subcommand or flag is a separate,
approvable decision, not part of this MVP; the file drives everything.

### Observability

- Every enforced drop and every audit would-drop is written to the rotating 0600
  JSONL with the matched rule (index + note) and the flow 3-tuple, so every
  active decision is auditable after the fact (Rule 13).
- The console shows a running count of drops (or would-drops), and, where the
  Exfiltration view already lists a destination, marks it dropped, so the
  operator sees enforcement is live even though the target app sees only a dead
  connection.

### Relationship to intercept

This firewall is standalone: it does not require the intercept proxy, does not
terminate TLS, and does not parse any payload. It can run with or without
`intercept`. Stage 3 (intercept + modify) is where the two meet: the proxy adds
the app-aware, content-aware layer on top of the L3/L4 firewall.

## North star (documented, NOT built here)

- Stage 2, stealth void: harden the drop so it is indistinguishable from a real
  outage, matching the OS's natural timeout/unreachable behavior and emitting no
  filter-revealing signal, so evasive software cannot detect the block.
- Stage 3, intercept + modify: within an allowed, decrypted flow, the Phase 2.5
  per-message pump rewrites a matched sensitive span in place with a character-
  class, length, and position preserving substitute (a digit becomes a digit, an
  uppercase letter an uppercase letter, punctuation and structure unchanged,
  total byte length identical), so `Content-Length` and both speakers' protocol
  stay intact and the secret never reaches the server. Naive masking changes
  length and breaks the exchange; this is what "redact without violating the
  protocol of the two speakers" requires.
- Signed-body honesty boundary (stage 3): a request carrying a cryptographic
  signature or HMAC over its body (AWS SigV4, OAuth body signatures, webhook
  signing) cannot be silently redacted; any body change fails verification. The
  honest rule: detect a body-signature header and either skip redaction
  (fail-open, and say so) or drop the flow. Never silently forward a request
  whose signed body we modified.

## Non-goals (MVP)

- No app-aware block decisions (address + port only).
- No payload inspection or modification.
- No RST or ICMP-based refusal (unresponsive sink; a labeled silent drop is the
  only fallback, chosen only if a sink is infeasible without NE).
- No default-deny/allowlist posture.
- No new CLI flags.
- No change to any allowed flow; unmatched traffic is byte-for-byte as today.

## Testing strategy

- Rule engine: exhaustive table tests for exact IP, CIDR (v4 and v6), port match
  and `any`, proto narrowing, precedence (first-match-wins), and default-allow.
  Pure, no root.
- Mechanism: task-0 maintainer-run root smoke test proves the chosen rung drops
  local outbound TCP and UDP with a host-down reaction and removes cleanly.
  Automated tests cover the rule-install/teardown seam with the pf/route exec
  mocked (assert the exact commands and that teardown flushes the anchor even
  after a simulated panic).
- Reversibility: a test that every exit path (exit, panic, signal, uninstall)
  flushes the anchor, and that arm flushes a stale anchor from a prior crash.
- Modes: audit installs no rules but logs would-drop; off/absent installs
  nothing; an unknown mode is treated as off (never fail-open into enforce).
- Regression: an unmatched flow is unaffected; with `intercept` also running, an
  allowed flow still decrypts and relays exactly as v0.7.0.

## Open questions for implementation planning

- Exact per-port drop primitive if the smoke test says pf `block` cannot filter
  local outbound: whether a blackhole route can be made per-port (likely not,
  route is per-host) or whether per-port then requires NE. The smoke test result
  decides.
- Whether `block.json` is read only at arm time (MVP proposal, re-arm to change
  rules) or watched for live reload.
- Whether audit/enforce counts share the `InterceptStatus` footer or get their
  own line. Deferred to the UI step of planning.

## Task 0: feasibility smoke test (maintainer-run, gates the mechanism)

Before the implementation plan commits to a mechanism, run as root on macOS. The
crux is whether we can SINK local outbound, not merely drop it.

Part A, can we redirect local outbound into a local sink (the unresponsive
reaction)?

1. Stand up a trivial local sink: a listener that accepts TCP, reads and ACKs
   bytes, and never writes back; for UDP, receives and never replies.
2. Try each redirect primitive to steer this machine's own outbound flow to a
   chosen `(addr, port)` into the sink: pf `divert-to` / divert socket first (pf
   `rdr` is already disproved for local outbound).
3. Verify from the same machine: the app's TCP connect SUCCEEDS (SYN-ACK from the
   sink), its request bytes are ACKed, and no application response arrives, so the
   app hangs at the application layer. Capture with tcpdump.
4. Confirm the redirect actually acts on locally-originated outbound (packets
   diverted, not zero, the metric the rdr test failed).
5. Remove the rule and confirm normal connectivity returns.

Part B, fallback, can we at least drop (host-down) if we cannot sink?

6. Install pf `block drop out` for the 3-tuple; verify the TCP connect times out /
   reads unreachable and UDP gets no answer, with no RST and no ICMP prohibited;
   confirm `pfctl` shows it acting on local outbound; remove and confirm recovery.

Record which rung works, with pfctl/tcpdump evidence, as the input that fixes the
implementation plan's mechanism: a general unresponsive sink if Part A succeeds,
the cooperative-HTTPS tarpit meanwhile, and a labeled silent drop only if Part A
fails and NE is not accepted.
