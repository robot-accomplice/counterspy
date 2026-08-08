# Phase 3 (MVP): Blind egress blocking

- Date: 2026-08-08
- Status: Design approved; awaiting spec review, then implementation plan
- Roadmap item: `roadmap-egress-active-controls` ("Phase 3 - Active egress controls: redact + block")
- Builds on: v0.7.0 (read-only TLS-intercepting decrypt mirror), shipped 2026-08-08

## Context

The outbound-visibility program has shipped Phases 1 and 2: passive destination
names (v0.6.0) and a consented, READ-ONLY TLS decrypt mirror (v0.7.0). Every
prior phase honors an observe-only network invariant: the proxy relays every
byte unmodified and never alters or drops traffic. It only reveals.

Phase 3 is the first phase to cross that invariant into active control. The
roadmap sequenced it deliberately after the read-only mirror earned a track
record, "so a bug can't silently mangle a user's request before interception is
trustworthy."

This spec covers the MVP: blind egress blocking. It also documents the north
star it is architected toward (content filtering and format-preserving
redaction) so the MVP does not paint us into a corner, but that north star is
explicitly NOT built here.

## Scope

In scope (MVP):

- Block whole outbound flows by `(app, destination)` rule.
- Decide the block at the CONNECT layer, before TLS termination. A blocked flow
  is never decrypted.
- Default-off, consented, reversible, on the same arm/disarm model as
  `intercept`.
- Audit mode (log would-block against live traffic without dropping) and enforce
  mode (actually drop).
- Every block and every audit would-block is logged and surfaced in the console.
  No silent drops.

Explicitly out of scope (north star, documented below, not built):

- Content inspection of any kind for the block decision (the MVP is "blind":
  it matches app and destination only, never payload).
- Payload modification, redaction, or format-preserving rewrite.
- Default-deny / allowlist-only posture (deny-rules over default-allow only).
- Blocking individual requests within an allowed tunnel (that needs the message
  gate, which is north star).

## The observe-only invariant crossing

Today's honesty invariant: the proxy never changes what crosses the wire. Phase
3 changes that for matched flows only, and replaces the old invariant with a
narrower one that this MVP must hold:

> The proxy either forwards a flow byte-for-byte unmodified (as today) or refuses
> it entirely and says so. It never forwards a modified flow, and it never drops
> a flow silently.

Blind blocking satisfies this by construction: a blocked flow is refused whole
(never modified, never partially forwarded), and the refusal is always logged
and surfaced. The MVP never terminates TLS on a blocked flow, so it cannot
mangle a request even in principle.

## Design

### Policy engine (pure)

A pure, I/O-free rule evaluator, unit-testable in isolation.

- A rule is `{ app: <glob>, dest: <glob>, note?: <string> }`.
- `app` matches the attributed process, tested against both its name (e.g.
  `Slack`) and its resolved executable path, so a rule can name either.
- `dest` matches the CONNECT authority host (not the port), as a glob:
  `*.segment.io`, `telemetry.example.com`, `*`.
- Wildcards fall out for free: `{app:"*", dest:"telemetry.example.com"}` blocks
  that destination for every app; `{app:"BackupDaemon", dest:"*"}` blocks one app
  entirely.
- Evaluation is first-match-wins over an ordered list; the default when nothing
  matches is allow (deny-rules over default-allow).

Interface:

```
Decision(app AppIdentity, destHost string) -> { Allow } | { Block, Rule, RuleIndex }
```

`AppIdentity` carries the name and path already resolved by the proxy's owner
attribution (Phase 2). The engine performs no lookups; the caller supplies the
attributed identity and the destination host parsed from the CONNECT line.

Rationale for pure separation: the block decision is the highest-consequence
logic in the phase (a wrong match silently breaks a user's app or fails to stop
a leak). Keeping it a pure function over explicit inputs makes it exhaustively
table-testable without the network, sudo, or a live proxy, matching the
project's mockable-seam rule.

### Rule source

Rules live in a config file, `~/.config/counterspy/block.json`, resolved to the
invoking user even under sudo (the same resolution `feedback.json` uses, so the
root daemon reads the operator's file, not root's home).

```jsonc
{
  "mode": "off",            // "off" (default) | "audit" | "enforce"
  "rules": [
    { "app": "*", "dest": "telemetry.example.com", "note": "kill this beacon" },
    { "app": "Slack", "dest": "*.segment.io", "note": "no Slack analytics" }
  ]
}
```

- `mode: "off"` (default, and the state when the file is absent) means the
  policy engine is never consulted; the proxy behaves exactly as v0.7.0.
- `mode: "audit"` evaluates rules and logs would-block decisions but forwards
  everything.
- `mode: "enforce"` evaluates rules and refuses matched flows.

No new CLI flags. Enforcement rides the existing `intercept` arm: the daemon
loads `block.json` at arm time and applies its mode. This respects the standing
"no new CLI flags without explicit approval" rule; a future flag (for example a
`--block-audit` convenience) is a separate, approvable decision, not part of this
MVP.

### Mechanism (CONNECT gate)

The block decision happens in the proxy's CONNECT handling, after the
destination host is parsed and the PID owner is attributed, and before any TLS
termination.

```
readConnect -> (destHost, ownerIdentity)
policy := Decision(ownerIdentity, destHost)
switch policy {
case Allow:
    // today's exact path: terminate TLS, capture, re-dial, relay unmodified
case Block (enforce mode):
    // refuse the tunnel: reply 403 to the client's CONNECT, close.
    // never terminate TLS, never decrypt, never re-dial.
    publish a `blocked` connection event
case Block (audit mode):
    // forward as Allow, but publish a `would-block` connection event
}
```

The refusal replies to the client's CONNECT with an error status (403) and
closes, so the app sees a visible, immediate failure rather than a hang or a
silent black hole. The failure is the app's own error path (a failed HTTPS
request), which is the honest, debuggable outcome of a firewall-style block.

### Modes, consent, reversibility

- Default-off. With no `block.json` or `mode: "off"`, behavior is identical to
  v0.7.0.
- Enabling active blocking (`mode: "enforce"`) is surfaced in the `intercept`
  consent prompt at arm time, so arming a proxy that will actively drop traffic
  is never silent. Audit mode is called out too, but as observe-only it does not
  change what crosses the wire.
- Blocking is reversible on the same triggers as the rest of `intercept`: exit,
  panic, signal, and `--uninstall` all disarm the whole proxy, which removes the
  block behavior with it. There is no separate persistent blocking state to
  leak.
- Recommended operating procedure (documented, not enforced by code): run
  `audit` first, confirm the would-block log matches intent, then switch to
  `enforce`. The MVP does not force an audit stage before enforce, per the
  "blind blocking is fine for now" decision, but audit exists precisely so an
  operator can de-risk a rule set cheaply.

### Honesty and observability

- A new flow status, `blocked`, joins the existing closed set
  (`decrypted` | `pinned` | `opaque` | `error`) so a refused flow is visibly
  distinct from a decrypted or opaque one in the Exfiltration view and in the
  JSONL log.
- Enforce blocks and audit would-blocks are both written to the rotating 0600
  JSONL log with the matched rule (index + note) and the `(app, dest)` that
  triggered them, so every active decision is auditable after the fact (Rule
  13: ship RCA instrumentation with the code).
- The console surfaces a running count of blocked (or would-block) flows, so an
  operator sees enforcement is live and how much it is catching.

## North star (documented, NOT built in this MVP)

The MVP's CONNECT gate and the eventual content controls are different insertion
points under one policy engine, and that is deliberate.

- Message gate: within an allowed, decrypted flow, the Phase 2.5 per-message
  pump already holds the plaintext and re-dials upstream. It is the natural home
  for two later capabilities:
  - Content filtering: drop a single matched request within an otherwise allowed
    tunnel (needs decryption and per-message evaluation, unlike the blind
    CONNECT block).
  - Format-preserving redaction: rewrite a matched sensitive span in place with
    a character-class, length, and position preserving substitute (a digit
    becomes a digit, an uppercase letter an uppercase letter, punctuation and
    structure unchanged, total byte length identical), reusing the `Redact`
    detector that already locates secrets for the view. Because length is
    preserved, `Content-Length` stays correct and both speakers' protocol stays
    parseable; the secret never reaches the server, but the conversation's shape
    is untouched. This is what "redact without violating the protocol of the two
    speakers" requires: naive masking changes length and breaks the exchange.
- Signed-body honesty boundary: some requests carry a cryptographic signature or
  HMAC over the body (AWS SigV4, OAuth body signatures, webhook signing). A
  format-preserving rewrite keeps the request parseable, but any body change
  still fails a signature check, so true invisibility is impossible there. The
  honest rule (the Phase 3 analog of the read-only mirror's honesty invariant):
  detect a body-signature header and either skip redaction (fail-open, and say
  so) or block the flow. Never silently forward a request whose signed body we
  have modified.

Nothing in the MVP forecloses this: the policy engine is shared, the `blocked`
status generalizes to `redacted`/`filtered`, and the message pump already exists.

## Non-goals

- No content-based block decisions in the MVP (blind block only).
- No payload modification of any kind in the MVP.
- No default-deny/allowlist posture.
- No new CLI flags.
- No changes to the read-only capture path for allowed flows; an allowed flow is
  byte-for-byte identical to v0.7.0.

## Testing strategy

- Policy engine: exhaustive table tests for exact match, app wildcard, dest
  glob, precedence (first-match-wins), default-allow, and name-vs-path app
  matching. Pure, no I/O.
- CONNECT gate: seam tests that an enforce-mode block refuses the tunnel with a
  403 and performs no TLS termination and no re-dial (assert the terminate/redial
  seams are never called), and publishes a `blocked` event; that audit-mode
  forwards but publishes `would-block`; that `mode: off` and an absent file leave
  the v0.7.0 path untouched.
- Config: load/parse tests including an absent file (mode off), an unknown mode
  (treated as off, with a surfaced notice, never fail-open into enforce), and
  sudo user resolution.
- Regression: an allowed `(app, dest)` still decrypts and relays exactly as
  today.

## Open questions for implementation planning

- Exact refusal status/response to the client CONNECT (403 vs 502 vs a plain
  close). 403 is the current proposal; confirm during planning against what
  CFNetwork/NSURLSession surface to the app most cleanly.
- Whether `block.json` is watched for live reload or only read at arm time. MVP
  proposal: read at arm time only (a rule change means re-arm), for simplicity
  and to avoid mid-session policy flapping.
- Whether audit and enforce counts share the existing `InterceptStatus` footer
  or get their own line. Deferred to the UI step of planning.
