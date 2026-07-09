# CounterSpy — Field Feedback Loop (v0.3.0) — Design

**Status:** approved (brainstorm), ready for implementation planning
**Date:** 2026-07-09
**Depends on:** v0.2.0 TUI (shipped, ABORT-gated at rc3)

## Problem

CounterSpy's public-readiness blocker is an unmeasured real-world false-positive
rate. The author has a single test Mac, so a fleet measurement is impossible
solo. This feature lets the **userbase become the fleet**: users label findings
true/false-positive, and anonymous fingerprints flow back so the author can
measure the false-positive rate and cull community-wide false positives — without
CounterSpy ever behaving like the thing it hunts.

## Non-goals

- No accounts, no persistent device ID, no login.
- No network **reads** of any kind (see the Egress-Only Invariant).
- No auto-applying community data to shipped heuristics.
- No blocking of triage on telemetry — feedback is always best-effort.
- Not the v0.4.0 egress monitor (see Future).

## Core principle — anonymity lives in the data, not the transport

Every record is intrinsically anonymous: a heuristic **fingerprint** + the user's
label + tool version + a throwaway nonce. Because the payload carries zero
identifying bytes (paths become classes, no usernames/hostnames), no sink can leak
the user through content. Privacy is decoupled from the wire.

## The Egress-Only Invariant (hard rule, enforced by test)

The feedback mechanism is **push-only and unidirectional for any destination**,
now or future. Enforced at three layers:

1. **Type layer — write-only by signature.** `Transmitter` has exactly one
   method, returning only an error:
   ```go
   type Transmitter interface {
       Send(ctx context.Context, records []model.FeedbackRecord) error
   }
   ```
   No `Fetch`/`Poll`/`Config` — nothing hands the network a way to speak back
   into program state.
2. **Response layer — one bit crosses back.** `httpTransmitter` POSTs, reads
   **only** the HTTP status code (keep-for-retry vs. clear), and discards the
   response body without parsing it. The endpoint cannot return an allowlist,
   command, or config the tool acts on.
3. **Capability layer — the tool never pulls.** No remote config, no remote
   allowlist/denylist fetch, no update check. All heuristics stay local and
   deterministic; the network can receive from CounterSpy, never direct it.

Enforced by `TestEgressOnly`: `internal/feedback`'s only outbound-network call
site is `Send`, and no HTTP response body is ever decoded into program state.
Survives refactors and any later swap of destination — the constraint is on the
mechanism, not the current sink.

## Architecture — one isolated seam, mirroring the `Actor` pattern

```
label (TUI/CLI) → feedback.Capture → feedback.Minimize → [review] → Transmitter.Send
```

- **New `internal/feedback` package**: pure `Capture` (Assessment + label →
  Record) and `Minimize` (deterministic scrub — code, not judgment). No I/O in
  the pure core.
- **`Transmitter` interface** (write-only, above). Two implementations:
  - `fileTransmitter` — appends JSONL locally; the build/test stub and the
    manual-export path. Ships first; the whole pipeline is testable without infra.
  - `httpTransmitter` — POSTs to the author-owned Worker URL from config.
- **`internal/tui` still imports only `internal/model`** (decoupling invariant
  holds). Labeling a finding emits a `Cmd`; `main` hands it to `feedback` — the
  same wiring seam already used for `cliActor`.

## Data model

`model.FeedbackRecord` (new type in `internal/model`):

```jsonc
{
  "schema": "1",                 // record schema version
  "tool": "v0.3.0",              // ToolVersion — weights/allowlist provenance
  "nonce": "<random hex>",       // per-submission, non-correlatable
  "label": "false_positive" | "true_positive",
  "recommendation": "quarantine|investigate|monitor",  // what the tool said
  "category": "surveillance-capable|keylogger|backdoor|…",
  "score_band": "0-4|5-9|10-14|15+",   // banded, not exact (anti-fingerprinting)
  "signals": ["persistence","codesign","tcc","proctree-network"],  // kinds that fired
  "codesign": "unsigned|adhoc|signed|notarized",
  "path_class": "system|user-library|hidden|tmp|other",  // class, never the path
  "tripwire": true,
  "identity": "com.docker.docker" | "",  // see Identity policy; a consented PRIVATE
                                         // identity populates THIS field (not extra)
  "extra": { }                   // reserved for detail=full opt-in only: richer,
                                 // non-identity context (e.g. raw path, argv).
                                 // Absent under detail=public.
}
```

Score is **banded, not exact** — mild anti-fingerprinting; costs a little
analytic resolution. Banding, path-class mapping, signal extraction, and
identity gating are all deterministic functions (Rule 6 — code answers).

### Identity policy — first-class for false positives

For a **false positive**, the app's identity is the actionable payload — you
can't remove something from the list without knowing what it is. So identity is a
first-class, always-*attempted* field on FP reports, gated by who can act on it:

- **Public / notarized identity** (Apple bundle ID, notarized vendor Team ID):
  captured **automatically**. These are the community-wide false positives worth
  culling and are already world-public, so publishing them is safe.
- **Private / custom identity** (custom bundle ID, or path-derived identity):
  removed via the **local allowlist** (already supported, zero network — the
  identifier never leaves the machine). For the *community* dataset it is only
  included when the user consents: `ask`-mode users may choose to include it;
  `detail = full` users opt into standing inclusion.
- `always + detail=public` users' private FPs stay fingerprint-only **by
  principle** — a private identifier is never published to a world-readable
  dataset without consent.

Net: every false positive is removable — community-wide (public identity,
automatic) or locally (private identity, no network) — with no private identifier
published without explicit consent.

"Recognizably public" is decided by a deterministic classifier: Apple-namespace
bundle IDs, and Team IDs/bundle IDs that pass Gatekeeper notarization
(`spctl` accept), are public; everything else is private. (Reuses the existing
codesign/spctl signals — no new collection.)

## Consent & config — the three-way model

Config file under the **invoking user's** home, resolved via `SUDO_USER`
(not root's home):

- `share = off` (default) — never touches the network.
- `share = ask` — shows the exact records to be sent; user redacts/cancels.
- `share = always` — standing consent; conservative auto-policy (public identity
  only unless `detail=full`).
- `detail = public` (default) | `full` — the opt-in richer-data toggle.

Default is silence: a fresh install shares nothing until the user explicitly
opts in. Consent is revocable (flip back to `off`).

## Labeling UX

- **TUI (natural home):** two keys on the selected finding — `g` "good / false
  positive," `b` "bad / correctly flagged." The label persists to the local
  feedback store immediately, so `ask`-mode review, offline retry, and manual
  export all work. A small on-screen confirmation (reuses the toast surface).
- **CLI:** `counterspy feedback` — list queued labels, submit, or export. Serves
  non-TUI use and scripted flows.

## Submission — batched, deduped, degrades gracefully

Labels accumulate in the local store, **deduped by fingerprint** (relabeling
updates, doesn't duplicate). Submission fires at **end-of-session**:

- `ask` → review prompt showing exact bytes, then send-or-cancel.
- `always` → best-effort POST.

If offline or the Worker is unreachable, records **stay local** and retry next
run. Triage never blocks; a failed send is surfaced (loud) but non-fatal.

## Transport — Worker + GitHub transparency mirror

A ~30-line **Cloudflare Worker** (free tier, non-pausing) exposes **only**
`POST /v1/feedback`: schema-validate, size-cap, rate-limit by IP, append to
R2/D1. No GET, no read path — physically unidirectional. The author periodically
publishes the aggregated (already public-safe) dataset to a public GitHub repo:
transparency without users needing GitHub accounts.

**The Worker is an author-owned prerequisite.** The client ships against a
config'd URL and is fully buildable/testable now via `fileTransmitter`; the
Worker can be stood up in parallel or after.

## Trust, poisoning, security

- Crowd labels are **advisory only**. The author reviews before anything
  influences shipped weights/allowlist; nothing auto-applies. (Otherwise malware
  authors could submit "false positive" on their own fingerprints to train
  suppression.) The write-only client can't be fed a remote allowlist, so
  determinism is preserved.
- TLS; no client secrets embedded (the endpoint needs no client auth).
- The nonce is per-submission and non-correlatable — it deduplicates a single
  submission's records, not a user across submissions.
- Sybil/flood risk on an unauthenticated endpoint is mitigated server-side (size
  caps, IP rate-limits) and by maintainer review; residual and accepted.

## Testing strategy

- **`Minimize` — heaviest coverage.** Property tests: no raw path/label/username/
  hostname ever survives scrubbing; path→class mapping is total; score banding is
  correct at boundaries; public-vs-private identity gating (a private bundle ID is
  dropped under `public`, kept under `full`/consent).
- **`TestEgressOnly`** — the invariant guard (no response-body decode; single
  network call site).
- **Consent gates:** `off` never calls `Send`; `ask` requires confirmation;
  `always` auto-sends. Tested with a fake `Transmitter`.
- **TUI labeling** via the existing `SimulationScreen`: `g`/`b` produce the right
  label Cmd and toast; the decoupling invariant test still passes.
- **`fileTransmitter`/`httpTransmitter`** via a fake HTTP server asserting POST,
  status-only handling, and body-discard.

## Future — v0.4.0 privacy egress monitor (out of scope here)

The next major push: **live tracking of what certified/legitimate apps actually
send** — moving CounterSpy from "is this spyware?" to "this app is trusted, but
here's what it's exfiltrating; do you consent?" A distinct subsystem (per-process
network observation, destination/volume tracking, consent deltas) with its own
spec. Recorded here so its rationale isn't lost; to be added to the roadmap.

## Sequencing

New minor release **v0.3.0**. Build order (detailed in the implementation plan):
model types → `feedback.Minimize`/`Capture` (pure, TDD) → local store +
`fileTransmitter` → consent/config → TUI/CLI labeling → `httpTransmitter` +
`TestEgressOnly` → author stands up the Worker.
