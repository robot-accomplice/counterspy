# Phase 2 — Transparent TLS-intercepting decrypt mirror — design

**Status:** approved in brainstorming (2026-07-15). Reorders the outbound-visibility program: the
transparent proxy (formerly Phase 3's decrypt half) is pulled forward to **Phase 2** because it is
what actually delivers broad visibility into **already-running** apps' encrypted traffic; SSLKEYLOGFILE
keylog is demoted to a small optional later add-on (it only reaches apps launched with the env var).

## Goal

Give the user broad, honest visibility into their own machine's outbound **TLS** content: a consented,
transparent, **read-only** intercepting proxy that decrypts HTTPS and surfaces the plaintext — without
modifying traffic (redact/block is the next cycle, on top of a proven decrypt layer).

## Locked decisions (from brainstorming)

- **Read-only this cycle.** Relay bytes unmodified; observe only. Redact/block deferred.
- **Routing: transparent pf redirect.** A pf `rdr` rule steers outbound TCP:443 to a local proxy port;
  the proxy recovers the original destination from `/dev/pf` (`DIOCNATLOOK`). Transparent — no per-app
  proxy config — so it catches native apps and already-running daemons (the goal), not just
  proxy-honoring ones.
- **Two cooperating processes.** `counterspy intercept` (root) is a long-lived background proxy;
  `counterspy console` is a separate viewer. The proxy **publishes** decrypted flows; the console reads.
- **Publish outputs chosen at launch.** `intercept` can stream over a **local unix socket** (live,
  ephemeral, nothing on disk) and/or append to a **rotating, size-capped, expiring log file** (the
  `--non-interactive` logging vision) — user selects one or both at launch.
- **Dedicated command + user-approved flags.** `counterspy intercept` (+ `--uninstall`, + the output
  selectors) is a deliberate, visible action, not a buried toggle. Approved despite the standing
  no-new-flags rule because the maintainer is defining this control surface here.
- **Invasiveness is not a gate** (user's own hardware, own data). Engineering rigor is: reliable
  teardown, reversible CA, honest coverage, never corrupt traffic.

## Architecture & data flow

```
$ sudo counterspy intercept --stream[=/path.sock] [--log=/path.jsonl[,size,keep,age]]
  1. consent prompt (spelled out: installs a local root CA + redirects your TLS)
  2. CA: generate/load a local single-purpose CA → install-trusted in the login keychain (reversible)
  3. pf: rdr outbound TCP:443 → 127.0.0.1:<proxyport>     (installed; torn down on every exit path)
  4. proxy accept loop:
        app ─► recover orig dest (/dev/pf DIOCNATLOOK)
               ├─ read ClientHello SNI → mint a leaf cert for it (signed by our CA)
               ├─ terminate the client TLS with that leaf (crypto/tls)
               ├─ dial the REAL server with crypto/tls (verify upstream normally)
               ├─ relay both directions BYTE-FOR-BYTE (unmodified)
               └─ capture plaintext → DecodeCleartext + Redact → publish (socket and/or log)

$ counterspy console      # separate process: connects to the socket and/or reads the log → shows flows
```

## Components

- **`internal/intercept` (new)** — the proxy core, all **stdlib** (`crypto/tls`, `crypto/x509`,
  `net`): accept loop, per-SNI leaf minting via `tls.Config.GetCertificate`, the
  terminate→re-dial→relay pump, and plaintext capture into flow records. **CI-testable end-to-end over
  loopback** (a throwaway CA + an in-process client↔proxy↔server), no root/pf.
- **`internal/intercept/ca` (new)** — generate/load the local CA, install/uninstall trust
  (`security add-trusted-cert` / `security remove-trusted-cert`), mint leaves. Reversible.
- **`internal/intercept/publish` (new)** — the flow-record sink(s): a unix-socket server (stream) and
  a rotating/size-capped/expiring file writer. Console-side reader too. Flow record = metadata (pid if
  recoverable, dest name/ip, SNI, timing, bytes) + decoded, Redact-masked content.
- **darwin pf edge (`internal/intercept/pf_darwin.go`)** — install/teardown `rdr` rules; original-dest
  recovery via `DIOCNATLOOK` on `/dev/pf`. The untestable OS I/O edge — compile-guarded + manual
  root smoke test, same pattern as `bpf_darwin.go`. Non-darwin: a stub that refuses.
- **`main` — `intercept` command** — consent, wire CA + pf + proxy + publisher, and the teardown
  contract. `console` — a new reader that surfaces intercepted flows alongside the live egress monitor.

## Safety rails (engineering, not gatekeeping)

- **Reliable teardown is the #1 requirement.** pf rules and the trust change are reverted on **every**
  exit path — `defer`, SIGINT/TERM/HUP handlers, and panic recovery — exactly like the TUI's terminal
  restore. Leaving a user's TLS redirected or a CA trusted after a crash is the worst failure; a
  self-heal `counterspy intercept --uninstall` removes any leftover pf rules + the CA idempotently.
- **Consent + reversibility.** The CA install + traffic redirect is gated behind an explicit,
  spelled-out prompt; the CA is local, single-purpose, and one command to remove.
- **Honest coverage.** Cert-**pinned** apps reject our leaf → their handshake fails; we detect it,
  report the host `pinned · not decryptable`, and keep a **bypass list** (pf exceptions) so a
  pinned/critical app is *excluded rather than broken*. Non-TLS / QUIC / opaque flows stay honestly
  labeled. Never claim decryption we didn't achieve.
- **Upstream verified.** The proxy verifies the REAL server's certificate normally — interception does
  not disable upstream trust (we don't become a downgrade vector).
- **Secrets.** Decrypted content runs through `model.Redact` before it is shown or logged; the rotating
  log is under the invoking user's home at 0600 and expires.

## Non-goals (this cycle)

- No traffic modification (redact/block) — next cycle.
- No QUIC / HTTP-3 (UDP/443, not TCP) — stays opaque, labeled.
- No decryption of cert-pinned apps (bypassed, not broken).
- Not a general MITM — only this host's own outbound, consented.

## Testing

- **Loopback integration (CI, no root):** a throwaway CA, an in-process TLS server, a client dialed
  through the proxy → assert the proxy decrypts and captures the plaintext, relays unmodified, and that
  a pinned client (verifies a fixed cert) fails the handshake and is reported honestly.
- **CA unit:** generate → install path mocked; leaf minting produces a valid chain to the CA; SNI → leaf.
- **Publish unit:** socket stream round-trips a flow record; the rotating writer honors size/keep/age.
- **darwin edges** (pf `rdr` + `DIOCNATLOOK`, keychain trust): manual root smoke test behind a compile
  guard; non-darwin stub refuses.
- Gate: `go test ./... -race`, coverage ≥80% total, `go vet`, `gofmt`, `GOOS=linux` build, `architext
  validate`. Decoupling + egress-only invariants unaffected (the proxy is a new subsystem; the TUI
  reads flow records as data).

## Control surface (approved)

- `counterspy intercept [--stream[=sock]] [--log[=path,maxsize,keep,maxage]] [--uninstall]` — the
  consented background proxy; at least one output selected, else a sensible default (stream).
- `counterspy console` gains an intercepted-flows source (socket and/or log reader), shown with the
  existing `DecodeCleartext` + `Redact` rendering.

## Architext / roadmap updates (on implementation)

- Reorder roadmap: `roadmap-egress-payload-inspection` → **Phase 2 (this proxy, decrypt-only)**; add a
  later item for the **redact/block active controls**; demote `roadmap-egress-keylog-decrypt` to an
  optional add-on. New `mod-intercept` node; a `decrypted-flow` data class (sensitive: decrypted
  content, ephemeral or short-lived under home); a trust-boundary note for the CA + pf redirect.
- Records the crossing of the observe-only line is deferred to the *modify* cycle; this cycle stays
  read-only, so the network path remains observe-only in behavior even though it now terminates TLS.
