# Intercept → Exfiltration view merge — design

**Date:** 2026-07-21 · **Branch:** feat/tls-intercept · **Driver:** v0.7.0 ABORT re-run
(fixes bounced because the merge was coded before the while-armed reality was designed).

## Problem

While the intercept proxy is armed, the byte-level egress view (nettop/lsof) is distorted:

- Proxy-honoring apps connect to `127.0.0.1:<proxyport>` (the CONNECT proxy) — NOT their real
  destination.
- The separate `intercept` daemon process re-dials the real upstreams under its OWN pid, so the
  real destinations appear attributed to counterspy.

Therefore the **intercept stream is the authoritative source** of "app → real destination +
decrypted content." The merge must respect that. The first wiring did not, producing: a join-key
mismatch, self-exclusion on the wrong process, and a decrypted-dest marker that can never fire.

## Design

1. **Join by PID, not path.** `InterceptedMessage.PID` and egress `Instance.PID` are the same
   originating app pid, so the join is exact and I/O-free — eliminating the `ps comm`
   (egress `g.Path`) vs `proc_pidpath` (`msg.Path`) mismatch. `EgressModel.Messages` is re-keyed
   `map[int][]InterceptedMessage` by PID; `interceptSummary` aggregates across the zoomed group's
   member PIDs (newest last, bounded).

2. **Self-exclusion by canonical self-path.** `egress.Monitor` excludes any instance whose
   executable path canonicalizes (EvalSymlinks, best-effort) to the console's own
   `EvalSymlinks(os.Executable())`. Same binary as the daemon → the daemon's relay dials are
   dropped regardless of pid; a trojaned copy at a different path stays visible. Always on (a
   security tool showing its own traffic is noise). Replaces the wrong `os.Getpid()` PID delete.

3. **Proxied marker from `ProxyAddr`.** While armed an app's decrypted destination IS the loopback
   proxy, so mark the app/connection whose endpoint == `ProxyAddr` as "decrypted (proxied)"; the
   REAL destinations are shown per-message from the intercept stream in `interceptSummary`. The old
   `destDecrypted` vs `InterceptedDests` (external IP) marker is removed — it can never match while
   armed. `InterceptedDests` is dropped (dead once the marker is gone).

4. **Version / malformed errors surfaced.** `scanMessages` synthesizes error events with empty
   Path/PID; these currently land unreachable. Route them to a **global console status line**
   (`EgressModel.InterceptStatus`) rendered in the Exfiltration footer, not a per-app pane.

5. **Drop accounting fixed.** `MessageDropCount` becomes per-PID (`map[int]int`) so a bounded
   buffer's drops are attributed to the right app; `interceptSummary` shows the count for the
   zoomed app's PIDs. (Socket-sink server-side `Dropped()` is out of scope — it is the daemon's
   counter, not visible to the console process.)

## Mechanical fixes (same batch, from the re-run)

- **F-A:** `copyTee` returns whether it detached; on first detach `runRelay` calls
  `markOpaque("tee detached — capture incomplete under load")` so a parser falling behind is an
  honest degraded signal, never a silent drop.
- **Socket 0700:** `NewSocketSink` explicitly `chmod`s the unix socket to 0600 rather than relying
  on ambient umask.
- **proxyAddr honesty:** only assert the proxy endpoint in the view once ingestion has actually
  produced at least one event (or the socket dialed), so the pane never claims an active proxy that
  isn't there. (Implementation: keep `ProxyAddr` as the mode gate but the empty state says
  "waiting for <addr>" until the first message.)
- **D1:** reconcile `releases/v0-7-0-tls-intercept.json` + `releases/index.json` wording
  (InterceptedFlow → per-message; Intercepted TUI → Exfiltration view) and honest status.

## Explicitly NOT doing (YAGNI / deferred)

- Re-attributing the whole byte-view (loopback→real dest) across every row — the intercept stream
  already gives the accurate per-app picture; a full rewrite is disproportionate.
- The arming-window trust race — pre-existing, accepted, narrow, self-heals via `--uninstall`.
- Spoofed-`/tmp`-socket peer-credential check — real but a separate hardening item; the socket
  0600 + the daemon's own `removeIfSocket` are the in-scope mitigations. Flagged for follow-up.

## Testing

- PID-join: an `InterceptedMessage{PID:n}` renders under a group whose member has `PID:n`, even when
  `g.Path` != `msg.Path` (the mismatch case that motivated this).
- Self-exclusion: an instance whose path == self canonical path is dropped; others remain.
- Proxied marker: a connection to `ProxyAddr` is flagged; unrelated dests are not.
- Version-error routing: a synthesized error event sets `InterceptStatus`, not a phantom `""` app.
- F-A: the large-unmatched-response relay test also asserts a `FlowOpaque` "tee detached" event.
- Per-PID drop count: overflow on PID A is not reported under PID B.
