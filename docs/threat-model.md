# CounterSpy — Threat Model

## What CounterSpy is

An on-demand macOS triage tool. It gathers four correlated signals (persistence,
code-signing, TCC privacy grants, process-tree + network), scores and correlates them,
synthesizes a plain-language verdict + recommendation per subject, and — with per-item
human approval — reversibly quarantines (disable + move, never delete) what you choose.

## What it defends against

- **Userland persistence-based spyware**: LaunchAgents/LaunchDaemons pointing at
  unsigned, hidden, or missing/renamed binaries.
- **Privilege-hungry surveillance**: apps holding Input Monitoring + Accessibility
  (keylogger shape), Screen Recording, or Full Disk Access — *when corroborated* by
  another signal.
- **Active beaconing/backdoors**: processes listening on sockets or connecting out,
  attributed to their full ancestry + argv (so a rogue `python3` is seen with what
  spawned it and which script it runs).
- **Identity fraud**: unsigned / non-Gatekeeper-accepted binaries; spoofed signing
  authorities (exact-match allowlist, authority trusted only when Gatekeeper accepts).

## What it explicitly does NOT defend against (non-goals)

- **Kernel implants, firmware/EFI, or anything below userland.** Userland tools only.
- **SIP-protected system components.** Not scanned for action; `/System` is never moved
  (SIP + an explicit refusal).
- **Supply-chain / signed-malware** where the attacker holds a valid Gatekeeper-accepted
  Developer ID. CounterSpy trusts Gatekeeper's verdict; it does not re-adjudicate it.
- **Live processes with no on-disk artifact.** These are surfaced for investigation but
  cannot be quarantined (nothing to move) and CounterSpy will not kill them — a kill is
  irreversible and out of scope for v1.

## Trust boundaries & how each is defended

- **Attacker-controlled `argv[0]`** — never used as identity (process evidence is keyed
  by PID only), so a listener can't alias onto an allowlisted app to hide.
- **Attacker-controlled signing authority string** — only trusted when `spctl` (exit
  code, not free text) accepts the binary; allowlist is exact-match, not substring.
- **Attacker-controlled paths** — the actor canonicalizes (`filepath.Clean`) and
  case-folds before the protected-path refusal, so `..` / case tricks can't smuggle a
  protected path through.

## Safety properties (the trust the tool must earn)

- **Never deletes.** Quarantine only *moves* into a timestamped folder that mirrors the
  original path (collision-proof). Deletion is a separate, manual, human step.
- **Reversible.** `restore` returns every moved artifact byte-identically, and refuses
  to overwrite anything that reappeared at the destination.
- **Recoverable partials.** A quarantine that fails mid-way still writes a manifest for
  what completed, so nothing becomes an unrecoverable orphan.
- **Fails loud.** A collector that can't read its source reports a *gap*; missing
  evidence never reads as "clean."
- **Auditable.** Every verdict is rule-based/deterministic (no LLM in the decision
  path); the `manifest.json` is both the undo and the RCA trail.

## Known limitation — false-positive VOLUME (read before shipping)

On a **developer's machine**, unsigned binaries with LaunchAgents are common and
legitimate (dev tools, self-built software). CounterSpy's Apple-only allowlist does not
recognize third-party Developer-ID software or the user's own tools, so those surface as
Quarantine/Investigate. A real scan of a working Mac produced **~2 actionable findings**
after the dedup fix (down from 260 pre-fix), but one of them was the operator's own
unsigned tool — a *true positive by the heuristic* that is nonetheless not spyware.

**Implication for public release:** the tool is a *triage aid that recommends, the human
decides* — it is not an automatic verdict. Before a general-audience release, the
false-positive volume should be reduced (candidate approaches: extend the allowlist to
Gatekeeper-accepted Developer-ID apps, require stronger correlation before Investigate,
or a first-run "known-good baseline"). This is the primary open question for the ABORT
go/no-go review (§11).
