# CounterSpy 🕵️

A macOS command-line tool that triages your Mac for spyware-like activity, ranks what
it finds with plain-language recommendations, and — with your approval — **reversibly**
quarantines suspicious items. It never deletes.

> **Status:** functional v1 (CLI). It runs end-to-end and is validated on a real Mac.
> See [known limitation](docs/threat-model.md#known-limitation--false-positive-volume-read-before-shipping)
> before treating its output as verdicts — it recommends, you decide. A TUI is planned
> (post-v1); see the [interactive mockup](docs/mockups/counterspy-tui.html).

## Build

```sh
go build -o counterspy .
```

Requires Go 1.21+. No third-party dependencies.

## Use

```sh
sudo ./counterspy scan                # ranked report (READ-ONLY, never mutates)
sudo ./counterspy scan --json         # machine-readable []Assessment (feeds CI / the ABORT gate)
sudo ./counterspy scan --interactive  # walk findings top-down: quarantine per item (y/N/q)
sudo ./counterspy restore <manifest>  # undo a prior quarantine

sudo ./counterspy tui                 # interactive triage TUI (navigate, quarantine, restore)
./counterspy tui --from scan.json     # drive the TUI from a `scan --json` snapshot (no sudo)
```

The **TUI** is a master-detail triage view (tcell): `j/k` navigate, `q` quarantine (with a
confirm + reversibility prompt), `u` restore this session, `m`/`s`/`/` toggle Monitor/sort/
filter, `?` help, `Q` quit. It needs a real terminal; piped, it tells you to use `scan`.

Run under `sudo` for full visibility — without it, the TCC (privacy-grant) signal is
unavailable and the report says so (it never silently reads as "clean").

## How it works

A strict three-phase pipeline (see [design spec](docs/superpowers/specs/2026-07-08-counterspy-design.md)):

```
collect (read-only) ──▶ score (pure) ──▶ interpret ──▶ report / act (consented)
 persistence                weighted      verdict +      exec summary +
 codesign          ──▶      correlation   category +  ▶  ranked findings;
 tcc                        + tripwires   recommendation  quarantine = disable+move
 process+network                                          (reversible, manifest)
```

- **Synthesis, not a dump.** The report leads with an executive summary and shows only
  actionable findings (Quarantine / Investigate); low-signal Monitor items are counted,
  not detailed.
- **Correlated evidence.** A listener spawned by a LaunchAgent from an unsigned binary
  that also holds Input Monitoring is one story told four ways — that correlation is how
  it beats single-signal noise.

## Safety guarantees

- **Never deletes** — quarantine only moves, into `~/CounterSpyQuarantine/<timestamp>/`.
- **Reversible** — `restore` round-trips byte-identically and refuses to clobber.
- **Never touches** Apple-signed/allowlisted items or protected system paths.
- **Fails loud** — a collector that can't read reports a gap, never silence.
- **Auditable** — deterministic, rule-based verdicts; `manifest.json` is undo + RCA trail.

## Field feedback (opt-in)

CounterSpy can measure its own false-positive rate from the field — but only if you
opt in. **It is off by default and never phones home unless you turn it on.**

In the TUI, press `g` to mark the selected finding a **false positive** (legitimate) or
`b` to confirm it was **correctly flagged**. Labels are stored locally under your home
(`~/.config/counterspy/`, resolved to the invoking user even under `sudo`).

Sharing is a separate, consent-gated step controlled by `~/.config/counterspy/feedback.json`:

```jsonc
{
  "share": "off",      // "off" (default) | "ask" (confirm each session) | "always"
  "detail": "public",  // "public" (default) | "full" (also include private identity + path)
  "endpoint": ""        // your push-only submission URL; empty = local export file only
}
```

What leaves your machine is an **anonymous fingerprint**, never raw data: the signals that
fired, a score *band*, the category, code-sign status, and a path *class* — no raw paths,
usernames, or hostnames. An app's identity is included only when it's recognizably public
(Apple-namespace or Gatekeeper-notarized); a private app's identity stays local unless you
choose `detail: "full"`. Use `counterspy feedback list` to see exactly what's queued and
`counterspy feedback submit` to send with a confirmation prompt.

**Egress-only by design:** the feedback channel is push-only. It sends; it never *reads*
from the network — no remote config, no fetched allowlists, no update checks. An
anti-spyware tool must never be remotely steerable, so this is enforced in code
(`TestEgressOnly`), not just promised.

## Not for

Kernel/firmware implants, SIP-protected components, or signed supply-chain malware —
see the [threat model](docs/threat-model.md) for the full scope and non-goals.
