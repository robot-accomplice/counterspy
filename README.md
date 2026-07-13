# CounterSpy 🕵️

[![CI](https://github.com/robot-accomplice/counterspy/actions/workflows/ci.yml/badge.svg)](https://github.com/robot-accomplice/counterspy/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/robot-accomplice/counterspy/graph/badge.svg)](https://codecov.io/gh/robot-accomplice/counterspy)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![platform](https://img.shields.io/badge/platform-macOS-000000?logo=apple&logoColor=white)
![dependencies](https://img.shields.io/badge/deps-stdlib%20%2B%20tcell-1f6feb)
![status](https://img.shields.io/badge/status-active-success)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A macOS command-line tool that triages your Mac for spyware-like activity, ranks what
it finds with plain-language recommendations, and — with your approval — **reversibly**
quarantines suspicious items. It never deletes.

> **Status:** active. The scanner, the interactive **TUI**, and the opt-in **feedback loop**
> ship today; the **Exfiltration monitor** (`counterspy console`, Tab to switch) lands in v0.4.0. See the
> [known limitation](docs/threat-model.md#known-limitation--false-positive-volume-read-before-shipping)
> on false-positive volume before treating output as verdicts — it recommends, you decide.

<p align="center">
  <img src="docs/screenshots/tui.png" alt="CounterSpy interactive triage TUI: findings ranked by concern with an evidence and provenance detail pane" width="900">
</p>

<p align="center"><em>Interactive triage TUI — findings ranked by concern, with correlated evidence and provenance. Below: the plain CLI report — synthesis, not a dump.</em></p>

<p align="center">
  <img src="docs/screenshots/scan.png" alt="CounterSpy CLI scan report: 1 actionable of 335 scanned, the rest counted" width="900">
</p>

## Install

**Prebuilt binary** — a checksum-verified universal binary (Apple Silicon + Intel), no Go toolchain needed:

```sh
curl -fsSL https://raw.githubusercontent.com/robot-accomplice/counterspy/main/install.sh | sh
```

**Homebrew** *(once the tap is published)*:

```sh
brew install robot-accomplice/tap/counterspy
```

**Manual** — download a `.tar.gz` from [Releases](https://github.com/robot-accomplice/counterspy/releases)
and extract. Builds aren't notarized yet (signing is imminent) — `curl | sh` and Homebrew sidestep
Gatekeeper, but a *browser* download needs `xattr -d com.apple.quarantine ./counterspy` before first run.

## Build (from source)

```sh
go build -o counterspy .
```

Requires **Go 1.26+** and the macOS SDK (cgo — code-signature checks call
`Security.framework` in-process). No third-party dependencies beyond
[`tcell`](https://github.com/gdamore/tcell) (vendored) for the terminal UI; everything else
is the Go standard library and system frameworks.

## Use

```sh
sudo ./counterspy scan                # ranked report (READ-ONLY, never mutates)
sudo ./counterspy scan --json         # machine-readable []Assessment (feeds CI / the ABORT gate)
sudo ./counterspy scan --interactive  # walk findings top-down: quarantine per item (y/N/q)
sudo ./counterspy restore <manifest>  # undo a prior quarantine

sudo ./counterspy console             # interactive UI: Findings + Exfiltration (Tab to switch)
./counterspy console --from scan.json # drive Findings from a `scan --json` snapshot (no sudo)

sudo ./counterspy console             # then Tab to Exfiltration: per-app outbound traffic + concern
sudo ./counterspy console --json      # one-shot, machine-readable Exfiltration snapshot (non-TTY)
```

The **TUI** is a master-detail triage view (tcell): `j/k` navigate, `q` quarantine (with a
confirm + reversibility prompt), `u` restore this session, `m`/`s`/`/` toggle Monitor/sort/
filter, `?` help, `Q` quit. It needs a real terminal; piped, it tells you to use `scan`.

Run under `sudo` for full visibility — without it, the TCC (privacy-grant) signal is
unavailable and the report says so (it never silently reads as "clean").

## Reading the marks

Each finding is tagged with a four-slot glyph cluster —
`[concern] [trust] [run-state] [socket]` — read left to right. Color also encodes
the concern tier, so the marks never rely on color alone. This key is generated
from the code, so it always matches what the tool emits:

<!-- BEGIN LEGEND (generated) -->
| Mark | Axis | Meaning |
|---|---|---|
| ⚑ | concern | quarantine |
| ▲ | concern | investigate |
| · | concern | monitor |
| ● | trust | Apple system code |
| ◆ | trust | notarized (Developer ID, accepted) |
| ◇ | trust | signed, not notarized |
| ○ | trust | unsigned |
| ⊘ | trust | revoked certificate |
| ▸ | liveness | running |
| † | liveness | vestigial (installed, not running) |
| ↔ | liveness | live network socket |
| ▣ | encryption | TLS-encrypted flow (□ = cleartext) |
<!-- END LEGEND -->

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

## Exfiltration monitor (v0.4.0)

The Exfiltration monitor (`counterspy console`, Tab) answers the complementary question to the scanner — not *"is this
spyware?"* but *"this app is trusted; what is it sending, where, and how much?"* It's a live,
per-application "egress top" built by polling `nettop` + `lsof` under sudo (no entitlements,
no packet capture, no payloads read):

- **Per-app rollup** — every PID, port, and protocol of an app collapses into one row you can
  expand; outbound rate, destinations, and a cadence (one-off / bursty / steady / periodic).
- **Trust + provenance lens** — each row carries its code-sign trust and process ancestry, so a
  notarized app talking to its vendor reads as *expected* while an unsigned background daemon
  uploading to a raw IP reads as *elevated*.
- **Inferred exfil risk** — capability × egress: an app that holds Screen Recording or Input
  Monitoring **and** is uploading gets flagged with the candidate data categories it *could* be
  leaking. Inference, never confirmed content — CounterSpy reads no payloads.

Piped or with `--json`, it prints a one-shot report instead of the live view. Real destination
*names* (SNI/DNS) are a roadmapped enrichment (v0.4.1); v1 shows `IP:port`.

## Testing

Deterministic, mock-driven, and CI-safe: the exec edges (`nettop`, `lsof`, `ps`, `codesign`,
TCC) and the terminal are behind injectable seams, so the whole suite runs in GitHub Actions
without sudo or external tools. Coverage is gated at **≥80%** per package in CI (currently
**91%** overall).

```sh
go test ./...                          # full suite
go test ./... -cover                   # per-package coverage
```

## Not for

Kernel/firmware implants, SIP-protected components, or signed supply-chain malware —
see the [threat model](docs/threat-model.md) for the full scope and non-goals.
