# Changelog

All notable changes to CounterSpy are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/) and stays in `0.x` until the field
false-positive rate is measured (see the threat model).

## [0.4.0] — 2026-07-11

First release cut to `main`, containing all work from the `0.1`–`0.4` development line.

### Added
- **Egress monitor** (`counterspy egress`) — a live per-application outbound "top" built
  by polling `nettop` + `lsof` under sudo (no entitlements, no packet capture, reads no
  payloads). Per-app rollup of rate, destinations, and cadence through the trust/provenance
  lens, with an **inferred exfiltration risk** (capability × egress — candidate categories,
  never confirmed content). Live TUI (expand/collapse, concern color, sparkline) with a
  non-TTY report / `--json` fallback.
- **Field feedback loop** (`counterspy feedback`) — opt-in, **off by default**, egress-only.
  `g`/`b` label findings true/false-positive; anonymous heuristic fingerprints push to a
  configured write-only endpoint. Three-way consent (`off`/`ask`/`always`); the push-only
  invariant is enforced in code (`TestEgressOnly`).
- **Interactive TUI** (`counterspy tui`) — master-detail triage over the scan, live or from
  a `--from` snapshot, with consented quarantine/restore through the hardened act path.
- **CLI** (`counterspy scan`) — read-only ranked report, `--json`, `--interactive`
  quarantine loop, and `restore`. Real `-h`/`--help`/`--version` + rich usage.

### Engineering
- GitHub Actions CI (macOS runner): gofmt / vet / build / `go test -race` + a **≥80%
  coverage gate** (project rule); Codecov upload. Exec edges (`nettop`/`lsof`/`ps`/
  `codesign`/TCC) and the terminal are behind injectable seams so CI runs without sudo or
  tools. Overall coverage ~91%.
- MIT licensed. Architecture + Release Truth tracked under `docs/architext/data/`.

### Deferred
- Real egress destination names (SNI/DNS) via packet capture → v0.4.1 (issue #3).
- Field false-positive measurement (0.x → 1.0 gate) pending an ingest endpoint + userbase
  (issues #5, #6).

## [0.3.0] — feedback loop
Opt-in anonymous field feedback so the false-positive rate can be measured from the userbase.
(Developed on the `0.x` line; first shipped to `main` as part of 0.4.0.)

## [0.2.0] — interactive TUI
tcell master-detail triage face over the scan pipeline; ABORT-gated.

## [0.1.0] — CLI
The three-phase pipeline: collect (read-only) → score (pure) → interpret → report / act
(consented, reversible move-not-delete). ABORT-gated.

[0.4.0]: https://github.com/robot-accomplice/counterspy/releases/tag/v0.4.0
