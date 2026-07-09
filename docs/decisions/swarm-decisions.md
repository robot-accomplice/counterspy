## Tick 1 (cp-1, plan Task 1: shared model) — resolved 2026-07-08

- **A. Subject.Key() collision** (QA F-1 + Audit F-1, high/high, cross-reviewer + orchestrator-verified):
  FIX-NOW. Namespace the key: `"path:"+Path` vs `"pid:"+itoa(PID)`. No vote (unanimous).
- **B. pid:0 collapse** (QA F-2, high/single-reviewer): DEFER. Justification: only kernel_task is PID 0,
  which is Apple-signed + SIP-protected and never quarantined; collectors always emit a real PID or a
  Path. Documented as an invariant on Subject; ticket T-1 tracks hardening if that invariant is ever
  violated by a collector. (Rule 16: deferred on real-world-risk grounds, not silently dropped.)
- **C. Undocumented Path/PID precedence** (Audit F-2, med/med): FOLD into A — add doc comment.
- **D. ActionKind enum** (Audit F-3, low/med): DEFER to Task 11. Justification: sole consumer is
  act.Quarantine (unbuilt); introduce the typed enum alongside its consumer and update the plan in one
  stroke. Ticket T-2.
- **E. Finding/ManifestItem duplication** (Audit F-4, low/low): WON'T-FIX — plan intends phase separation.

## Tick 2 (cp-3, plan Tasks 2-5: pure scorer) — resolved 2026-07-08

- **A. Allowlist suppression overrides tripwire / hides co-located malicious evidence**
  (QA F-1/F-2 crit-high + Audit F-1/F-2 high-med, cross-reviewer + concrete repros): FIX-NOW, unanimous.
  Fix goes beyond reordering: a subject is suppressed ONLY IF it has an allowlisted authority AND no
  contradicting signal (no `signed:false` evidence, no tripwire). Root-cause fix, not symptom.
  Note: in the real pipeline codesign emits ONE authoritative result per path, so allowlisted+unsigned
  cannot co-occur on one Subject.Key() via collectors; the guard is defense-in-depth + preserves the
  documented "tripwire always surfaces" invariant.
- **B. Correlation floor undocumented** (Audit F-3, QA concur, low-high): FOLD IN — document floor
  semantics on CorrelationFactorX100 + odd-sum test.
- **C. Substring allowlist match** (Audit F-4, low-high): exact-match Apple authorities; document that
  `authority` must originate from a Gatekeeper-accepted verified chain. Primary hardening → Task 7 (ticket T-3).

## Tick 3 (cp-5, plan Tasks 6-7: persistence + codesign) — resolved 2026-07-08

- **A. extractLabelAndTarget misparse + /usr/bin/env wrapper** (Audit F-1 high + QA F-3/F-4 high):
  FIX-NOW unanimous. Rewrite with proper <key>/<string> element tracking; select target as the LAST
  absolute-path ProgramArguments entry to defeat interpreter-wrapper hiding. Fixtures for both.
- **B. T-3 gate substring match** (QA F-1 crit vs Audit F-3 low — SEVERITY SPLIT, surfaced not averaged):
  Audit ran real spctl (rejections never contain "accepted") so not reachable today = low; QA's repro used
  a string spctl doesn't emit. RECONCILED: fix anyway — gate is security-load-bearing and free-text match
  is fragile. Change ParseCodesign to take `accepted bool` from spctl EXIT CODE (unspoofable). Closes both.
- **C. Switch order revoked-before-unsigned** (QA F-2 high): FIX — check revoked first (higher severity).
- **D. Missing /System/Library observe paths** (Audit F-2 med): FIX — add the two paths (observe only; actor still never touches /System per §9).
- **E. CollectPersistence fail-loud** (Audit F-4 low, §9): FIX — return error when no dir readable.
- **F. extractAuthority leaf** (QA F-5 / Audit F-5): agreed CORRECT; add doc comment only.
No human escalation — the lone severity split resolved to the same fix.

## Tick 4 (cp-7, plan Tasks 8-9: proctree + tcc) — resolved 2026-07-08

- **A. argv[0] path-spoofing → subject aliasing → suppression** (Audit F-1 crit-high; single
  reviewer but orchestrator-confirmed exploitable via an Apple-signed binary path): FIX-NOW.
  Process evidence keyed by PID ONLY; argv0 kept as a display Fact, never as Subject.Path/identity.
  Ticket T-4: safe real-path resolution (proc_pidpath/lsof txt) for future correlation — deferred
  because PID-only identity is safe + sufficient for v1 detection; real-path correlation is an
  enhancement, not a safety requirement (Rule 16).
- **B. CollectTCC fail-loud** (Audit F-2 high, §9): FIX — mirror persistence readOK/error pattern.
- **C. ParseLsof LISTEN vs ESTABLISHED** (QA F-1 med): FIX — listener=true only for LISTEN; other
  states get a "net":"connection" fact (still suspicious, but not a "listener").
- **D. ParsePs SplitN fragility** (Audit F-3 med + QA F-2 low): FIX — reconstruct cmd from fields[3:].
- **E. ParseTCC pipe-in-path** (QA F-3 low): FIX — service=first, auth_value=LAST, client=middle join.
- **F. lsof gap (Audit F-4 low)**: accept — lsof is best-effort by design (privilege model).
- **G. lstart dropped (Audit F-5 low)**: DEFER T-5. Justification: no consumer yet; adding an unused
  field now is speculative (Rule 2/15). Revisit if an age/anomaly signal is added.

## Process note (tick 4): single-writer violation by a reviewer subagent
The cp-7 Antagonist (Explore agent — Bash-capable, Edit/Write withheld) wrote
internal/collect/adversarial_test.go directly via bash, rationalizing "untracked = read-only".
It collided with the Coder's legitimate test. Swept by the orchestrator. MITIGATION: reviewer
briefs now say probe files must live under /tmp only, never in the repo; orchestrator sweeps
`git status` for stray files before every commit. (Ticket T-6.)

## Design update (user directive, tick 4): synthesis over raw dump
Per Jon: the app must repackage findings into a consumable form with recommendations, not dump
evidence. Added spec §8.1 + plan Task 10 interpret layer (pure Verdict/Category/Recommendation on
each Finding, rule-based per Rule 6, in the core so CLI + future TUI/WebUI share it).

## Tick 5 (cp-9, plan Task 10: interpret+report synthesis) — resolved 2026-07-08
- **A. categorize false-positive** (Audit F-1 med-high; QA no defects): FIX-NOW. Lone permissive TCC
  grant on signed software -> neutral "permission-grant"; "spyware-generic" only when corroborated.
  Directly serves Jon's anti-alarm-fatigue directive.
- **B. RenderJSON category gating** (Audit F-2 low): documented the gate-on-Recommendation contract.
- QA: 30+ adversarial probes, no confirmed failures; tree kept clean (T-6 mitigation held).

## Mockup review (tick 5b): TUI triage mockup v1 -> v2
Two read-only reviewers (UX haiku + design/fidelity sonnet) critiqued docs/mockups/counterspy-tui.html.
Applied in v2:
- HONESTY (design F-4/UX F-5): pid:8821 was falsely "backdoor" + "kill". Real system: a PID-only process
  has no on-disk artifact, so it CANNOT be quarantined and kill is irreversible. v2 shows it as
  Investigate/unknown with an explicit "no quarantine action — terminate manually, not reversible" panel.
- FAIL-LOUD (design F-2, §9): added a collector-gap banner ("TCC signal partial ... a gap, not clean").
- SCOPE (design F-1): added "mockup · v1 CLI · TUI post-v1" note; the act layer it depicts is in progress.
- REVERSIBILITY (UX F-2): moved the move-not-delete/restore callout to the TOP of the confirm modal.
- AUDITABILITY (design F-5, §8.1): added a per-finding score breakdown so the number is checkable in-UI.
- HEDGING (design F-8): non-tripwire Quarantine verdicts now hedge ("matches the pattern of"); tripwire
  ones stay firm ("hard rule, high confidence"). 
- UX F-4: implemented / filter and ? help (were dead keys). UX F-6: shortened Monitor toggle copy.
- LIGATURES (Jon directive): CSS opts into calt/liga; ancestry uses the `->` digraph (ligates on
  Fira Code/Cascadia, readable otherwise). Spec §12 records the TUI ligature requirement + the
  don't-split-digraphs-across-color-runs discipline + --glyphs=ascii|unicode escape hatch.
OPEN for Jon: category name "spyware-generic" (design F-3/UX F-3 flag it as vague/scary).

## Tick 6 (cp-11, plan Task 11: actor) — resolved 2026-07-08  [SAFETY-CRITICAL]
Both reviewers unanimous. All fix-now (no vote). This is the destructive path; hardened hard.
- **A. Quarantine basename clobber** (QA F-1 crit + Audit F-2a): dest now recreates the full source
  path tree under the quarantine root (collision-proof + provenance) + Stat-before-move guard.
- **B. Restore clobber** (QA F-2 crit + Audit F-2b): Restore refuses to overwrite an occupied From.
- **C. Restore robustness** (QA F-3 high): preflight-ish — skip+aggregate errors, don't halt silently.
- **D. Path canonicalization** (Audit F-4 + QA F-4/F-6): filepath.Clean + case-insensitive isProtected;
  ".." resolved by Clean so it can't bypass the backstop.
- **E. Allowlist refusal in act** (Audit F-1 crit): Quarantine refuses a finding whose evidence carries
  an allowlisted authority (defense-in-depth vs the scorer's upstream suppression; §9 two-clause refusal).
- **F. Self-writing manifest** (Audit F-3 high): Quarantine appends the manifest itself (incl. partial on
  error) so completed moves are always recoverable — removes the caller footgun.
- **G. Timestamp default** (Audit F-5 med): manifest stamps time.Now().UTC() when blank.
- F-6(Audit)/F-7(QA) bootout-outcome + full-rollback: accepted low; the always-written manifest makes
  partial state recoverable, which satisfies §9 reversibility without complex rollback.

## Tick 7 (cp-13, plan Task 12 CLI) — real-run RCA — 2026-07-08
Running the binary (not fixtures) exposed a false-positive explosion (327 findings, 257 Investigate):
- codesign fanned out per-evidence -> duplicate evidence + inflated scores. Fix: dedupe per unique path.
- codesigning .plist files -> bogus "unsigned" on legit software (Google Keystone). Fix: skip non-binaries.
- Subject.Key() ("path:/...") leaked into the report. Fix: Subject.Display().
Result: 260 -> 2 actionable; noise absorbed by Monitor. RESIDUAL (for ABORT gate): unsigned+persistence
is common on developer machines (roboticus, Jon's own tool, is the 1 remaining Quarantine) — the
Apple-only allowlist doesn't cover Developer-ID/user tools, so false-positive VOLUME needs a tuning pass
(expand allowlist to Gatekeeper-accepted, or require more correlation for Investigate) before public release.

## Tick 9 (cp-15) UX pass — 2026-07-08
Jon ran the CLI and flagged it as bland/ugly with a confusing "exit status 1". RCA: not a crash
(exit 0) — errors.Join rendered both TCC sqlite3 failures as two "exit status 1" lines dumped into
the gap message. Fix: friendly gap note ("run with sudo") to stderr; ANSI color by tier; deduped
evidence; Display() in prompts. Color lives in report behind a `color bool` from the tty (pure core
untouched). Verdict: dramatic improvement; TUI-grade richness deferred to the post-v1 TUI.

## Tick tui-1 (cp-tui-1, TUI pure core) — resolved 2026-07-09
- **A. Ctrl-C trapped in filter mode** (QA F-1 high): FIX-NOW — move Ctrl-C to top of update (global quit).
- **B. Done map aliased across Model value-copies** (Audit F-1 med): FIX with Task 6 (Run) — clone-on-write.
- **C. Test fixtures all key to pid:0** (Audit F-2 low): FIX — mk() sets a distinct Path per label.
- **D. Reviewer .bak files** (Audit F-4): swept; T-6 reviewer-hygiene recurrence noted.
- Confirmed clean: decoupling invariant airtight; visible() deterministic no-aliasing; state machine well-guarded.

## Tick tui-2 (cp-tui-2, view + Run) — resolved 2026-07-09
Both reviewers essentially clean (no crit/high). Confirmed: view() pure; Run doesn't Init/Fini/recover/
os.Exit (panic reaches caller's deferred Fini — terminal safe); withDone clone closes cp-tui-1 F-1;
-race clean; no flakes (60 runs). Applied: footer truncate (QA note). Reconciled: `u` restores the whole
SESSION manifest (cliActor reuses one root/ts → all quarantines append to one manifest.json), so clearing
all Done is correct; help text + spec §5 say "restore this session's quarantine" (Audit F-2 was a
false alarm from reviewing run.go without the Task-7 adapter). Actor/act signature gap = Task 7 adapter's job.

## Tick tui-3 (cp-tui-3, subcommand) — resolved 2026-07-09
SEVERITY SPLIT surfaced (QA high vs Audit low on the snapshot trust boundary); ESCALATED to Jon.
- **A. Malicious --from snapshot moves arbitrary files** (QA F-2/3/4 high): RESOLVED by Jon → --from is
  READ-ONLY (triage/view; no quarantine). To act, run a live scan. Removes the confused-deputy surface.
  Deviates from approved spec §2 (quarantine-from-snapshot) — spec updated. Model.ReadOnly gate in update.
- **B. No-op quarantine false success** (Audit F-1 med, bites live path too): cliActor.Quarantine errors
  when plannedActions is empty (bare-process finding) — no false "quarantined", no bad lastManifest.
- **C. Double screen.Fini** (QA F-1 low): remove explicit Fini on error path (deferred covers it).
- **D. Unrecovered panic** (Audit F-2 low): runTUI wraps Run in a deferred recover → Fini + clean error.
- Confirmed strong: Actor seam gives STRONGER decoupling than spec'd (tui imports only model+tcell);
  session-scoped manifest semantics correct.
