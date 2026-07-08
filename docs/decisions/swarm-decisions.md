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
