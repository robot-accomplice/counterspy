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
