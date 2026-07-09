- [ ] T-1  (sev:med, deferred tick1)  Harden Subject identity so PID=0/no-Path subjects can't conflate.
      Origin: cp-1 QA F-2. Trigger to revisit: any collector emits Subject{PID:0,Path:""}.
- [ ] T-2  (sev:low, deferred tick1)  Introduce `type ActionKind string` enum (bootout|move) for Action.Kind.
      Origin: cp-1 Audit F-3. Do it in Task 11 alongside act.Quarantine; update plan Task 11 code too.
- [ ] T-3  (sev:med, tick2)  Task 7 codesign collector MUST set Facts["authority"] only from a
      codesign-verified + spctl-accepted chain (not raw cert CN), so IsAllowlisted can't be spoofed.
      Origin: cp-3 Audit F-4.
- [ ] T-4  (sev:med, tick4)  Resolve the REAL executable path per PID (proc_pidpath or `lsof -p <pid>` txt)
      so process evidence can safely correlate with codesign/persistence by Path. Origin: cp-7 Audit F-1.
- [ ] T-5  (sev:low, tick4)  Add lstart to ps + Proc.Start for age/anomaly signals (spec §6). Origin: cp-7 Audit F-5.
- [ ] T-6  (process)  Reviewer subagent briefs: probe files under /tmp only; orchestrator sweeps stray
      untracked files before each commit (single-writer integrity). Origin: cp-7 Antagonist leakage.
- [ ] T-7  (sev:med)  Interpreter-wrapper LOLBin persistence: `osascript -e <payload>` / `python3 -c <payload>`
      resolves to the Apple-signed interpreter, so the finding looks trusted (acceptedSigned). pickTarget
      should detect an interpreter + inline-code flag and treat the inline script as the real payload.
      Origin: rc3 C3 verifier. Pre-existing; needs interpreter-aware parsing in collect/persistence + proctree.
