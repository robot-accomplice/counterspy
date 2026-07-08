- [ ] T-1  (sev:med, deferred tick1)  Harden Subject identity so PID=0/no-Path subjects can't conflate.
      Origin: cp-1 QA F-2. Trigger to revisit: any collector emits Subject{PID:0,Path:""}.
- [ ] T-2  (sev:low, deferred tick1)  Introduce `type ActionKind string` enum (bootout|move) for Action.Kind.
      Origin: cp-1 Audit F-3. Do it in Task 11 alongside act.Quarantine; update plan Task 11 code too.
- [ ] T-3  (sev:med, tick2)  Task 7 codesign collector MUST set Facts["authority"] only from a
      codesign-verified + spctl-accepted chain (not raw cert CN), so IsAllowlisted can't be spoofed.
      Origin: cp-3 Audit F-4.
