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
- [ ] T-8  (sev:high, deferred cp-insA)  True 4-tuple flow correlation: capture the LOCAL port upstream
      (nettop/lsof in internal/egress) → thread into model.Conn + inspect.Flow.Src, match seg.Src too,
      and use it in the T-9 BPF filter. Trigger: any multi-local-port-same-remote inspection confusion.
      Origin: cp-insA QA F-1 = Audit F-2 (cross-confirmed high). Deferred: needs new collector data, not a code slip.
- [ ] T-9  (sev:high, Phase-A checkpoint)  Install a scoped cBPF filter in openLiveCapture
      (`host <remote-ip> and port <remote-port> and tcp`) via BIOCSETF so capture is NOT whole-interface
      (spec §6 least-privilege). Land WITH the live capture wiring + the maintainer sudo smoke test.
      Origin: cp-insA Audit F-1 (crit→high). MUST land before the Phase A PR.
- [ ] T-10 (sev:med, deferred cp-insA)  Full TCP segment reassembly (seq tracking + reordering) for
      ClientHello/payload spanning many out-of-order segments. Phase-A ships best-effort concat-in-order.
      Origin: cp-insA Audit F-4. Deferred: stateful reassembly is a distinct feature; concat handles the common split.
- [ ] T-11 (sev:med, cp-insD)  main's Inspector adapter MUST bound the live capture: a BPF read
      deadline + packet cap + a hard wall-clock cap, so a consented inspection of an idle flow can't
      freeze the TUI event loop for more than ~1.5s. Origin: cp-insC Audit F-2.
- [ ] T-12 (sev:low, if-needed)  Async inspection: run inspector.Inspect on a goroutine and deliver the
      Result as a tcell EventInterrupt with a "capturing…" placeholder state, keeping quit/redraw live
      during capture. Only do this if T-11's bounded sync freeze proves annoying. Origin: cp-insC Audit F-2 (deferred half).
- [ ] T-9-ref (sev:med, refinement)  Tighten the kernel BPF filter from host+TCP to host+remote-PORT+TCP
      (IPv4 needs LoadMemShift IHL-indexing for the port offset; IPv6 port is at a fixed offset). VM-test
      port match/mismatch. Marginal §6 gain (same-host-other-port); userspace already enforces the port.
      Origin: cp-insD Audit F-1. Host-scoping (the bulk of §6) is DONE in cp-insD.
- [x] T-13 (DONE 2026-07-13)  installFlowFilter passes BpfProgram{Insns:&insns[0]}
      into a raw Syscall but nothing keeps `insns` alive across the call — a runtime.KeepAlive-class
      hazard that can EFAULT/corrupt the BIOCSETF filter install (currently swallowed → would silently
      defeat the T-9 filter). Add runtime.KeepAlive(insns) after the syscall. Separate from the
      BIOCSBLEN fix; address as its own change. The filter-drop smoke test may surface it.
- [ ] T-14 (sev:low, pre-existing) Prune the app-level out+in spark maps (monitor.spark + sparkIn,
      keyed by path) on dead app keys, like the per-PID/conn rings. Pre-existing for `spark`; cp-tr1
      doubled the surface with `sparkIn`. Bounded by distinct app-paths seen in a session (small), so low.
      Origin: cp-tr1 Audit F-2.
- [ ] T-15 (sev:low, UX) When both SENT and RECEIVED content panes are present and the terminal is
      short, the second (RECEIVED) pane can be silently skipped for lack of rows — show a "… (received
      hidden — resize)" marker or split the space so the user knows it exists. Origin: cp-insE-bidir Antag F-3.
