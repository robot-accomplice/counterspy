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
- [x] T-7  (DONE cp-t7 — inline-interpreter detection + dedicated signal; interpreter no longer trusted subject)  Interpreter-wrapper LOLBin persistence: `osascript -e <payload>` / `python3 -c <payload>`
      resolves to the Apple-signed interpreter, so the finding looks trusted (acceptedSigned). pickTarget
      should detect an interpreter + inline-code flag and treat the inline script as the real payload.
      Origin: rc3 C3 verifier. Pre-existing; needs interpreter-aware parsing in collect/persistence + proctree.
- [ ] T-8  (sev:high, deferred cp-insA)  True 4-tuple flow correlation: capture the LOCAL port upstream
      (nettop/lsof in internal/egress) → thread into model.Conn + inspect.Flow.Src, match seg.Src too,
      and use it in the T-9 BPF filter. Trigger: any multi-local-port-same-remote inspection confusion.
      Origin: cp-insA QA F-1 = Audit F-2 (cross-confirmed high). Deferred: needs new collector data, not a code slip.
- [x] T-9  (DONE cp-insD — host-scoped BIOCSETF filter installed)  Install a scoped cBPF filter in openLiveCapture
      (`host <remote-ip> and port <remote-port> and tcp`) via BIOCSETF so capture is NOT whole-interface
      (spec §6 least-privilege). Land WITH the live capture wiring + the maintainer sudo smoke test.
      Origin: cp-insA Audit F-1 (crit→high). MUST land before the Phase A PR.
- [ ] T-10 (sev:med, deferred cp-insA)  Full TCP segment reassembly (seq tracking + reordering) for
      ClientHello/payload spanning many out-of-order segments. Phase-A ships best-effort concat-in-order.
      Origin: cp-insA Audit F-4. Deferred: stateful reassembly is a distinct feature; concat handles the common split.
- [x] T-11 (DONE cp-insD — non-blocking fd + deadline + packet cap)  main's Inspector adapter MUST bound the live capture: a BPF read
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
- [x] T-14 (DONE cp-hk1) Prune the app-level out+in spark maps (monitor.spark + sparkIn,
      keyed by path) on dead app keys, like the per-PID/conn rings. Pre-existing for `spark`; cp-tr1
      doubled the surface with `sparkIn`. Bounded by distinct app-paths seen in a session (small), so low.
      Origin: cp-tr1 Audit F-2.
- [x] T-15 (DONE cp-hk1 — reserved space keeps RECEIVED visible) When both SENT and RECEIVED content panes are present and the terminal is
      short, the second (RECEIVED) pane can be silently skipped for lack of rows — show a "… (received
      hidden — resize)" marker or split the space so the user knows it exists. Origin: cp-insE-bidir Antag F-3.
- [ ] T-13 (sev:low, deferred cp-t7)  Arbitrary-renamed interpreter symlink evasion: `/opt/x -c <src>`
      where /opt/x -> /usr/bin/py3 defeats name-based isTrustedShim/inline detection (basename
      "x" is unknown), so the interpreter's Apple signature can still whitewash via the symlink.
      Deferred: closing it needs readlink/stat resolution of argv[0], which is filesystem I/O and
      breaks the pure-over-bytes persistence parser -- belongs in the codesign I/O collector (resolve
      the real signed binary vs the argv path). Attacker also needs write to a PATH dir. Origin: cp-t7 Antagonist A3.
- [ ] T-14b (sev:low, deferred cp-t7)  Render Facts["inline_code"] in the text report (report.dedupe
      only surfaces ancestry/argv today); the source is captured for RCA via JSON but not shown in the
      primary human surface. Deferred: reporting UX, separate from detection correctness. Origin: cp-t7 Audit F-4.
- [x] T-15 (DONE cp-p1e) (sev:nit, cp-p1a Audit)  Move the Resolver interface from producer (internal/netname) to
      its consumer (internal/egress) at wiring time — idiomatic Go; netname.Cache satisfies it
      structurally, letting netname/resolver.go be deleted. Do in cp-p1c (egress wiring).
- [x] T-16 (DONE cp-p1d) (sev:med, cp-p1c Audit F-1)  Harden internal/inspect bpfCapture for concurrent Close: add
      an atomic "closed" flag set by Close() and checked in Next() (return io.EOF if closed, incl. when
      a racing read errors), so Observer.Close→Run always ends via a clean io.EOF, not a benign-but-
      unsynchronized fd-close-during-read. Do in cp-p1d (already editing bpf_darwin.go there).
- [ ] T-17 (sev:low, cp-p1h Audit F-1)  Surface the passive DNS observer's terminating error for RCA
      (Rule 14). Can't stderr mid-alt-screen; do it in the --non-interactive/logging mode
      (roadmap-non-interactive-mode), which has a file/stdout channel. Today: mid-session read failure
      degrades destinations to IPs with no log line.
- [ ] T-18 (sev:low, cp-p2c F-3)  High-entropy body-secret detection for the intercept/inspect content
      (feature #4 territory): Redact masks pattern-exact credential fields + known headers, but a
      free-form high-entropy secret in a body (a raw token with no field name) is still shown. Add the
      fuzzy detector when feature #4 lands.
- [ ] T-19 (sev:med, cp-p2d)  The intercept daemon's unix socket path MUST be short (<~104 chars,
      macOS sun_path limit) — use e.g. /tmp/counterspy-intercept.sock or a short ~ path, not a long
      nested path. Surfaced by a socket test that overflowed t.TempDir()'s path. Enforce in cp-p2f.
- [ ] T-20 (sev:med, cp-spec2.5-r2 Audit F-6) The root proxy's CONNECT read (internal/intercept/proxy.go:70-72,
      http.ReadRequest) accepts UNBOUNDED headers from any local client, bounded only by the 10s
      connectTimeout — live unbounded memory exposure in the root daemon. Bound it (LimitReader /
      MaxHeaderBytes-style wrap) in Phase 2.5's pump work, where §3.1.5 already mandates a header cap.
