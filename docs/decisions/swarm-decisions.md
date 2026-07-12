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

## Handover + substrate reconciliation (fresh-context resume) — 2026-07-12

Resumed CounterSpy under a fresh orchestrator session; coordinated a live handover
with the retired writer session (via ccd_session_mgmt) rather than reconstructing
from the bus alone. Key reconciliations recorded so a future resume is not misled
by the stale cp-* picture:

- **Execution model:** the project has moved OFF the cp-* fan-out checkpoint model
  onto **gitflow + PR**, CI-gated (build/vet/gofmt/test --race + >=80% coverage per
  package). The `.swarm/` bus checkpoints end at cp-tui-3 (2026-07-09); egress,
  feedback, and the TUI spinner shipped since via PR, reviewed through gitflow.
- **Swarm value retained:** the swarm's parallel read-only reviewer fan-out
  (Antagonist + Audit subagents on each diff) + single-writer discipline is kept as
  the quality mechanism; only the shipped artifact changed (cp-* bus entry -> git PR).
  No spawn_task chips (they would create a second writer).
- **Branch/PR posture at handover:** main = v0.4.0; develop = integration target.
  Open PRs -> develop: #25 feature/native-codesign (trust-semantics shift, awaiting
  Jon's human decision) and #26 bug/tui-startup-spinner (spinner, green).
- **Current work:** feature/symbology-legend off develop. Spec + plan committed
  (docs/superpowers/{specs,plans}/2026-07-1*-symbology-legend*). Three-axis mark
  vocabulary (concern/trust/liveness), uniform-cadence cluster, documented drift-proof
  key. Closes T-4 (real exec path per PID) + #23 (active-vs-vestigial). Liveness is
  display-only (scorer untouched). PR #25 coupling flagged, not decided here (spec §8).

## cp-T1 (Task 1: internal/mark vocabulary) — reviewed 2026-07-12
Antagonist(haiku)+Audit(sonnet) read-only fan-out on the diff. CROSS-REVIEWER CONFIRMED:
- **F-1 (crit, both, high-conf): isAppleAuthority substring-spoof.** A Gatekeeper-accepted
  Developer-ID cert with "Apple" in the CN forged ● Apple-system. FIX-NOW (unanimous): exclude
  the "Developer ID" leaf prefix before Apple matching. T-3's accepted-gate already blocks
  self-signed fakes; the reachable case was a legit-notarized third-party CN — now closed.
- **F-2 (high, Audit): spoof case untested.** FIX-NOW: added devid-apple-spoof + installer-spoof tests.
- **DEFER (justified): multi-codesign-evidence tie-break** (both, low). Not reachable — codesign.go
  emits exactly one codesign Evidence per finding (verified). Revisit only if that invariant changes.
- **WON'T-FIX (justified): case-sensitive "signed"** (our collector emits canonical lowercase) and
  **Concern default->Monitor** (safe low-noise default by design).

## Symbology & legend feature — SHIPPED to PR — 2026-07-12
feature/symbology-legend → PR #27 (base develop). 9 plan tasks, each through an Antagonist+Audit
fan-out. Real catches: cp-T1 ● Apple-spoof (crit), cp-T2 vestigial-mislabel (high), cp-T4/ESC-1
comm=→full-argv correlation, cp-T5 nil-liveness prod bug (high), cp-T7 ?-overlay off-screen (crit),
cp-T9 Architext gap (med). CI gate green (-race, coverage ≥83%/pkg). Architext mod-mark recorded.
OPEN FOLLOW-UPS: (1) PR #25 native-codesign coupling — revisit mark.Trust ◆/◇ mapping on merge (spec §8);
(2) T-7 interpreter-wrapper: liveness now argv-matches it, but the DETECTION/scoring side (pickTarget
interpreter-awareness) remains open; (3) cosmetic: egress TRUST column oversized for a 1-glyph value.

## RESUME NOTE — Exfiltration inspection interceptor (#3), Phase A in progress — 2026-07-12

Session got large; this note lets a compacted OR fresh session resume identically.

### Operating model (unchanged)
Single-writer swarm, orchestrator+subagents substrate. Each reviewable unit = a checkpoint:
implement test-first → commit → spawn read-only Antagonist(haiku)+Audit(sonnet) fan-out on the
diff → vote/remediate → advance. Ship as gitflow branch → PR → develop, CI-gated (build+cgo,
vet, gofmt across ALL tracked files, test --race, >=80% coverage/pkg). No spawn_task chips.
Persist findings to .swarm/bus/inbox/{findings,coding}.md. NATIVE-FIRST principle (maintainer):
never shell out to an external process when a native/in-process path exists (BPF via syscall, not
tcpdump; Security.framework, not codesign CLI). Pre-push: gofmt -l over git ls-files '*.go'.

### Where things stand
develop has: symbology marks, native codesign (◆/◇ reconciled), CI flake fix, spinner, heat
sparklines, per-connection sparklines, console unification (one `console` command, Tab-switch
Findings⇄Exfiltration, lazy sampling). All merged & green.

### #3 interceptor — spec APPROVED, on branch `spec/exfil-inspect-interceptor` (pushed):
- Spec: docs/superpowers/specs/2026-07-12-exfil-inspect-interceptor.md (READ FIRST). Decisions:
  native BPF only (no tcpdump/gopacket); tier-2 native interposition only (no shelled frida/dtrace);
  redaction masked-by-default w/ reveal toggle; consent opt-in per session; tiers 2 & 4 need own consent.
- Tiers: 0 metadata(SNI/JA3/cert/sizes, always) · 1 plaintext flows · 2 SSL_write hook · 3 keylog · 4 proxy+CA.
- DONE checkpoint 1: internal/inspect/tls.go — pure TLS ClientHello SNI parser + tests (bounds-checked).
- NEXT checkpoints (in order): (a) Ethernet/IP/TCP framing parser (pure, fixtures) → captured packet to TLS record;
  (b) native BPF capture of the selected 4-tuple behind an injectable seam (root; /dev/bpf via x/sys); tests mock the seam;
  (c) flow↔connection correlation (4-tuple ↔ the Exfiltration row's pid+local+remote);
  (d) tier orchestration + honest per-flow coverage verdict (internal/inspect);
  (e) the `i` inspection view in internal/tui (new mode off an Exfiltration row) + consent gate;
  (f) bundle Phase A into ONE PR when the vertical slice renders SNI/metadata for a real flow.
- Phase B: SSL_write-hook feasibility SPIKE (native DYLD-interpose helper / task_for_pid / libdtrace-cgo)
  against a non-hardened target BEFORE building tier 2. Phase C: keylog + proxy. Then #4 highlighting
  (keyword/regex + key/secret heuristics; also drives the mask-by-default redaction) on surfaced plaintext.
- Grounding confirmed on this host: /dev/bpf* present, dtrace ships, tcpdump present (NOT to be used — native-first).

## RESUME NOTE UPDATE — Phase A engine COMPLETE — 2026-07-12 (session 2)

internal/inspect package built + tested (branch spec/exfil-inspect-interceptor, all pushed):
- tls.go        — ClientHelloSNI (pure, bounds-checked) ✓ tested
- framing.go    — ParseIPPacket → TCPSegment (4-tuple via netip + payload) ✓ tested
- linklayer.go  — stripLinkLayer (Ethernet/null/raw → IP) ✓ tested
- capture.go    — PacketSource seam + fixtureSource ✓ tested
- bpf_darwin.go — openLiveCapture: native /dev/bpf via x/sys/unix (root I/O edge; compile+vet
                  verified; LIVE sudo capture NOT yet run — no interactive sudo in sandbox. TODO:
                  a maintainer should run a root smoke: sudo go test -run LiveCapture with curl traffic)
- bpf_other.go  — non-darwin stub
- inspect.go    — Inspect(src,flow,maxPackets) Result: correlate by remote, SNI, HONEST coverage
                  verdict (TLS→metadata-only no-payload; plaintext→payload; none). ✓ tested

REMAINING Phase A (checkpoint e), then the Phase A PR:
1. The `i` inspection VIEW in internal/tui: a new mode/overlay reached by pressing `i` on an
   Exfiltration connection row. Build a Flow{PID, Remote} from the selected row (the row already
   carries pid + remote endpoint via model.Conn), call inspect.Inspect over a live capture, render:
   header (app·pid·local→remote·trust glyph) + the coverage verdict line + metadata (SNI) + the
   content pane (when plaintext), esc/i returns. Reuse internal/mark for the trust glyph.
   NOTE: internal/tui may import internal/inspect only if inspect stays a pure-ish leaf (it imports
   netip + x/sys via bpf_darwin — check the tui decoupling invariant in imports_test.go; inspect is
   NOT model-shaped, so this likely needs the capture wired in MAIN, not tui: pass an inspect
   function/result into the tui via a seam, keeping tui importing only model+mark+inspect-types, OR
   do the capture in main and hand the tui a Result. Decide at implementation — prefer main owns the
   root capture, tui renders a Result via an injected `inspect func(Flow) Result` seam.)
2. CONSENT gate: first `i` in a session prompts "capture this flow's packets? [y/N]" before any
   capture. A --no-inspect flag disables it. (spec §5)
3. Wire openLiveCapture in main (root); the console's `i` handler builds the Flow, opens capture,
   runs Inspect with a timeout/packet cap, shows the Result. Capture stops on view close.
4. Redaction (spec §6): mask obvious secrets in the rendered payload by default (bearer/AKIA/PEM/
   high-entropy) with a reveal toggle — this overlaps #4 highlighting; can land with #4.
5. Bundle Phase A into ONE PR → develop; swarm fan-out; CI gate.
Then Phase B: SSL_write-hook feasibility SPIKE (native DYLD-interpose / task_for_pid / libdtrace-cgo).

## cp-insA (inspect ENGINE ff4b81b..835f229) — deferred fan-out, resolved 2026-07-12 (session 3 resume)
The Phase A engine (tls/framing/linklayer/capture/bpf/inspect) was committed a→d but never
fan-out-reviewed (findings bus had no entry). Standing obligation → reviewed before building the view.
Antagonist(haiku)+Audit(sonnet), read-only, on the engine diff. Outcome:
- **F-1 4-tuple correlation** (QA high + Audit high, CROSS-CONFIRMED): DEFER (T-8). model.Conn has NO
  local endpoint (egress/parse.go:116 + egress.go:11 verified) — the row is remote-keyed, so per-remote
  match is the most specific identity that exists; over-merge is same-pid-same-remote, display-only,
  observe-only. Spec §3 "row carries its local endpoint" is INACCURATE — code wins; spec reconciled.
- **Audit F-1 no kernel BPF filter** (crit→HIGH): FIX in Phase A (T-9), its own checkpoint with the live
  wiring. Whole-interface capture violates §6 least-privilege; reclassed high (over-captured bytes are
  discarded in userspace, never shown/stored). cBPF host+port filter before the Phase A PR.
- **Audit F-3 silent error swallow** (high, §9 fail-loud): FIX-NOW — surface capture failure on Result.
- **Audit F-4 no SNI reassembly** (med): PARTIAL FIX-NOW (SNI over accumulated same-remote buffer) + T-10 (full reassembly).
- **Audit F-5 BPF record-walker untested** (med): FIX-NOW — darwin fixture test.
- **Audit F-6 ifreq no size assert** (med): FIX-NOW trivial. **F-7 TLS record types** (low): FIX-NOW one-liner.
No human escalation: all engineering calls with recorded justifications. Remediation = next checkpoint (cp-insB).

## cp-insC (i inspection view) — reviewed 2026-07-12 (session 3)
Antagonist(haiku)+Audit(sonnet), read-only, on the cp-insC diff. Both independently confirmed the
security invariants: consent is a real by-construction, session-scoped gate (§5); redaction applied
every draw with no raw-Content path when masked; InspectView.Content is display-only (never disk/log/net,
§6); decoupling invariant holds (tui deps = model+mark only, NO internal/inspect); observe-only.
Antagonist CLEAN (10× -race stress, no flake). Audit found:
- **F-1 (med, CONFIRMED): PEM partial leak** — masked only complete BEGIN…END. FIX-NOW: added a
  dangling-BEGIN→EOF fallback (rePEMOpen) + a partial-PEM test. §6 hardened.
- **F-4 (info): message named a nonexistent --no-inspect flag** — FIX-NOW: softened to
  "inspection unavailable in this build"; cp-insD adds the real flag.
- **F-2 (med, PLAUSIBLE): sync Inspect seam UI-freeze** — ACCEPT sync seam (RunConsole can wrap it async
  later WITHOUT an interface change, so nothing's locked in); bound the capture in cp-insD's adapter
  (T-11: read deadline + packet + wall-clock cap, worst-case <~1.5s); async upgrade → T-12 if needed.
- **F-3 (low): Coverage duplication has no exhaustiveness guard** — DEFER to cp-insD (the adapter maps
  them there; add an exhaustive switch + test so a future tier forces both files to change).
No human escalation — engineering calls with recorded justifications.
