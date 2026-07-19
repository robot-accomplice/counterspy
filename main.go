package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"counterspy/internal/ack"
	"counterspy/internal/act"
	"counterspy/internal/collect"
	"counterspy/internal/egress"
	"counterspy/internal/feedback"
	"counterspy/internal/inspect"
	"counterspy/internal/interpret"
	"counterspy/internal/mark"
	"counterspy/internal/model"
	"counterspy/internal/netname"
	"counterspy/internal/report"
	"counterspy/internal/score"
	"counterspy/internal/tui"
	"github.com/gdamore/tcell/v2"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, stdout io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help", "-?":
		usage(stdout) // explicit help request is success
		return 0
	case "version", "--version":
		fmt.Fprintln(stdout, "counterspy "+model.Version)
		return 0
	case "scan":
		return runScan(args[1:], stdout)
	case "console":
		return runConsole(args[1:], stdout)
	case "restore":
		if len(args) < 2 {
			fmt.Fprintln(stdout, "usage: counterspy restore <manifest.json>")
			return 2
		}
		if err := act.Restore(args[1]); err != nil {
			fmt.Fprintln(stdout, "restore:", report.Clean(err.Error()))
			return 1
		}
		fmt.Fprintln(stdout, "restored from", args[1])
		fmt.Fprintln(stdout, dim("  disabled launch items reload at next login (or were re-enabled now)."))
		return 0
	case "feedback":
		return runFeedback(args[1:], stdout)
	case "intercept":
		return runIntercept(args[1:], stdout)
	default:
		fmt.Fprintln(stdout, "unknown command:", args[0])
		fmt.Fprintln(stdout)
		usage(stdout)
		return 2
	}
}

// usage prints the full help: the tool banner + version, every command with its flags, and
// how to choose the plain CLI (scan) vs the interactive UI (tui).
func usage(w io.Writer) {
	fmt.Fprintf(w, `CounterSpy %s — macOS spyware triage 🕵️
Scans for spyware-like activity, ranks findings, and reversibly quarantines on approval (never deletes).

Usage:
  counterspy <command> [flags]

Commands:
  scan                     Print a ranked report to the terminal (the plain CLI)
      --json                 emit machine-readable JSON instead of the report
      --interactive          after the report, prompt to quarantine each finding
  console                  Open the interactive UI: Findings triage + the Exfiltration monitor,
                           switched with Tab / Shift-Tab (the visual mode)
      --from <file>          load a 'scan --json' snapshot instead of scanning live (read-only)
      --json                 print the Exfiltration report as JSON and exit (no live UI)
      --once                 print the Exfiltration report once and exit (no live UI)
  restore <manifest.json>  Undo a quarantine from its manifest
  intercept                Decrypt outbound TLS through a local proxy (installs a trusted CA + sets
                           the system HTTPS proxy; reverts on exit). Requires sudo. View via console.
      --stream[=sock]        publish live flows to a unix socket (the default output)
      --log[=path]           publish flows to a rotating 0600 JSONL log
      --uninstall            revert the CA trust + system proxy and exit
      --yes                  skip the interactive consent prompt
      --install-daemon       install a PERSISTENT root daemon (re-arms at every boot, logs to
                             /var/log/counterspy; prompts separately). counterspy scan will flag it.
      --uninstall-daemon     remove the daemon and revert everything
  feedback [list|submit]   Manage opt-in anonymous false-positive feedback (off by default)
  version                  Print the version (also --version)
  help                     Show this help (also -h, --help, -?)

Run under sudo for full visibility (the TCC privacy-grant signal needs it).
Plain CLI report:  sudo counterspy scan       Interactive UI:  sudo counterspy console
`, model.Version)
}

func runScan(flags []string, stdout io.Writer) int {
	asJSON := has(flags, "--json")
	interactive := has(flags, "--interactive")
	dry := has(flags, "--dry") // collect nothing; used by tests

	var ev []model.Evidence
	var gaps []string
	if !dry {
		ev, gaps = collectWithSpinner()
	}
	running, _ := collect.CollectRunningPaths()
	assessments := filterAllowed(interpret.Assess(score.Score(ev), running), userAllowlist())

	if asJSON {
		// Gaps ride inside the snapshot now (not stderr) so a `--from` load can surface the same
		// "signal unavailable" notes a live scan shows, instead of reading as a clean bill (#8).
		b, err := report.RenderJSON(assessments, gaps)
		if err != nil {
			fmt.Fprintln(os.Stderr, "render:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprint(stdout, report.Render(assessments, gaps, colorEnabled(), livenessFor(assessments)))
	if interactive {
		quarantineLoop(assessments, stdout, os.Stdin, actQuarantiner{})
	}
	return 0
}

// collectorSpec pairs an evidence collector with the friendly gap note to record when it
// errors.
type collectorSpec struct {
	gap string
	fn  func() ([]model.Evidence, error)
}

// evidenceCollectors is the fan-out set collectAll drives; a package var so tests can
// inject fakes (success + failure) instead of touching the OS (CI has no sudo).
var evidenceCollectors = []collectorSpec{
	{"Persistence signal unavailable", collect.CollectPersistence},
	{"Process/network signal unavailable", collect.CollectProcesses},
	{"TCC privacy-grant signal unavailable — run with sudo to include it", collect.CollectTCC},
}

// collectAll fans out the collectors and returns any signal GAPS as friendly notes —
// a missing signal is reported, never silently read as "clean" (spec §9, Rule 13).
// livenessFor assembles each assessment's display marks (run-state + socket) from the
// liveness interpret already derived (issue #23). The run-state itself is resolved once,
// at Assess time, against the live-process set — so a snapshot (`--from`) carries its
// scan-time liveness instead of being re-derived against a different machine's processes.
func livenessFor(assessments []model.Assessment) map[string]mark.Liveness {
	return mark.Classify(assessments)
}

func collectAll() ([]model.Evidence, []string) { return collectAllWithProgress(nil) }

// collectAllWithProgress runs the collectors, then the per-binary code-signature checks
// CONCURRENTLY (a bounded pool — each CollectCodesign spawns 3 subprocesses, so serial over
// hundreds of binaries is the dominant startup cost). onCodesign, if non-nil, is called after
// each binary completes so callers can render progress.
func collectAllWithProgress(onCodesign func(done, total int)) ([]model.Evidence, []string) {
	var ev []model.Evidence
	var gaps []string
	add := func(gap string, fn func() ([]model.Evidence, error)) {
		e, err := fn()
		if err != nil {
			gaps = append(gaps, gap)
			return
		}
		ev = append(ev, e...)
	}
	for _, c := range evidenceCollectors {
		add(c.gap, c.fn)
	}
	// codesign runs ONCE per unique on-disk binary surfaced by the other collectors.
	// Skip .plist files (they aren't signed binaries — codesigning one yields a bogus
	// "unsigned") and anything that isn't a regular existing file.
	seen := map[string]bool{}
	var paths []string
	for _, e := range ev {
		p := e.Subject.Path
		if p == "" || seen[p] || strings.HasSuffix(p, ".plist") {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	return append(ev, codesignAll(paths, collect.CollectCodesign, onCodesign)...), gaps
}

// codesignWorkers bounds concurrency for the code-signature checks. codesign/spctl are
// subprocess-bound (I/O), so oversubscribing the CPU count is the win.
const codesignWorkers = 16

// codesignAll runs cs over paths concurrently (bounded pool) and returns the evidence in a
// deterministic order (by input path index). cs is injected so tests need not shell out.
// onDone, if non-nil, fires once per completed path with the running done/total count.
func codesignAll(paths []string, cs func(string) []model.Evidence, onDone func(done, total int)) []model.Evidence {
	total := len(paths)
	if total == 0 {
		return nil
	}
	results := make([][]model.Evidence, total)
	sem := make(chan struct{}, codesignWorkers)
	var wg sync.WaitGroup
	var done int64
	for i := range paths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			results[i] = cs(paths[i])
			<-sem
			if onDone != nil {
				onDone(int(atomic.AddInt64(&done, 1)), total)
			}
		}(i)
	}
	wg.Wait()
	// The per-worker onDone ticks carry unique counts (1..total) but are invoked
	// concurrently, so the LAST callback the caller observes is not guaranteed to be
	// the one with done==total. Emit a deterministic final tick after all workers
	// finish so progress always ends at total/total (fixes a flaky freeze at "N/M").
	if onDone != nil {
		onDone(total, total)
	}
	var out []model.Evidence
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// collectWithSpinner runs collection, animating a progress line on stderr when it is a tty
// so the multi-second code-signature phase is never a silent wait. Piped/non-tty stays quiet.
func collectWithSpinner() ([]model.Evidence, []string) {
	if !isTerminal(os.Stderr) {
		return collectAll()
	}
	var done, total int64
	stop := make(chan struct{})
	spinnerDone := make(chan struct{})
	go func() { scanSpinner(os.Stderr, &done, &total, stop); close(spinnerDone) }()
	ev, gaps := collectAllWithProgress(func(d, t int) {
		atomic.StoreInt64(&done, int64(d))
		atomic.StoreInt64(&total, int64(t))
	})
	close(stop)
	<-spinnerDone // ensure the spinner cleared its line before the report prints
	return ev, gaps
}

// scanSpinner animates a braille spinner + progress line on w until stop closes.
func scanSpinner(w io.Writer, done, total *int64, stop <-chan struct{}) {
	frames := []rune("⣾⣽⣻⢿⡿⣟⣯⣷")
	// Tint the braille glyph with the shared mint accent (report sMint, 38;5;79 — CounterSpy
	// chrome); the message stays default. NO_COLOR drops the tint (the caller already gates the
	// whole spinner on a tty).
	col, reset := "\033[38;5;79m", "\033[0m"
	if os.Getenv("NO_COLOR") != "" {
		col, reset = "", ""
	}
	t := time.NewTicker(90 * time.Millisecond)
	defer t.Stop()
	for i := 0; ; i++ {
		select {
		case <-stop:
			fmt.Fprint(w, "\r\033[K") // clear the line
			return
		case <-t.C:
			d, tot := atomic.LoadInt64(done), atomic.LoadInt64(total)
			msg := "collecting signals…"
			if tot > 0 {
				msg = fmt.Sprintf("checking code signatures  %d/%d", d, tot)
			}
			fmt.Fprintf(w, "\r\033[K%s%c%s %s", col, frames[i%len(frames)], reset, msg)
		}
	}
}

// isTerminal reports whether f is a real character-device terminal. A package var so
// tests can simulate a tty (CI has none) without a real terminal.
var isTerminal = func(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colorEnabled reports whether to emit ANSI color: a real terminal on stdout and
// NO_COLOR unset (https://no-color.org).
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTerminal(os.Stdout)
}

// quarantiner performs the quarantine effect quarantineLoop requests — a small local
// interface (narrower than tui.Actor, which quarantineLoop doesn't need) so tests can
// inject a fake and assert y/N/q branch behavior without touching the filesystem.
type quarantiner interface {
	Quarantine(root, ts string, a model.Assessment) (model.ManifestItem, error)
}

// actQuarantiner is the real quarantiner: it calls internal/act.
type actQuarantiner struct{}

func (actQuarantiner) Quarantine(root, ts string, a model.Assessment) (model.ManifestItem, error) {
	return act.Quarantine(root, ts, a)
}

func quarantineLoop(assessments []model.Assessment, stdout io.Writer, stdin io.Reader, q quarantiner) {
	home, _ := os.UserHomeDir()
	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	root := filepath.Join(home, "CounterSpyQuarantine", ts)
	in := bufio.NewReader(stdin)

	for _, a := range assessments {
		if a.Recommendation == model.RecMonitor {
			continue
		}
		actions := plannedActions(a.Finding)
		if len(actions) == 0 {
			continue // e.g. a process-only finding: no artifact to move, no reversible action
		}
		fmt.Fprintf(stdout, "\n  Quarantine %s? %s ", report.Clean(a.Subject.Display()), dim("(moves, reversible) [y/N/q]"))
		line, _ := in.ReadString('\n')
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "q":
			return
		case "y":
			a.Actions = actions // a.Finding.Actions (embedded)
			if _, err := q.Quarantine(root, ts, a); err != nil {
				fmt.Fprintln(stdout, "    stopped (partial state recorded in manifest):", report.Clean(err.Error()))
				continue
			}
			fmt.Fprintln(stdout, "    ✓ quarantined ->", root)
			fmt.Fprintln(stdout, dim("      undo: sudo counterspy restore "+filepath.Join(root, "manifest.json")))
		}
	}
}

// plannedActions derives the reversible actions for a finding: disable the launch
// item (by label), then move its plist(s) and its on-disk target. A finding with no
// label and no path (e.g. a bare process) yields no actions — CounterSpy won't perform
// an irreversible kill.
func plannedActions(f model.Finding) []model.Action {
	var a []model.Action
	if f.Subject.Label != "" {
		a = append(a, model.Action{Kind: model.ActionBootout, From: f.Subject.Label})
	}
	seen := map[string]bool{}
	for _, e := range f.Evidence {
		if p := e.Facts["plist"]; p != "" && !seen[p] {
			seen[p] = true
			a = append(a, model.Action{Kind: model.ActionMove, From: p})
		}
	}
	if f.Subject.Path != "" && !seen[f.Subject.Path] {
		a = append(a, model.Action{Kind: model.ActionMove, From: f.Subject.Path})
	}
	return a
}

// userAllowlist reads the operator's vetted known-good subjects (one label or path
// per line, # comments) from ~/.config/counterspy/allowlist.txt. Missing file = empty.
func userAllowlist() map[string]bool {
	m := map[string]bool{}
	home, err := os.UserHomeDir()
	if err != nil {
		return m
	}
	b, err := os.ReadFile(filepath.Join(home, ".config", "counterspy", "allowlist.txt"))
	if err != nil {
		return m
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" && !strings.HasPrefix(ln, "#") {
			m[ln] = true
		}
	}
	return m
}

// filterAllowed drops assessments the operator has vetted (by label or path).
func filterAllowed(as []model.Assessment, allow map[string]bool) []model.Assessment {
	if len(allow) == 0 {
		return as
	}
	out := make([]model.Assessment, 0, len(as))
	for _, a := range as {
		if allow[a.Subject.Label] || allow[a.Subject.Path] {
			continue
		}
		out = append(out, a)
	}
	return out
}

// proxyEndpointForConsole returns the armed intercept proxy endpoint so the Exfiltration view can
// recognize proxied connections. It is plain data from main's constant — no internal package imports
// package main (decoupling invariant).
func proxyEndpointForConsole() string { return fmt.Sprintf("127.0.0.1:%d", interceptProxyPort) }

// runConsole is the unified interactive UI: Findings triage + the Exfiltration monitor in one
// screen, switched with Tab. `console --json`/`--once` instead prints the non-interactive
// Exfiltration report (what `egress --json/--once` used to do).
func runConsole(flags []string, stdout io.Writer) (code int) {
	if has(flags, "--json") || has(flags, "--once") {
		return exfilReport(flags, stdout)
	}
	// The console needs a real terminal; refuse (and guide) when piped BEFORE doing a scan, so
	// `console > out.txt` exits fast instead of collecting evidence it will never render.
	if !isTerminal(os.Stdout) {
		fmt.Fprintln(stdout, "console needs a terminal — use `counterspy scan` (or `console --json`).")
		return 2
	}
	from := flagValue(flags, "--from")
	var assessments []model.Assessment
	var gaps []string
	if from != "" {
		as, g, err := loadSnapshot(from)
		if err != nil {
			fmt.Fprintln(stdout, "console: cannot read snapshot:", err)
			return 1
		}
		assessments = as
		gaps = g // a snapshot's collector gaps now surface in --from, same as a live scan (#8)
	} else {
		// Show the progress spinner while collecting (before the alt-screen opens) so the
		// TUI startup isn't a silent multi-second freeze — same helper the scan path uses.
		ev, g := collectWithSpinner()
		running, _ := collect.CollectRunningPaths()
		assessments = filterAllowed(interpret.Assess(score.Score(ev), running), userAllowlist())
		gaps = g
	}

	screen, err := newScreen()
	if err != nil {
		fmt.Fprintln(stdout, "console: cannot open screen:", err)
		return 1
	}
	if err := screen.Init(); err != nil {
		fmt.Fprintln(stdout, "console: cannot init screen:", err)
		return 1
	}
	// Assert our own window title. Without this the terminal derives the title from the foreground
	// child process, so it flips to "nettop" every time the egress monitor samples.
	screen.SetTitle("CounterSpy")
	// finiOnce guarantees the terminal is restored exactly once no matter which path
	// (signal, panic, error, or success) triggers it first.
	var finiOnce sync.Once
	fini := func() { finiOnce.Do(func() { screen.Fini() }) }

	// Restore the terminal on an EXTERNAL kill (SIGINT/TERM/HUP — e.g. `kill`, SSH drop)
	// which bypasses defers. SIGKILL can never be caught (true of any TUI) (ABORT-TUI
	// Worst-Case-Customer NO-GO).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	sigDone := make(chan struct{})
	defer func() { signal.Stop(sigCh); close(sigDone) }()
	go func() {
		select {
		case <-sigCh:
			fini()
			os.Exit(130)
		case <-sigDone: // normal exit — unregister and return instead of leaking this goroutine
		}
	}()

	// Deferred LIFO: Fini runs first (restore the terminal), THEN recover reports a
	// TUI-internal panic WITH its stack to stderr (durable RCA, not one opaque line to a
	// screen that's about to clear) (ABORT-TUI Future-Me #1).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "console: internal error: %v\n%s\n", r, debug.Stack())
			code = 1
		}
	}()
	defer fini()

	home, _ := os.UserHomeDir()
	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	cfgPath, storePath := feedbackPaths()
	cfg := feedback.LoadConfig(cfgPath)
	store := feedback.NewStore(storePath)
	acks := ack.NewStore(ackPath())
	_ = acks.Load() // missing/unreadable ack file → empty store; triage still opens (Rule 13)
	actor := &cliActor{
		root: filepath.Join(home, "CounterSpyQuarantine", ts), ts: ts,
		readOnly: from != "", store: store, detail: cfg.Detail, acks: acks,
	}
	// Pre-populate each finding's planned actions (pure) so the TUI can preview them in
	// the confirm modal without importing act (keeps internal/tui → model only).
	for i := range assessments {
		assessments[i].Actions = plannedActions(assessments[i].Finding)
	}
	m := tui.New(assessments, gaps)
	m.Liveness = livenessFor(assessments)
	m.Acked, m.AckChanged = acksFor(acks, assessments)
	m.ReadOnly = from != "" // snapshots are triage-only; act only on a live scan (untrusted paths)

	// Exfiltration sampler + a ~3Hz ticker. RunConsole samples LAZILY (only while Exfiltration is
	// the visible mode), so the ticker fires regardless but no nettop/lsof work happens in
	// Findings mode. The ticker closes `tick` on stop so RunConsole's sample goroutine ends.
	// 0.3s keeps the live view — and the zoom graph — advancing briskly (bounded by nettop/lsof
	// latency: if one sample takes longer than the interval, the sample loop just runs back-to-back).
	const interval = 0.3
	mon := newEgressMonitor(interval)
	// Passive DNS name resolution (#3): wire it into the live monitor BEFORE the sample loop runs
	// (SetResolver is set-once, read by Sample). Flagless + best-effort; returns a stop func.
	defer startNameResolver(mon)()
	tick := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop) // ends the ticker → closes tick → ends RunConsole's sample goroutine (also on panic)
	go func() {
		defer close(tick)
		t := time.NewTicker(time.Duration(interval * float64(time.Second)))
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case tick <- struct{}{}:
				default:
				}
			case <-stop:
				return
			}
		}
	}()
	// The `i` inspection overlay captures a flow's packets via native /dev/bpf (root); --no-inspect
	// disables it entirely for locked-down environments (spec §5.3), leaving a nil Inspector.
	err = tui.RunConsole(screen, m, actor, mon, newInspector(has(flags, "--no-inspect")), tick, pbcopy, nil, proxyEndpointForConsole())
	if err != nil {
		fmt.Fprintln(stdout, "console:", err)
		return 1
	}
	fini() // restore the terminal BEFORE the feedback prompt/messages (stdin cooked, stdout visible)
	_ = submitFeedback(cfg, store, chooseTransmitter(cfg, filepath.Dir(storePath)), cfg.Share == feedback.ShareAsk, os.Stdin, stdout)
	return 0
}

// loadSnapshot decodes a `scan --json` snapshot from a file or stdin ("-"), returning the
// assessments AND any collector gaps recorded at scan time so --from can surface them (#8).
// maxSnapshotBytes caps an untrusted --from snapshot so a hostile file can't OOM the
// "safe to open" read-only workflow (ABORT-TUI Attacker #1). A pre-#8 snapshot was a bare
// []Assessment; that shape is still accepted (gaps unknown → empty) so old snapshots keep loading.
const maxSnapshotBytes = 16 << 20 // 16 MiB

func loadSnapshot(path string) ([]model.Assessment, []string, error) {
	var rc io.Reader
	if path == "-" {
		rc = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		rc = f
	}
	b, err := io.ReadAll(io.LimitReader(rc, maxSnapshotBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxSnapshotBytes {
		return nil, nil, fmt.Errorf("snapshot exceeds %d MiB — refusing to load", maxSnapshotBytes>>20)
	}
	// Current wrapped form: {tool_version, gaps, assessments}.
	var snap report.Snapshot
	if err := json.Unmarshal(b, &snap); err == nil && snap.Assessments != nil {
		return snap.Assessments, snap.Gaps, nil
	}
	// Back-compat: a bare []Assessment from a pre-#8 snapshot (gaps unknown).
	var as []model.Assessment
	if err := json.Unmarshal(b, &as); err != nil {
		return nil, nil, err
	}
	return as, nil, nil
}

// cliActor adapts internal/act to the tui.Actor interface, capturing the run root+ts and
// converting the ManifestItem result to the manifest path the TUI tracks for restore.
type cliActor struct {
	root, ts string
	readOnly bool
	store    *feedback.Store
	detail   feedback.Detail
	acks     *ack.Store
}

func (c *cliActor) Quarantine(a model.Assessment) (string, error) {
	// Defense-in-depth: even if the UI's ReadOnly gate is ever bypassed, the actor
	// boundary refuses to move files from an untrusted snapshot (ABORT-TUI Attacker/Domain #2).
	if c.readOnly {
		return "", fmt.Errorf("quarantine refused — snapshot is read-only; run a live scan to act")
	}
	if len(a.Actions) == 0 { // Actions were pre-populated by runTUI (or empty for a bare process)
		a.Actions = plannedActions(a.Finding)
	}
	if len(a.Actions) == 0 {
		return "", fmt.Errorf("nothing to quarantine — no on-disk artifact for %s", a.Subject.Display())
	}
	item, err := act.Quarantine(c.root, c.ts, a)
	// A manifest was written iff at least one action completed — report the path only
	// then, so the TUI never claims "recorded" for a no-op (ABORT-TUI Domain #3).
	mp := ""
	if len(item.Actions) > 0 {
		mp = filepath.Join(c.root, "manifest.json")
	}
	return mp, err
}

func (c *cliActor) RestoreItem(manifest string, a model.Assessment) error {
	return act.RestoreItem(manifest, a.Subject.Key())
}

// Label records a TP/FP judgement to the local store (no network — submission is a
// separate, consent-gated step). A read-only snapshot may still be labeled.
func (c *cliActor) Label(a model.Assessment, falsePositive bool) error {
	if c.store == nil {
		return nil
	}
	label := model.LabelTruePositive
	if falsePositive {
		label = model.LabelFalsePositive
	}
	return c.store.Add(feedback.Capture(a, label, c.detail, feedback.NewNonce()))
}

// Ack records a LOCAL "reviewed / leave it" decision, fingerprinting the finding's current state so
// a later change re-flags it. Unack clears it. Both are local-only and never transmitted (#4).
func (c *cliActor) Ack(a model.Assessment) error {
	if c.acks == nil {
		return nil
	}
	return c.acks.Ack(a.Subject.Key(), ack.Fingerprint(a), c.ts)
}

func (c *cliActor) Unack(a model.Assessment) error {
	if c.acks == nil {
		return nil
	}
	return c.acks.Unack(a.Subject.Key())
}

// invokingUserHome resolves the HOME of the human who ran the tool, not root's — the tool
// runs under sudo, so os.UserHomeDir() would point at /var/root. Falls back to os.UserHomeDir.
func invokingUserHome() string {
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

// feedbackPaths returns the config and local-store paths under the invoking user's home.
func feedbackPaths() (configPath, storePath string) {
	base := filepath.Join(invokingUserHome(), ".config", "counterspy")
	return filepath.Join(base, "feedback.json"), filepath.Join(base, "feedback-store.json")
}

// ackPath returns the local ack-store path under the invoking user's home (#4).
func ackPath() string {
	return filepath.Join(invokingUserHome(), ".config", "counterspy", "ack.json")
}

// acksFor loads the ack store and derives the two per-finding display maps the TUI needs: which
// findings are acked, and which of those have CHANGED since they were reviewed (stored fingerprint
// no longer matches the finding's current state). A load error degrades to no acks — a triage view
// must never fail to open because a local note file is unreadable (Rule 13: surfaced via empty maps,
// the feature simply shows nothing rather than crashing).
func acksFor(store *ack.Store, assessments []model.Assessment) (acked, changed map[string]bool) {
	acked, changed = map[string]bool{}, map[string]bool{}
	if store == nil {
		return
	}
	for _, a := range assessments {
		key := a.Subject.Key()
		if rec, ok := store.Get(key); ok {
			acked[key] = true
			if rec.Fingerprint != ack.Fingerprint(a) {
				changed[key] = true
			}
		}
	}
	return
}

// submitFeedback pushes pending labels according to the consent level. off → nothing;
// ask → show the exact records and require an explicit yes; always → best-effort send.
// A failed send keeps the records for retry (triage never blocks on telemetry).
func submitFeedback(cfg feedback.Config, store *feedback.Store, tx feedback.Transmitter, ask bool, in io.Reader, out io.Writer) error {
	if cfg.Share == feedback.ShareOff {
		return nil
	}
	pending, err := store.Pending()
	if err != nil || len(pending) == 0 {
		return err
	}
	if ask {
		fmt.Fprintf(out, "\n  Share %d anonymized feedback record(s)? The exact bytes:\n", len(pending))
		b, _ := json.MarshalIndent(pending, "  ", "  ")
		fmt.Fprintf(out, "  %s\n  send? [y/N] ", string(b))
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			fmt.Fprintln(out, "  not shared (kept locally).")
			return nil
		}
	}
	if err := tx.Send(context.Background(), pending); err != nil {
		fmt.Fprintln(out, "  feedback not sent (kept for retry):", err)
		return err
	}
	fmt.Fprintf(out, "  shared %d record(s). Thank you.\n", len(pending))
	if err := store.MarkSent(pending); err != nil {
		// Sent, but the local mark didn't stick — surface it loudly (§13 fail-loud): those records
		// may re-send next run. The endpoint dedups on nonce+fingerprint, so this is a warning,
		// not data loss.
		fmt.Fprintln(out, "  warning: records were sent but could not be marked locally — they may re-send next run (the endpoint dedups):", err)
		return err
	}
	return nil
}

// chooseTransmitter uses the configured HTTP endpoint when set, else falls back to a local
// export file (the manual-share path) so labels are never lost when no endpoint is configured.
func chooseTransmitter(cfg feedback.Config, storeDir string) feedback.Transmitter {
	if cfg.Endpoint != "" {
		return &feedback.HTTPTransmitter{URL: cfg.Endpoint}
	}
	return &feedback.FileTransmitter{Path: filepath.Join(storeDir, "feedback-export.jsonl")}
}

// runFeedback is the non-TUI surface: list queued labels or force a submit.
func runFeedback(args []string, stdout io.Writer) int {
	cfgPath, storePath := feedbackPaths()
	cfg := feedback.LoadConfig(cfgPath)
	store := feedback.NewStore(storePath)
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		p, err := store.Pending()
		if err != nil {
			fmt.Fprintln(stdout, "feedback:", err)
			return 1
		}
		fmt.Fprintf(stdout, "%d pending feedback record(s); sharing is %q.\n", len(p), cfg.Share)
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	case "submit":
		if cfg.Share == feedback.ShareOff {
			fmt.Fprintln(stdout, "sharing is off — set share to \"ask\" or \"always\" in", cfgPath)
			return 0
		}
		if err := submitFeedback(cfg, store, chooseTransmitter(cfg, filepath.Dir(storePath)), true, os.Stdin, stdout); err != nil {
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stdout, "usage: counterspy feedback [list|submit]")
		return 2
	}
}

// newEgressMonitor builds the egress sampler. It's a package var so tests can inject a fake
// sampler and exercise the report/JSON path WITHOUT shelling out to nettop/lsof (CI-safe).
var newEgressMonitor = func(interval float64) tui.Sampler { return egress.New(interval) }

// newDNSCapture is the injectable seam for the passive DNS capture (mirrors newScreen/newEgressMonitor)
// so the name-resolver wiring is testable without root/pcap (Audit cp-p1h F-2).
var newDNSCapture = func(iface string, port int) (inspect.PacketSource, error) {
	return inspect.OpenPortCapture(iface, port)
}

// startNameResolver wires passive DNS name resolution into a live egress Monitor and returns a stop
// func (call it deferred). Best-effort + flagless: a non-Monitor sampler (the test fake) or a failed
// capture (no sudo / the non-darwin stub) leaves it a no-op — destinations then show their IPs, never
// a failure. SetResolver runs BEFORE the caller starts sampling (the set-once ordering, cp-p1e).
func startNameResolver(mon tui.Sampler) func() {
	realMon, ok := mon.(*egress.Monitor)
	if !ok {
		return func() {}
	}
	src, err := newDNSCapture(dnsInterface(), 53)
	if err != nil {
		return func() {}
	}
	cache := netname.NewCache(dnsCacheSize)
	realMon.SetResolver(cache) // before any Sample() reads m.resolve
	obs := netname.NewObserver(cache, src)
	go func() {
		// A mid-session read failure degrades destinations to IPs. Surfacing the terminating error for
		// RCA (Rule 14) needs a TUI-safe channel we don't have while the alt-screen is up — deferred to
		// the --non-interactive logging mode, which writes to a file/stdout (T-17).
		_ = obs.Run()
	}()
	return func() { _ = obs.Close() }
}

// newScreen opens the terminal screen. A package var so tests can inject a
// tcell.SimulationScreen and drive the TUI event loops without a real terminal (CI-safe).
var newScreen = func() (tcell.Screen, error) { return tcell.NewScreen() }

// runEgress observes per-app outbound traffic. On a TTY it launches the live "egress top"
// TUI; piped/redirected (or with --once) it prints a one-shot report (or --json).
// exfilReport prints the non-interactive Exfiltration report (or JSON) — the output the old
// `egress --once/--json` produced, now reached via `console --once/--json`.
func exfilReport(flags []string, stdout io.Writer) int {
	mon := newEgressMonitor(2.0)
	mon.Sample()           // establish a baseline
	groups := mon.Sample() // second sample carries rates
	if has(flags, "--json") {
		b, err := report.RenderEgressJSON(groups)
		if err != nil {
			fmt.Fprintln(os.Stderr, "render:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprint(stdout, report.RenderEgress(groups, colorEnabled()))
	return 0
}

func flagValue(flags []string, name string) string {
	for i, f := range flags {
		if f == name && i+1 < len(flags) {
			return flags[i+1]
		}
		if strings.HasPrefix(f, name+"=") {
			return strings.TrimPrefix(f, name+"=")
		}
	}
	return ""
}

// pbcopy writes s to the macOS clipboard (the egress TUI's copy-path action).
func pbcopy(s string) error {
	c := exec.Command("pbcopy")
	c.Stdin = strings.NewReader(s)
	return c.Run()
}

func dim(s string) string {
	if colorEnabled() {
		return "\x1b[38;5;244m" + s + "\x1b[0m"
	}
	return s
}

func has(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
