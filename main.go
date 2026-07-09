package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"counterspy/internal/act"
	"counterspy/internal/collect"
	"counterspy/internal/feedback"
	"counterspy/internal/interpret"
	"counterspy/internal/model"
	"counterspy/internal/report"
	"counterspy/internal/score"
	"counterspy/internal/tui"
	"github.com/gdamore/tcell/v2"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, stdout io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, "usage: counterspy scan [--json] [--interactive] | counterspy restore <manifest.json>")
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout)
	case "tui":
		return runTUI(args[1:], stdout)
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
	default:
		fmt.Fprintln(stdout, "unknown command:", args[0])
		return 2
	}
}

func runScan(flags []string, stdout io.Writer) int {
	asJSON := has(flags, "--json")
	interactive := has(flags, "--interactive")
	dry := has(flags, "--dry") // collect nothing; used by tests

	var ev []model.Evidence
	var gaps []string
	if !dry {
		ev, gaps = collectAll()
	}
	assessments := filterAllowed(interpret.Assess(score.Score(ev)), userAllowlist())

	if asJSON {
		for _, g := range gaps { // gaps to stderr — keep --json clean
			fmt.Fprintln(os.Stderr, "note:", g)
		}
		b, err := report.RenderJSON(assessments)
		if err != nil {
			fmt.Fprintln(os.Stderr, "render:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprint(stdout, report.Render(assessments, gaps, colorEnabled()))
	if interactive {
		quarantineLoop(assessments, stdout)
	}
	return 0
}

// collectAll fans out the collectors and returns any signal GAPS as friendly notes —
// a missing signal is reported, never silently read as "clean" (spec §9, Rule 13).
func collectAll() ([]model.Evidence, []string) {
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
	add("Persistence signal unavailable", collect.CollectPersistence)
	add("Process/network signal unavailable", collect.CollectProcesses)
	add("TCC privacy-grant signal unavailable — run with sudo to include it", collect.CollectTCC)
	// codesign runs ONCE per unique on-disk binary surfaced by the other collectors.
	// Skip .plist files (they aren't signed binaries — codesigning one yields a bogus
	// "unsigned") and anything that isn't a regular existing file.
	seen := map[string]bool{}
	for _, e := range append([]model.Evidence{}, ev...) {
		p := e.Subject.Path
		if p == "" || seen[p] || strings.HasSuffix(p, ".plist") {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.IsDir() {
			continue
		}
		seen[p] = true
		ev = append(ev, collect.CollectCodesign(p)...)
	}
	return ev, gaps
}

// colorEnabled reports whether to emit ANSI color: a real terminal on stdout and
// NO_COLOR unset (https://no-color.org).
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func quarantineLoop(assessments []model.Assessment, stdout io.Writer) {
	home, _ := os.UserHomeDir()
	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	root := filepath.Join(home, "CounterSpyQuarantine", ts)
	in := bufio.NewReader(os.Stdin)

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
			if _, err := act.Quarantine(root, ts, a); err != nil {
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

func runTUI(flags []string, stdout io.Writer) (code int) {
	from := flagValue(flags, "--from")
	var assessments []model.Assessment
	var gaps []string
	if from != "" {
		as, err := loadSnapshot(from)
		if err != nil {
			fmt.Fprintln(stdout, "tui: cannot read snapshot:", err)
			return 1
		}
		assessments = as
	} else {
		ev, g := collectAll()
		assessments = filterAllowed(interpret.Assess(score.Score(ev)), userAllowlist())
		gaps = g
	}

	// The TUI needs a real terminal; refuse (and guide) when piped.
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(stdout, "TUI needs a terminal — use `counterspy scan` (or `--json`).")
		return 2
	}
	screen, err := tcell.NewScreen()
	if err != nil {
		fmt.Fprintln(stdout, "tui: cannot open screen:", err)
		return 1
	}
	if err := screen.Init(); err != nil {
		fmt.Fprintln(stdout, "tui: cannot init screen:", err)
		return 1
	}
	// finiOnce guarantees the terminal is restored exactly once no matter which path
	// (signal, panic, error, or success) triggers it first.
	var finiOnce sync.Once
	fini := func() { finiOnce.Do(func() { screen.Fini() }) }

	// Restore the terminal on an EXTERNAL kill (SIGINT/TERM/HUP — e.g. `kill`, SSH drop)
	// which bypasses defers. SIGKILL can never be caught (true of any TUI) (ABORT-TUI
	// Worst-Case-Customer NO-GO).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigCh
		fini()
		os.Exit(130)
	}()

	// Deferred LIFO: Fini runs first (restore the terminal), THEN recover reports a
	// TUI-internal panic WITH its stack to stderr (durable RCA, not one opaque line to a
	// screen that's about to clear) (ABORT-TUI Future-Me #1).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "tui: internal error: %v\n%s\n", r, debug.Stack())
			code = 1
		}
	}()
	defer fini()

	home, _ := os.UserHomeDir()
	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	cfgPath, storePath := feedbackPaths()
	cfg := feedback.LoadConfig(cfgPath)
	store := feedback.NewStore(storePath)
	actor := &cliActor{
		root: filepath.Join(home, "CounterSpyQuarantine", ts), ts: ts,
		readOnly: from != "", store: store, detail: cfg.Detail,
	}
	// Pre-populate each finding's planned actions (pure) so the TUI can preview them in
	// the confirm modal without importing act (keeps internal/tui → model only).
	for i := range assessments {
		assessments[i].Actions = plannedActions(assessments[i].Finding)
	}
	m := tui.New(assessments, gaps)
	m.ReadOnly = from != "" // snapshots are triage-only; act only on a live scan (untrusted paths)
	if err := tui.Run(screen, m, actor); err != nil {
		fmt.Fprintln(stdout, "tui:", err)
		return 1
	}
	fini() // restore the terminal BEFORE the feedback prompt/messages (stdin cooked, stdout visible)
	_ = submitFeedback(cfg, store, chooseTransmitter(cfg, filepath.Dir(storePath)), cfg.Share == feedback.ShareAsk, os.Stdin, stdout)
	return 0
}

// loadSnapshot decodes a `scan --json` snapshot ([]model.Assessment) from a file or stdin ("-").
// maxSnapshotBytes caps an untrusted --from snapshot so a hostile file can't OOM the
// "safe to open" read-only workflow (ABORT-TUI Attacker #1).
const maxSnapshotBytes = 16 << 20 // 16 MiB

func loadSnapshot(path string) ([]model.Assessment, error) {
	var rc io.Reader
	if path == "-" {
		rc = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rc = f
	}
	b, err := io.ReadAll(io.LimitReader(rc, maxSnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSnapshotBytes {
		return nil, fmt.Errorf("snapshot exceeds %d MiB — refusing to load", maxSnapshotBytes>>20)
	}
	var as []model.Assessment
	return as, json.Unmarshal(b, &as)
}

// cliActor adapts internal/act to the tui.Actor interface, capturing the run root+ts and
// converting the ManifestItem result to the manifest path the TUI tracks for restore.
type cliActor struct {
	root, ts string
	readOnly bool
	store    *feedback.Store
	detail   feedback.Detail
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

func (c *cliActor) Restore(manifest string) error { return act.Restore(manifest) }

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
	return store.MarkSent(pending)
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
