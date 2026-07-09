package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"counterspy/internal/act"
	"counterspy/internal/collect"
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

func runTUI(flags []string, stdout io.Writer) int {
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
	defer screen.Fini() // ALWAYS restore the terminal, even on panic

	home, _ := os.UserHomeDir()
	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	actor := &cliActor{root: filepath.Join(home, "CounterSpyQuarantine", ts), ts: ts}
	if err := tui.Run(screen, tui.New(assessments, gaps), actor); err != nil {
		screen.Fini()
		fmt.Fprintln(stdout, "tui:", err)
		return 1
	}
	return 0
}

// loadSnapshot decodes a `scan --json` snapshot ([]model.Assessment) from a file or stdin ("-").
func loadSnapshot(path string) ([]model.Assessment, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var as []model.Assessment
	return as, json.Unmarshal(b, &as)
}

// cliActor adapts internal/act to the tui.Actor interface, capturing the run root+ts and
// converting the ManifestItem result to the manifest path the TUI tracks for restore.
type cliActor struct {
	root, ts string
}

func (c *cliActor) Quarantine(a model.Assessment) (string, error) {
	a.Actions = plannedActions(a.Finding)
	if _, err := act.Quarantine(c.root, c.ts, a); err != nil {
		return "", err
	}
	return filepath.Join(c.root, "manifest.json"), nil
}

func (c *cliActor) Restore(manifest string) error { return act.Restore(manifest) }

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
