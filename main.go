package main

import (
	"bufio"
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
	case "restore":
		if len(args) < 2 {
			fmt.Fprintln(stdout, "usage: counterspy restore <manifest.json>")
			return 2
		}
		if err := act.Restore(args[1]); err != nil {
			fmt.Fprintln(stdout, "restore:", err)
			return 1
		}
		fmt.Fprintln(stdout, "restored from", args[1])
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
	if !dry {
		ev = collectAll(stdout)
	}
	assessments := interpret.Assess(score.Score(ev))

	if asJSON {
		b, err := report.RenderJSON(assessments)
		if err != nil {
			fmt.Fprintln(stdout, "render:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprint(stdout, report.Render(assessments))
	if interactive {
		quarantineLoop(assessments, stdout)
	}
	return 0
}

// collectAll fans out the collectors, printing a gap line for any that fail — a
// missing signal is reported, never silently read as "clean" (spec §9, Rule 13).
func collectAll(stdout io.Writer) []model.Evidence {
	var ev []model.Evidence
	add := func(name string, fn func() ([]model.Evidence, error)) {
		e, err := fn()
		if err != nil {
			fmt.Fprintf(stdout, "! %s signal unavailable: %v\n", name, err)
			return
		}
		ev = append(ev, e...)
	}
	add("persistence", collect.CollectPersistence)
	add("process/network", collect.CollectProcesses)
	add("TCC", collect.CollectTCC)
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
	return ev
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
		fmt.Fprintf(stdout, "\nQuarantine %s  [%s]? [y/N/q] ", a.Subject.Key(), a.Recommendation)
		line, _ := in.ReadString('\n')
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "q":
			return
		case "y":
			f := a.Finding
			f.Actions = actions
			if _, err := act.Quarantine(root, ts, f); err != nil {
				fmt.Fprintln(stdout, "  quarantine stopped (partial state recorded in manifest):", err)
				continue
			}
			fmt.Fprintln(stdout, "  quarantined ->", root)
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

func has(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
