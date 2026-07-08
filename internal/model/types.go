// Package model is the shared vocabulary. It does no I/O and imports nothing
// outside the standard library's fmt.
package model

import "fmt"

type SignalKind string

const (
	KindPersistence SignalKind = "persistence"
	KindCodesign    SignalKind = "codesign"
	KindTCC         SignalKind = "tcc"
	KindProcess     SignalKind = "process"
)

// Subject is who a piece of evidence is about.
type Subject struct {
	Path  string
	PID   int
	Label string
}

// Key is the correlation identity used to group evidence about the same subject.
// The two namespaces are tagged distinctly ("path:" vs "pid:") so a captured path
// can never alias a synthetic PID key.
//
// Precedence invariant: when a Path is known it is the whole identity and the PID
// is dropped from the key — so two live processes executing the same on-disk binary
// correlate as one subject. Collectors always emit either a real PID (>0) or a Path;
// a Subject with neither is not produced (see ticket T-1).
func (s Subject) Key() string {
	if s.Path != "" {
		return "path:" + s.Path
	}
	return fmt.Sprintf("pid:%d", s.PID)
}

// Evidence is one observation from one collector about one subject.
type Evidence struct {
	Subject Subject
	Kind    SignalKind
	Summary string
	Weight  int
	Facts   map[string]string
}

// ActionKind is the closed set of operations the actor performs (T-2: typed so a
// typo can't compile, matching the SignalKind precedent).
type ActionKind string

const (
	ActionBootout ActionKind = "bootout" // disable a launch item so it can't respawn
	ActionMove    ActionKind = "move"    // move an artifact to quarantine (reversible)
)

// Action is a single operation the actor will perform, in order.
type Action struct {
	Kind ActionKind
	From string
	To   string
}

// Finding is all evidence about one subject, correlated and totaled.
type Finding struct {
	Subject  Subject
	Score    int
	Kinds    []SignalKind
	Evidence []Evidence
	Tripwire string
	Actions  []Action
}

type ManifestItem struct {
	Subject  Subject
	Actions  []Action
	Evidence []Evidence
}

type Manifest struct {
	Timestamp string
	Items     []ManifestItem
}

// Recommendation is the synthesized action for a Finding (spec §8.1).
type Recommendation string

const (
	RecQuarantine  Recommendation = "Quarantine"
	RecInvestigate Recommendation = "Investigate"
	RecMonitor     Recommendation = "Monitor"
)

// Assessment is a Finding repackaged for a human: a plain-language verdict, a
// heuristic category, and a recommended action. Produced by the interpret layer so
// the CLI and any future TUI/WebUI render the same synthesis (spec §8.1, §12).
type Assessment struct {
	Finding
	Verdict        string
	Category       string
	Recommendation Recommendation
}
