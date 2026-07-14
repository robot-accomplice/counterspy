// Package model is the shared vocabulary. It does no I/O and imports nothing
// outside the standard library's fmt.
package model

import (
	"fmt"
	"strings"
)

// Version is stamped into every manifest so an incident can be traced to the exact
// build (weights, allowlist, rules) that produced a quarantine (ABORT C4).
const Version = "v0.5.0"

// Clean strips control/escape characters from attacker-influenced strings (labels,
// paths, argv) before they reach a terminal — so a crafted value can't inject ANSI or
// newlines that spoof a prompt, corrupt a tcell buffer, or hide a finding.
func Clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f: // ESC, CR, LF, other C0 controls
		case r >= 0x202a && r <= 0x202e: // bidi embeddings/overrides (RTLO spoofing)
		case r >= 0x2066 && r <= 0x2069: // bidi isolates
		case r >= 0x200b && r <= 0x200f: // zero-width + LRM/RLM
		case r == 0xfeff: // zero-width no-break space / BOM
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

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

// Display is a human-facing name: label, else path, else the correlation key.
// (Key() is the internal grouping id and leaks "path:"/"pid:" prefixes — not for display.)
func (s Subject) Display() string {
	if s.Label != "" {
		return s.Label
	}
	if s.Path != "" {
		return s.Path
	}
	return s.Key()
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

// ManifestItem records not just WHAT moved but WHY — the score, tripwire, category,
// recommendation, and verdict that justified the action — so a later incident is
// root-causable from the manifest alone (ABORT C4).
type ManifestItem struct {
	Subject        Subject
	Actions        []Action
	Evidence       []Evidence
	Score          int
	Tripwire       string
	Category       string
	Recommendation Recommendation
	Verdict        string
}

type Manifest struct {
	Timestamp   string
	ToolVersion string
	Items       []ManifestItem
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

// FeedbackSchema is the FeedbackRecord wire-schema version (independent of tool Version).
const FeedbackSchema = "1"

// Feedback labels: the user's verdict on a finding.
const (
	LabelFalsePositive = "false_positive" // the tool flagged legitimate software
	LabelTruePositive  = "true_positive"  // the tool flagged correctly
)

// FeedbackRecord is an intrinsically-anonymous field report: a finding's heuristic
// fingerprint plus the user's label. It carries no raw path, username, hostname, or
// (by default) private identifier — anonymity lives in the data, not the transport.
type FeedbackRecord struct {
	Schema         string            `json:"schema"`
	Tool           string            `json:"tool"`  // Version — weights/allowlist provenance
	Nonce          string            `json:"nonce"` // per-submission, non-correlatable
	Label          string            `json:"label"`
	Recommendation string            `json:"recommendation"`
	Category       string            `json:"category"`
	ScoreBand      string            `json:"score_band"` // banded, not exact
	Signals        []string          `json:"signals"`
	Codesign       string            `json:"codesign"`
	PathClass      string            `json:"path_class"` // class, never the path
	Tripwire       bool              `json:"tripwire"`
	Identity       string            `json:"identity,omitempty"` // public, or consented private
	Extra          map[string]string `json:"extra,omitempty"`    // detail=full only
}
