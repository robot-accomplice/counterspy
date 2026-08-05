// Package interpret repackages scored findings into human-consumable assessments:
// a plain-language verdict, a heuristic category, and a recommended action. Pure
// (no I/O) and rule-based (Rule 6) so verdicts are reproducible and the CLI/TUI/WebUI
// all render the same synthesis (spec §8.1).
package interpret

import (
	"fmt"
	"strings"

	"counterspy/internal/model"
	"counterspy/internal/score"
)

// Assess annotates each finding with a category, verdict, and recommendation.
// `running` is the set of filesystem paths referenced by live processes (from
// collect.CollectRunningPaths); it feeds liveness only. Assess itself does no I/O,
// so verdicts stay reproducible from (findings, running) alone (Rule 6). Pass nil
// when the run-state is unknown; findings then read as armed/blank, never active.
func Assess(findings []model.Finding, running map[string]bool) []model.Assessment {
	out := make([]model.Assessment, 0, len(findings))
	for _, f := range findings {
		s := signalsOf(f)
		cat := categorize(s)
		live := livenessState(f, running)
		out = append(out, model.Assessment{
			Finding:        f,
			Category:       cat,
			Verdict:        verdict(f, s),
			Recommendation: recommend(f, s, cat, live),
			Liveness:       live,
			Concern:        concernOf(f, s),
		})
	}
	return out
}

// livenessState derives the finding's run-state (issue #23). It is the single source of liveness.
// Both scoring (recommend) and display (mark.Classify) read the value it stores on the Assessment,
// so the two can never disagree. Precedence:
//   - dormant. A persistence remnant that CANNOT execute: its target is missing/renamed, or its
//     plist is a disabled ".bak" variant (the com.ironclad.agent case). Caps scoring at Monitor.
//   - active. A live process, or a persistence target found in `running`.
//   - armed. A persistence target that exists (extracted, not missing) but isn't running: loaded,
//     will fire on its trigger. NOT dormant. It can still execute.
//   - "". No process/persistence run-state (e.g. a bare file or lone TCC grant), OR a
//     persistence finding whose target couldn't be extracted (an unknown target must not read as a
//     misleading dormant/armed; swarm cp-T2 F-1).
func livenessState(f model.Finding, running map[string]bool) string {
	var hasProc, targetKnown, targetRunning bool
	for _, e := range f.Evidence {
		switch e.Kind {
		case model.KindProcess:
			hasProc = true
		case model.KindPersistence:
			if strings.Contains(e.Summary, "missing/renamed") || strings.Contains(e.Facts["plist"], ".bak") {
				return model.LivenessDormant
			}
			if t := e.Facts["target"]; t != "" {
				targetKnown = true
				if running[t] {
					targetRunning = true
				}
			}
		}
	}
	switch {
	case hasProc, targetRunning:
		return model.LivenessActive
	case targetKnown:
		return model.LivenessArmed
	default:
		return ""
	}
}

// concernOf derives the coarse concern band (issue #4) from trust × location × behavior. It exists to
// make the Findings view legible (NOT to change scoring) so the large tail of Apple-signed system
// code (~300 Monitor rows) recedes to Minimal and the few non-Apple/unsigned/actively-networking items
// stand out. Apple-namespace code is the floor (Minimal) unless it is somehow unsigned (defensive:
// real Apple code never is). Everything else accrues a small additive score, banded like egress concern.
func concernOf(f model.Finding, s signals) model.ConcernLevel {
	if isAppleNamespace(f) && !s.unsigned {
		return model.Minimal
	}
	score := 0
	switch { // trust
	case s.unsigned:
		score += 2
	case !s.acceptedSigned:
		score++ // signed-but-not-Gatekeeper-accepted, or unknown provenance
	}
	switch pathBucket(f.Subject.Path) { // location
	case "tmp", "hidden":
		score += 2
	case "user":
		score++
	}
	if s.listener { // behavior
		score += 2
	} else if s.connection {
		score++
	}
	if s.persistence {
		score++
	}
	if s.screen || s.fullDisk || s.inputMon || s.accessibility {
		score++
	}
	return concernBand(score)
}

// concernBand maps the additive concern score to a band. Mirrors internal/egress band() thresholds so
// the two concern surfaces read on one scale (the enum is shared; the score inputs differ by domain).
func concernBand(score int) model.ConcernLevel {
	switch {
	case score >= 4:
		return model.Elevated
	case score >= 3:
		return model.Notable
	case score >= 1:
		return model.Low
	default:
		return model.Minimal
	}
}

// isAppleNamespace reports whether a finding is first-party Apple code: a com.apple.* bundle label,
// a /System path, or a codesign authority Gatekeeper accepted as Apple's. This is the recede-to-floor
// signal; it is deliberately Apple-only (a NOTARIZED third party is trusted but not floored, since
// notarized spyware exists).
func isAppleNamespace(f model.Finding) bool {
	if strings.HasPrefix(f.Subject.Label, "com.apple.") {
		return true
	}
	if strings.HasPrefix(f.Subject.Path, "/System/") {
		return true
	}
	for _, e := range f.Evidence {
		if e.Kind == model.KindCodesign {
			a := e.Facts["authority"]
			if strings.Contains(a, "Apple") || a == "Software Signing" {
				return true
			}
		}
	}
	return false
}

// pathBucket coarsely classifies where a subject lives, most-concerning first (tmp/hidden > user >
// system). Empty path (a PID-only subject) buckets as "" (no location signal).
func pathBucket(p string) string {
	switch {
	case p == "":
		return ""
	case hasAnyPrefix(p, "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"):
		return "tmp"
	case strings.Contains(p, "/."):
		return "hidden"
	case strings.Contains(p, "/Users/"):
		return "user"
	default:
		return "system"
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// signals is the boolean shape of a finding, extracted once.
type signals struct {
	unsigned, persistence, listener, connection bool
	inputMon, accessibility, screen, fullDisk   bool
	acceptedSigned                              bool // has a Gatekeeper-accepted signing authority
	tccGrants                                   []string
}

func signalsOf(f model.Finding) signals {
	var s signals
	for _, e := range f.Evidence {
		switch e.Kind {
		case model.KindCodesign:
			if e.Facts["signed"] == "false" {
				s.unsigned = true
			}
			if e.Facts["authority"] != "" { // set only when Gatekeeper accepted (codesign T-3)
				s.acceptedSigned = true
			}
		case model.KindPersistence:
			s.persistence = true
		case model.KindProcess:
			if e.Facts["listener"] == "true" {
				s.listener = true
			}
			if e.Facts["net"] == "connection" {
				s.connection = true
			}
		case model.KindTCC:
			s.tccGrants = append(s.tccGrants, e.Summary)
			switch e.Facts["service"] {
			case "kTCCServiceListenEvent":
				s.inputMon = true
			case "kTCCServiceAccessibility":
				s.accessibility = true
			case "kTCCServiceScreenCapture":
				s.screen = true
			case "kTCCServiceSystemPolicyAllFiles":
				s.fullDisk = true
			}
		}
	}
	return s
}

func categorize(s signals) string {
	permissive := s.screen || s.fullDisk || s.inputMon || s.accessibility
	// A lone permission grant on otherwise-quiet (often legitimately-signed) software
	// is NOT spyware. Only call it that when corroborated by another signal, else it
	// reads as a scary false positive and erodes trust (cp-9 Audit F-1).
	corroborated := s.unsigned || s.persistence || s.listener || s.connection || len(dedupeGrants(s.tccGrants)) >= 2
	switch {
	case s.inputMon && s.accessibility:
		return "keylogger"
	case s.unsigned && s.listener && s.persistence:
		return "backdoor"
	case permissive && corroborated:
		return "surveillance-capable"
	case permissive:
		return "permission-grant" // neutral: a single, uncorroborated privacy grant
	case s.persistence:
		return "persistence-only"
	default:
		return "unknown"
	}
}

// verdict composes one plain-language sentence from the present signals.
func verdict(f model.Finding, s signals) string {
	var parts []string
	if s.unsigned {
		parts = append(parts, "an unsigned binary")
	}
	if len(s.tccGrants) > 0 {
		parts = append(parts, strings.ToLower(strings.Join(dedupeGrants(s.tccGrants), " + ")))
	}
	if s.persistence {
		parts = append(parts, "installed for persistence")
	}
	if s.listener {
		parts = append(parts, "listening for inbound connections")
	} else if s.connection {
		parts = append(parts, "making outbound network connections")
	}
	who := f.Subject.Display()
	if len(parts) == 0 {
		return fmt.Sprintf("%s shows weak, isolated signals.", who)
	}
	return fmt.Sprintf("%s is %s.", who, joinWithAnd(parts))
}

// recommend maps a finding to an action. C3 hardening (ABORT v0.1.0-rc2):
//   - a tripwire always Quarantines (and tripwires require unsigned evidence, so signed
//     software never reaches Quarantine through this path);
//   - Gatekeeper-accepted signed software is never auto-Quarantined (capped at
//     Investigate) so the tool can't be weaponized to disable legit signed apps/EDR;
//   - "weak" categories (persistence-only / permission-grant / unknown) never
//     auto-Quarantine without a tripwire, softening the score-only escalation that
//     flagged benign unsigned dev tools.
func recommend(f model.Finding, s signals, cat string, liveness string) model.Recommendation {
	if f.Tripwire != "" {
		return model.RecQuarantine
	}
	// A dormant remnant (disabled .bak or missing target) cannot execute. Cap it at Monitor so a
	// dead artifact never reads as urgently as a live, loaded one (issue #23). A tripwire still wins.
	if liveness == model.LivenessDormant {
		return model.RecMonitor
	}
	weak := cat == "persistence-only" || cat == "permission-grant" || cat == "unknown"
	if s.acceptedSigned && !s.unsigned {
		if !weak && f.Score >= score.ShowThreshold {
			return model.RecInvestigate
		}
		return model.RecMonitor
	}
	if weak {
		// Escape hatch: overwhelming accumulated signal on an UNSIGNED weak-category
		// subject still Quarantines. Otherwise a high-scoring unsigned persistent
		// infostealer would be capped at Investigate forever (ABORT rc3 C3 false-neg).
		if f.Score >= score.CriticalTier {
			return model.RecQuarantine
		}
		if f.Score >= score.ShowThreshold {
			return model.RecInvestigate
		}
		return model.RecMonitor
	}
	switch {
	case f.Score >= score.HighTier:
		return model.RecQuarantine
	case f.Score >= score.ShowThreshold:
		return model.RecInvestigate
	default:
		return model.RecMonitor
	}
}

func dedupeGrants(g []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range g {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func joinWithAnd(parts []string) string {
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
	}
}
