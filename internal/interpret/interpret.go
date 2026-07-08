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
func Assess(findings []model.Finding) []model.Assessment {
	out := make([]model.Assessment, 0, len(findings))
	for _, f := range findings {
		s := signalsOf(f)
		out = append(out, model.Assessment{
			Finding:        f,
			Category:       categorize(s),
			Verdict:        verdict(f, s),
			Recommendation: recommend(f),
		})
	}
	return out
}

// signals is the boolean shape of a finding, extracted once.
type signals struct {
	unsigned, persistence, listener, connection bool
	inputMon, accessibility, screen, fullDisk   bool
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
	// is NOT spyware — only call it that when corroborated by another signal, else it
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

func recommend(f model.Finding) model.Recommendation {
	switch {
	case f.Tripwire != "" || f.Score >= score.HighTier:
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
