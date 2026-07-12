// Package mark is the pure symbology vocabulary: the glyph marks CounterSpy
// draws for a finding's concern tier, code-signing trust, and liveness, plus the
// Legend that documents them. It does no I/O and imports only internal/model, so
// every render surface (CLI report, TUI, egress) shares one source of truth.
package mark

import (
	"strings"

	"counterspy/internal/model"
)

// Concern (tier) glyphs — carried by BOTH color and glyph, so tier survives a
// NO_COLOR / piped terminal.
const (
	GlyphQuarantine  = '⚑'
	GlyphInvestigate = '▲'
	GlyphMonitor     = '·'
)

// Trust (provenance) glyphs — a filled→hollow→struck gradient of decreasing trust.
const (
	GlyphApple     = '●' // Apple system code
	GlyphNotarized = '◆' // Developer ID, Gatekeeper-accepted
	GlyphSigned    = '◇' // signed but not accepted/notarized
	GlyphUnsigned  = '○' // no signature
	GlyphRevoked   = '⊘' // revoked certificate
)

// Liveness glyphs.
const (
	GlyphActive    = '▸' // subject maps to a running process
	GlyphVestigial = '†' // persistence install whose target is not running
	GlyphSocket    = '↔' // holds a network listener
)

// Concern maps a recommendation tier to its glyph.
func Concern(r model.Recommendation) rune {
	switch r {
	case model.RecQuarantine:
		return GlyphQuarantine
	case model.RecInvestigate:
		return GlyphInvestigate
	default:
		return GlyphMonitor
	}
}

// Trust classifies a finding's code-signing provenance from its codesign
// evidence Facts. Returns 0 (blank slot) when the finding carries no codesign
// signal. Apple-authority is checked before Developer-ID so Apple system code
// reads as ● not ◆. The mapping is written against current develop (spctl-accepted)
// semantics; see spec §8 for the PR #25 coupling.
func Trust(f model.Finding) rune {
	for _, e := range f.Evidence {
		if e.Kind != model.KindCodesign {
			continue
		}
		switch e.Facts["signed"] {
		case "revoked":
			return GlyphRevoked
		case "false":
			return GlyphUnsigned
		case "true":
			switch a := e.Facts["authority"]; {
			case a == "":
				return GlyphSigned
			case isAppleAuthority(a):
				return GlyphApple
			default:
				return GlyphNotarized
			}
		}
	}
	return 0
}

// isAppleAuthority reports whether an spctl-accepted signing authority is Apple's
// own platform code. A third-party Developer-ID leaf ALWAYS begins with
// "Developer ID " ("Developer ID Application:" / "Developer ID Installer:"), so we
// exclude that prefix first — otherwise a legitimately-notarized Developer-ID cert
// whose company name merely contains "Apple" (e.g. "Developer ID Application: Apple
// Fan LLC") would forge the ● Apple-system mark. Only after ruling out Developer-ID
// do we accept Apple's platform authorities. (swarm cp T1 review F-1, crit.)
func isAppleAuthority(a string) bool {
	if strings.HasPrefix(a, "Developer ID") {
		return false
	}
	return strings.Contains(a, "Apple") || a == "Software Signing"
}

// Liveness is the run-state + socket marks for one subject. A zero field is a
// blank slot. RunState and Socket are independent so ▸ active and ↔ live-socket
// can co-occur.
type Liveness struct {
	RunState rune // GlyphActive, GlyphVestigial, or 0
	Socket   rune // GlyphSocket or 0
}

// Classify derives per-subject liveness (keyed by Subject.Key()). `running` is
// the set of real executable paths of currently-running processes (see
// collect.CollectExecPaths / T-4). Rules:
//   - socket = ↔ if any evidence reports a LISTEN socket (Facts["listener"]=="true")
//   - a finding with process evidence is active (it is a live process)
//   - else a persistence finding is active iff its target path is running, else vestigial
//   - otherwise run-state is blank (a file/grant with no process/persistence liveness)
//
// Liveness is DISPLAY-ONLY and never influences scoring.
func Classify(assessments []model.Assessment, running map[string]bool) map[string]Liveness {
	out := make(map[string]Liveness, len(assessments))
	for _, a := range assessments {
		var lv Liveness
		var hasProc bool
		// Persistence run-state is derived from the extracted target executable
		// (Facts["target"]), NOT Subject.Path: when target extraction fails,
		// persistence.go falls Subject.Path back to the plist path, which would
		// then falsely read as vestigial. An unknown target stays blank, not a
		// misleading † (swarm cp-T2 review F-1).
		var targetKnown, targetRunning bool
		for _, e := range a.Evidence {
			if e.Facts["listener"] == "true" {
				lv.Socket = GlyphSocket
			}
			switch e.Kind {
			case model.KindProcess:
				hasProc = true
			case model.KindPersistence:
				if t := e.Facts["target"]; t != "" {
					targetKnown = true
					if running[t] {
						targetRunning = true
					}
				}
			}
		}
		switch {
		case hasProc: // a live process wins; process/persistence can't co-occur today (defensive, cp-T2 F-2)
			lv.RunState = GlyphActive
		case targetRunning:
			lv.RunState = GlyphActive
		case targetKnown:
			lv.RunState = GlyphVestigial
		}
		out[a.Subject.Key()] = lv
	}
	return out
}
