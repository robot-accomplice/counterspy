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
// TrustLabel maps the egress collector's trust-label strings (apple / notarized /
// signed / unsigned / revoked / unknown / "") to trust glyphs, so the egress view
// shares the same vocabulary as findings. Returns 0 (blank) for unknown/unclassified.
func TrustLabel(s string) rune {
	switch s {
	case "apple":
		return GlyphApple
	case "notarized":
		return GlyphNotarized
	case "signed":
		return GlyphSigned
	case "unsigned":
		return GlyphUnsigned
	case "revoked":
		return GlyphRevoked
	default:
		return 0
	}
}

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
// the set of filesystem paths referenced by running processes — executables and
// argv path tokens (see collect.CollectRunningPaths / T-4, ESC-1). Rules:
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

// Gap is the single inter-slot separator; markField is one display cell per slot.
// Uniform cadence is structural: every slot is one glyph or one blank, joined by
// exactly one Gap (see spec §3.1 — no width library needed, all glyphs are width-1).
const (
	Gap       = " "
	markField = 1
)

// Cluster renders the four fixed slots [concern][trust][run-state][socket] with
// uniform cadence. A zero rune renders as a blank slot of the same width.
func Cluster(concern, trust rune, lv Liveness) string {
	slots := [...]rune{concern, trust, lv.RunState, lv.Socket}
	parts := make([]string, len(slots))
	for i, g := range slots {
		parts[i] = pad(g)
	}
	return strings.Join(parts, Gap)
}

func pad(g rune) string {
	if g == 0 {
		return strings.Repeat(" ", markField)
	}
	return string(g)
}

// LegendRow documents one glyph. Legend is the single source of truth rendered
// by the in-app legend (CLI footer + TUI overlay) and the README key
// (see legend_doc_test.go). Meaning is the full text; Short is the compact label
// for space-tight surfaces like the TUI overlay.
type LegendRow struct {
	Glyph   rune
	Axis    string
	Meaning string
	Short   string
}

// Legend returns the canonical, ordered vocabulary key.
func Legend() []LegendRow {
	return []LegendRow{
		{GlyphQuarantine, "concern", "quarantine", "quarantine"},
		{GlyphInvestigate, "concern", "investigate", "investigate"},
		{GlyphMonitor, "concern", "monitor", "monitor"},
		{GlyphApple, "trust", "Apple system code", "Apple"},
		{GlyphNotarized, "trust", "notarized (Developer ID, accepted)", "notarized"},
		{GlyphSigned, "trust", "signed, not notarized", "signed"},
		{GlyphUnsigned, "trust", "unsigned", "unsigned"},
		{GlyphRevoked, "trust", "revoked certificate", "revoked"},
		{GlyphActive, "liveness", "running", "running"},
		{GlyphVestigial, "liveness", "vestigial (installed, not running)", "vestigial"},
		{GlyphSocket, "liveness", "live network socket", "socket"},
	}
}

// LegendCompact returns the vocabulary grouped into one line per axis (concern,
// trust, liveness) using Short labels — for the space-tight TUI ? overlay. Derived
// from Legend() so it can never drift from the marks the app actually emits.
func LegendCompact() []string {
	var axes []string
	byAxis := map[string]string{}
	for _, r := range Legend() {
		if _, seen := byAxis[r.Axis]; !seen {
			axes = append(axes, r.Axis)
		}
		if byAxis[r.Axis] != "" {
			byAxis[r.Axis] += "  "
		}
		byAxis[r.Axis] += string(r.Glyph) + " " + r.Short
	}
	lines := make([]string, 0, len(axes))
	for _, ax := range axes {
		lines = append(lines, byAxis[ax])
	}
	return lines
}

// LegendMarkdown renders the Legend as a Markdown table — the single source the
// README key must match (enforced by legend_doc_test.go, so the docs can never
// drift from the marks the app actually emits).
func LegendMarkdown() string {
	var b strings.Builder
	b.WriteString("| Mark | Axis | Meaning |\n|---|---|---|\n")
	for _, r := range Legend() {
		b.WriteString("| ")
		b.WriteRune(r.Glyph)
		b.WriteString(" | " + mdCell(r.Axis) + " | " + mdCell(r.Meaning) + " |\n")
	}
	return b.String()
}

// mdCell escapes a value for a Markdown table cell so a future Meaning containing
// a pipe or newline can't corrupt the rendered table (cp-T9 review F-1).
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

// LegendLine is a compact one-line key for the CLI footer.
func LegendLine() string {
	var b strings.Builder
	b.WriteString("key: ")
	for i, r := range Legend() {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteRune(r.Glyph)
		b.WriteString(" ")
		b.WriteString(r.Meaning)
	}
	return b.String()
}
