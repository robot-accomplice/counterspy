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
	GlyphActive    = '▸' // running now (live process, or loaded with a live PID)
	GlyphArmed     = '◐' // installed/loaded, will fire on a trigger — no live PID (issue #23)
	GlyphVestigial = '†' // dormant: disabled (.bak) or target missing — cannot execute
	GlyphSocket    = '↔' // holds a network listener
)

// LivenessGlyph maps an Assessment.Liveness state to its glyph (0 = no state).
func LivenessGlyph(state string) rune {
	switch state {
	case model.LivenessActive:
		return GlyphActive
	case model.LivenessArmed:
		return GlyphArmed
	case model.LivenessDormant:
		return GlyphVestigial
	default:
		return 0
	}
}

// Encryption annotation: a sealed box (▣) marks a TLS/encrypted flow, an open box (□) marks
// cleartext, absent = unknown. Both are single runes from the Geometric Shapes block (like the
// trust glyphs), so they render where a padlock/key emoji would tofu. In the tree and zoom this is
// a HEURISTIC from the destination port only (no capture); the inspection pane reflects the real
// captured verdict.
const (
	GlyphEncrypted = '▣'
	GlyphCleartext = '□'
)

// Intercept visibility (Phase 2) — an APERTURE that closes: how much of a decrypted-proxy flow we could
// actually read. This is a different question from GlyphEncrypted/GlyphCleartext (which is a
// port heuristic about whether a flow is TLS at all); this axis reports what interception achieved.
//
// Only GlyphDecrypted may read as success — the rest say WHY there is no content, and must never look
// like we saw something we didn't. Note ⊘ is NOT reused here: it already means "revoked certificate"
// (GlyphRevoked), and a pinned flow is not a revoked one.
const (
	GlyphDecrypted = '◉' // open: TLS terminated, plaintext captured
	GlyphPinned    = '⦸' // barred: the app rejected our leaf (cert pinning) — bypassed, not decrypted
	GlyphOpaque    = '◌' // empty: not interceptable (not TLS we could terminate)
	GlyphFlowError = '⨯' // broken: a capture/relay error; the connection was not tampered with
)

// EncKind is the encryption classification of a flow.
type EncKind int

const (
	EncUnknown EncKind = iota
	EncTLS             // a well-known TLS-by-default port
	EncClear           // a well-known cleartext port
)

// tlsPorts / clearPorts are the well-known ports we classify. STARTTLS ports (587 submission, 5222
// xmpp) are deliberately absent — they begin in the clear and may or may not upgrade, so claiming
// either would be dishonest; they stay EncUnknown.
var tlsPorts = map[int]bool{443: true, 4433: true, 5228: true, 5061: true, 563: true, 636: true,
	853: true, 990: true, 992: true, 993: true, 995: true, 6514: true, 8443: true, 9443: true, 465: true}
var clearPorts = map[int]bool{21: true, 23: true, 25: true, 70: true, 79: true, 80: true, 110: true,
	119: true, 143: true, 389: true, 3128: true, 8000: true, 8080: true}

// PortEnc classifies a destination port as TLS, cleartext, or unknown — a port-only heuristic, not
// a captured fact.
func PortEnc(port int) EncKind {
	switch {
	case tlsPorts[port]:
		return EncTLS
	case clearPorts[port]:
		return EncClear
	default:
		return EncUnknown
	}
}

// EncGlyph returns the base rune and combining runes to render for an EncKind — (0, nil) for
// unknown (nothing drawn). Callers render via a screen's combining-aware SetContent.
func EncGlyph(k EncKind) (rune, []rune) {
	switch k {
	case EncTLS:
		return GlyphEncrypted, nil
	case EncClear:
		return GlyphCleartext, nil
	default:
		return 0, nil
	}
}

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
// reads as ● not ◆. ◆ notarized is gated on the explicit `notarized` fact (an
// offline stapled-ticket check) rather than on `authority` alone, because the
// native backend sets `authority` for any valid signature (spec §8).
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
			case e.Facts["notarized"] == "true":
				return GlyphNotarized
			default:
				// A valid, trusted-anchor signature that is NOT notarized (Developer-ID
				// signed but not stapled). Since the native backend now sets `authority`
				// for any valid signature (not only Gatekeeper-notarized), ◆ is gated on
				// the explicit `notarized` fact so it can't over-report (PR #25 coupling).
				return GlyphSigned
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
	RunState rune // GlyphActive ▸, GlyphArmed ◐, GlyphVestigial †, or 0 — from Assessment.Liveness
	Socket   rune // GlyphSocket or 0
}

// Classify assembles the per-subject display marks (keyed by Subject.Key()):
//   - RunState = the glyph for the finding's liveness, which interpret already derived and stored on
//     Assessment.Liveness (▸ active / ◐ armed / † dormant / blank). Sourcing it from that single
//     value — rather than re-deriving here — is what keeps the scored run-state and the displayed
//     run-state from ever disagreeing (issue #23).
//   - Socket = ↔ if any evidence reports a LISTEN socket (Facts["listener"]=="true"). Independent of
//     RunState, so ▸ active and ↔ live-socket can co-occur.
func Classify(assessments []model.Assessment) map[string]Liveness {
	out := make(map[string]Liveness, len(assessments))
	for _, a := range assessments {
		lv := Liveness{RunState: LivenessGlyph(a.Liveness)}
		for _, e := range a.Evidence {
			if e.Facts["listener"] == "true" {
				lv.Socket = GlyphSocket
			}
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
		{GlyphActive, "liveness", "active (running now)", "active"},
		{GlyphArmed, "liveness", "armed (loaded, fires on a trigger — no live PID)", "armed"},
		{GlyphVestigial, "liveness", "dormant (disabled or target missing — cannot execute)", "dormant"},
		{GlyphSocket, "liveness", "live network socket", "socket"},
		{GlyphEncrypted, "encryption", "TLS-encrypted flow (□ = cleartext)", "encrypted"},
		{GlyphDecrypted, "intercept", "decrypted (plaintext captured)", "decrypted"},
		{GlyphPinned, "intercept", "pinned (app rejected our leaf — bypassed, not decrypted)", "pinned"},
		{GlyphOpaque, "intercept", "opaque (not interceptable)", "opaque"},
		{GlyphFlowError, "intercept", "capture/relay error (traffic not tampered with)", "error"},
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
