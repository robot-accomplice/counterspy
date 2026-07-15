package model

import "regexp"

// InspectCoverage is how much of an inspected flow was actually revealed — the honest
// per-flow verdict the inspection view leads with (spec §4). It mirrors inspect.Coverage;
// this is the pure, TUI-facing copy at the decoupling boundary (the tui may not import the
// inspect engine, which carries a BPF I/O edge).
type InspectCoverage int

const (
	InspectNone      InspectCoverage = iota // nothing captured / capture failed
	InspectMetadata                         // encrypted — SNI/handshake metadata only
	InspectPlaintext                        // readable application payload (unencrypted flow)
)

// InspectView is the inspection result rendered for one flow, expressed in the pure display
// vocabulary the decoupled TUI can import (the engine's inspect.Result — []byte/netip/error —
// is mapped to this by the main adapter). Content is sanitized outbound plaintext held in
// memory for the view only (§6, ephemeral); the view masks obvious secrets with Redact unless
// the user reveals, so a shoulder-surfer/screenshot doesn't leak them.
type InspectView struct {
	SNI       string
	Verdict   string // the honest one-line coverage verdict
	Coverage  InspectCoverage
	Encrypted bool // the flow is TLS (ciphertext) vs cleartext — set by the engine's evidence + port
	// Sent/Received are what each direction shows: readable text for a plaintext direction, or a
	// hexdump for a cleartext-but-binary one. Empty for a TLS-ciphertext direction (nothing readable)
	// and for an idle direction. Already sanitized (through Clean); the view masks secrets until reveal.
	Sent     string
	Received string
	// SentBytes/RecvBytes are the byte volumes each direction, shown for ANY coverage so an
	// encrypted flow still conveys its shape (e.g. a mostly-inbound response stream).
	SentBytes int
	RecvBytes int
	Err       string // capture-failure text, "" when capture succeeded
}

// Redaction patterns for the obvious, unambiguous secrets named in spec §6. High-entropy blob
// detection is intentionally left to feature #4 (highlighting), which owns the fuzzy heuristics;
// these three are pattern-exact and carry a negligible false-mask rate, so they mask by default now.
var (
	reBearer = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)
	reAWSKey = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	rePEM    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	// A dangling BEGIN (a partial/segmented capture with no END yet) must still be masked to the
	// end of the buffer, or the key material after the header leaks (cp-insC Audit F-1).
	rePEMOpen = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*`)
	// Sensitive HTTP header VALUES: an inspected cleartext HTTP request/response shows its headers,
	// and Authorization/Cookie/API-key values are credentials just like a bearer token (#3). Match a
	// header line (line-anchored, case-insensitive) and mask only its value, preserving the trailing
	// CR so lines don't merge. Covers the named set plus any *-token/*-secret/*-key header.
	reHeaderSecret = regexp.MustCompile(`(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|[a-z0-9-]*(?:token|secret|apikey|api-key)):[ \t]*[^\r\n]*`)
)

// redactMark is the ASCII replacement for a masked secret (ASCII so it renders under
// --glyphs=ascii and never depends on a font's glyph coverage).
const redactMark = "[redacted]"

// Redact masks obvious secrets (OAuth bearer tokens, AWS access-key IDs, PEM private-key
// blocks) in a plaintext payload before it's shown, so inspecting exfiltration doesn't itself
// spill the very secrets it's hunting (§6). Pure and idempotent: masking an already-masked
// string is a no-op. It is display masking only — the caller keeps the real bytes for reveal.
func Redact(s string) string {
	s = rePEM.ReplaceAllString(s, redactMark)     // complete BEGIN…END blocks first
	s = rePEMOpen.ReplaceAllString(s, redactMark) // then any dangling BEGIN…EOF (partial capture)
	s = reHeaderSecret.ReplaceAllString(s, "$1: "+redactMark)
	s = reBearer.ReplaceAllString(s, "Bearer "+redactMark)
	s = reAWSKey.ReplaceAllString(s, redactMark)
	return s
}
