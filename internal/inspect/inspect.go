package inspect

import (
	"io"
	"net/netip"
)

// Flow identifies the connection to inspect, taken from the Exfiltration row the user pressed `i`
// on. Correlation is by remote endpoint (the model dedups connections per destination), with the
// PID kept for attribution and a future BPF filter / hook target.
type Flow struct {
	PID    int
	Remote netip.AddrPort
}

// Coverage is how much of a flow the interceptor could actually reveal.
type Coverage int

const (
	CoverageNone      Coverage = iota // encrypted, nothing decrypted (metadata may still exist)
	CoverageMetadata                  // SNI / handshake metadata only
	CoveragePlaintext                 // full application payload (unencrypted flow)
	// hook / keylog / proxy tiers add more values in later phases.
)

// Result is what the inspection view renders for a flow.
type Result struct {
	Flow     Flow
	SNI      string // hostname from the TLS ClientHello, if seen
	Coverage Coverage
	Tier     string // which tier yielded the result: "metadata" | "plaintext" | "none"
	Verdict  string // the honest one-line coverage verdict shown to the user
	Payload  []byte // outbound application bytes, when a tier surfaced plaintext
}

// maxInspectBytes bounds how much outbound payload we accumulate for one inspection.
const maxInspectBytes = 8 << 10

// Inspect reads up to maxPackets from src, correlates the target flow by its remote endpoint,
// and produces a tier-0/1 result: the SNI + an honest "encrypted, metadata only" verdict for
// TLS, or the payload for a plaintext flow. Pure given the PacketSource (tests inject fixtures).
func Inspect(src PacketSource, flow Flow, maxPackets int) Result {
	r := Result{Flow: flow, Coverage: CoverageNone, Tier: "none"}
	var outbound []byte
	for i := 0; i < maxPackets; i++ {
		pkt, err := src.Next()
		if err == io.EOF || err != nil {
			break
		}
		seg, ok := ParseIPPacket(pkt)
		if !ok || seg.Dst != flow.Remote || len(seg.Payload) == 0 {
			continue // only outbound (client → target) application segments
		}
		if r.SNI == "" {
			if host, ok := ClientHelloSNI(seg.Payload); ok {
				r.SNI = host
			}
		}
		outbound = append(outbound, seg.Payload...)
		if len(outbound) >= maxInspectBytes {
			break
		}
	}

	switch {
	case looksPlaintext(outbound):
		r.Coverage, r.Tier, r.Payload = CoveragePlaintext, "plaintext", outbound
		r.Verdict = "plaintext — readable (not encrypted)"
	case len(outbound) > 0:
		r.Coverage, r.Tier = CoverageMetadata, "metadata"
		if r.SNI != "" {
			r.Verdict = "ENCRYPTED · SNI " + r.SNI + " · not decrypted (metadata only)"
		} else {
			r.Verdict = "ENCRYPTED · not decrypted (metadata only)"
		}
	default:
		r.Verdict = "no application data captured"
	}
	return r
}

// looksPlaintext heuristically decides whether accumulated bytes are a readable (unencrypted)
// protocol rather than a TLS record or opaque ciphertext: not a TLS handshake/app-data record
// and overwhelmingly printable in the leading window.
func looksPlaintext(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if b[0] == 0x16 || b[0] == 0x17 { // TLS handshake / application_data record
		return false
	}
	n := len(b)
	if n > 64 {
		n = 64
	}
	printable := 0
	for _, c := range b[:n] {
		if c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*100/n >= 85
}
