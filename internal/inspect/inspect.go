package inspect

import (
	"fmt"
	"io"
	"net/netip"

	"counterspy/internal/mark"
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

// Result is what the inspection view renders for a flow. Both directions are captured: Outbound
// (what the app SENDS, the exfil concern) and Inbound (what it RECEIVES, the response). A flow is
// often active in only one direction at a time (an established TLS connection receiving is inbound-
// heavy; its ClientHello/SNI is already in the past), so showing both is what makes on-demand
// inspection useful, not just handshake-time.
type Result struct {
	Flow     Flow
	SNI      string // hostname from the TLS ClientHello (outbound), if seen
	Coverage Coverage
	Tier     string // which tier yielded the result: "metadata" | "plaintext" | "none"
	Verdict  string // the honest one-line coverage verdict shown to the user
	Outbound []byte // application bytes sent to the remote (client → target)
	Inbound  []byte // application bytes received from the remote (target → client)
	// Per-direction plaintext flags: a direction's bytes are readable TEXT when set (shown as text);
	// otherwise the bytes are still shown, as a hexdump. The flag governs text-vs-hex rendering, not
	// whether content is shown; the wire bytes are always surfaced (§6: never fabricate decryption,
	// but never hide what actually crossed the wire either).
	OutboundPlaintext bool
	InboundPlaintext  bool
	// Encrypted is true when the flow is CONFIRMED or strongly-presumed TLS: a ClientHello SNI or a
	// TLS record was seen, or the remote is a well-known TLS port. Distinguishes "ENCRYPTED (TLS)
	// ciphertext" from "cleartext but binary/opaque"; a :80 flow with a non-text body is NOT TLS.
	Encrypted bool
	Err       error // a real capture failure (not clean EOF); surfaced so the view can't hide it (§9)
}

// maxInspectBytes bounds how much payload we accumulate for one inspection, across both directions.
const maxInspectBytes = 8 << 10

// Inspect reads up to maxPackets from src, correlates the target flow by its remote endpoint in
// BOTH directions, and produces a tier-0/1 result: the SNI + an honest "encrypted, metadata only"
// verdict for TLS, or the readable payload (either direction) for a plaintext flow. Pure given the
// PacketSource (tests inject fixtures).
func Inspect(src PacketSource, flow Flow, maxPackets int) Result {
	r := Result{Flow: flow, Coverage: CoverageNone, Tier: "none"}
	var outbound, inbound []byte
	var seen int // TCP packets on this flow past the kernel filter (either direction, incl. ACKs)
	for i := 0; i < maxPackets; i++ {
		pkt, err := src.Next()
		if err == io.EOF {
			break // clean end of the fixture / capture window
		}
		if err != nil {
			r.Err = err // a real read failure: surfaced, never silently swallowed (§9)
			break
		}
		seg, ok := ParseIPPacket(pkt)
		if !ok {
			continue
		}
		seen++
		if len(seg.Payload) == 0 {
			continue // ACK / control segment: seen, but no application bytes to accumulate
		}
		switch {
		case seg.Dst == flow.Remote: // client → target (sent)
			outbound = append(outbound, seg.Payload...)
			// SNI is parsed over the accumulated in-order outbound bytes, so a ClientHello split
			// across TCP segments still resolves (best-effort reassembly; full reordering is T-10).
			if r.SNI == "" {
				if host, ok := ClientHelloSNI(outbound); ok {
					r.SNI = host
				}
			}
		case seg.Src == flow.Remote: // target → client (received)
			inbound = append(inbound, seg.Payload...)
		}
		if len(outbound)+len(inbound) >= maxInspectBytes {
			break
		}
	}
	r.Outbound, r.Inbound = outbound, inbound
	r.OutboundPlaintext = looksPlaintext(outbound)
	r.InboundPlaintext = looksPlaintext(inbound)
	// TLS only when there's actual evidence (an SNI/handshake or a TLS record) or the remote is a
	// well-known TLS port. Never infer "encrypted" merely from bytes being non-text: a cleartext
	// download's binary body is opaque but NOT TLS (the reported :80 mislabel).
	r.Encrypted = r.SNI != "" || looksTLS(outbound) || looksTLS(inbound) ||
		mark.PortEnc(int(flow.Remote.Port())) == mark.EncTLS

	switch {
	case r.OutboundPlaintext || r.InboundPlaintext:
		r.Coverage, r.Tier = CoveragePlaintext, "plaintext"
		r.Verdict = "plaintext: readable (not encrypted)"
	case len(outbound) > 0 || len(inbound) > 0:
		r.Coverage, r.Tier = CoverageMetadata, "metadata"
		switch {
		case r.Encrypted && r.SNI != "":
			r.Verdict = "ENCRYPTED · SNI " + r.SNI + " · TLS ciphertext (not decryptable)"
		case r.Encrypted:
			r.Verdict = "ENCRYPTED · TLS ciphertext (not decryptable)"
		default:
			r.Verdict = "CLEARTEXT · binary / non-text payload (shown as hex, not TLS)"
		}
	case r.Err != nil:
		r.Verdict = "capture failed: " + r.Err.Error() // honest failure, not a clean "no data"
	default:
		// An established connection can be silent in the capture window (its handshake/SNI is in the
		// past); report what the wire showed so an empty result is honest, not misread as "clean".
		r.Verdict = fmt.Sprintf("no application data captured (%d packets seen)", seen)
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
	// TLS record content types: 0x14 ChangeCipherSpec, 0x15 Alert, 0x16 Handshake,
	// 0x17 ApplicationData, 0x18 Heartbeat; none of which is readable plaintext.
	if b[0] >= 0x14 && b[0] <= 0x18 {
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

// looksTLS reports whether bytes begin with a TLS record header: a content type (0x14-0x18)
// followed by a plausible protocol version (0x03 0x00-0x04). Positive evidence of TLS, unlike the
// weak "not printable" negative in looksPlaintext, so a binary cleartext payload isn't mistaken for
// ciphertext.
func looksTLS(b []byte) bool {
	return len(b) >= 3 && b[0] >= 0x14 && b[0] <= 0x18 && b[1] == 0x03 && b[2] <= 0x04
}
