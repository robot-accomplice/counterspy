package inspect

import (
	"fmt"
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
	Err      error  // a real capture failure (not clean EOF); surfaced so the view can't hide it (§9)
}

// maxInspectBytes bounds how much outbound payload we accumulate for one inspection.
const maxInspectBytes = 8 << 10

// Inspect reads up to maxPackets from src, correlates the target flow by its remote endpoint,
// and produces a tier-0/1 result: the SNI + an honest "encrypted, metadata only" verdict for
// TLS, or the payload for a plaintext flow. Pure given the PacketSource (tests inject fixtures).
func Inspect(src PacketSource, flow Flow, maxPackets int) Result {
	r := Result{Flow: flow, Coverage: CoverageNone, Tier: "none"}
	var outbound []byte
	var seen, matched int // seen = TCP packets on this host past the kernel filter; matched = outbound-to-remote
	for i := 0; i < maxPackets; i++ {
		pkt, err := src.Next()
		if err == io.EOF {
			break // clean end of the fixture / capture window
		}
		if err != nil {
			r.Err = err // a real read failure — surfaced, never silently swallowed (§9)
			break
		}
		seg, ok := ParseIPPacket(pkt)
		if !ok {
			continue
		}
		seen++ // a TCP packet that passed the kernel host filter (either direction)
		if seg.Dst != flow.Remote || len(seg.Payload) == 0 {
			continue // only outbound (client → target) application segments
		}
		matched++
		outbound = append(outbound, seg.Payload...)
		// SNI is parsed over the accumulated in-order outbound bytes, so a ClientHello split
		// across TCP segments still resolves (best-effort reassembly; full reordering is T-10).
		if r.SNI == "" {
			if host, ok := ClientHelloSNI(outbound); ok {
				r.SNI = host
			}
		}
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
	case r.Err != nil:
		r.Verdict = "capture failed: " + r.Err.Error() // honest failure, not a clean "no data"
	default:
		// Report what the wire showed so an empty result is diagnosable: 0 seen = the flow was
		// silent during the window (an established connection's ClientHello/SNI is already in the
		// past); seen>0 but 0 matched = traffic to the host but no fresh outbound payload to read.
		r.Verdict = fmt.Sprintf("no application data captured (%d packets seen · %d outbound for this flow)", seen, matched)
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
	// 0x17 ApplicationData, 0x18 Heartbeat — none of which is readable plaintext.
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
