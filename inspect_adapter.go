package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"counterspy/internal/inspect"
	"counterspy/internal/model"
	"counterspy/internal/tui"
)

// Inspection capture bounds: an `i` capture is a modal action, so it must return quickly.
// maxWait caps the wall-clock window (an idle flow can't hang the UI, T-11); maxPackets caps how
// many packets we accumulate (a ClientHello / first plaintext request lands in the first few).
const (
	inspectMaxWait    = 1500 * time.Millisecond
	inspectMaxPackets = 256
	defaultIface      = "en0"
)

// liveInspector satisfies tui.Inspector with the native /dev/bpf capture + tier-0/1 engine. It is
// the main-side adapter at the decoupling boundary: it speaks the engine's rich types (netip,
// []byte, error) and maps them to the pure model.InspectView the TUI renders. Requires root.
type liveInspector struct{}

func (liveInspector) Inspect(conn model.Conn) model.InspectView {
	remote, ok := remoteAddrPort(conn)
	if !ok {
		return model.InspectView{Verdict: "cannot inspect: unparseable remote endpoint"}
	}
	iface := outboundInterface(remote)
	src, err := inspect.OpenLiveCapture(iface, remote, inspectMaxWait)
	if err != nil {
		// Fail loud (§9): the raw error stays on Err for diagnostics; Verdict is the human line.
		return model.InspectView{Err: err.Error(), Verdict: captureFailVerdict(err)}
	}
	defer src.Close()
	res := inspect.Inspect(src, inspect.Flow{PID: conn.PID, Remote: remote}, inspectMaxPackets)
	return toInspectView(res)
}

// toInspectView maps an engine Result to the pure TUI view. The coverage switch is exhaustive over
// the current tiers; a future tier (Phase B/C) added to inspect.Coverage lands in the default and
// is shown honestly as "not decrypted" rather than silently mislabeled (cp-insC Audit F-3). The
// mapping is pinned by TestToInspectView_CoverageMapping so adding a tier forces a decision here.
func toInspectView(r inspect.Result) model.InspectView {
	v := model.InspectView{
		SNI: r.SNI, Verdict: r.Verdict, Encrypted: r.Encrypted,
		SentBytes: len(r.Outbound), RecvBytes: len(r.Inbound), // volumes shown for any coverage
		Sent:     renderFlowBytes(r.Outbound, r.OutboundPlaintext, r.Encrypted),
		Received: renderFlowBytes(r.Inbound, r.InboundPlaintext, r.Encrypted),
	}
	if r.Err != nil {
		v.Err = r.Err.Error()
	}
	switch r.Coverage {
	case inspect.CoverageMetadata:
		v.Coverage = model.InspectMetadata
	case inspect.CoveragePlaintext:
		v.Coverage = model.InspectPlaintext
	default:
		v.Coverage = model.InspectNone
	}
	return v
}

// renderFlowBytes turns one direction's captured bytes into what the pane shows: readable TEXT when
// the direction is plaintext (HTTP headers, protocol text, secrets still masked in the view); a
// HEXDUMP when it's cleartext-but-binary (so the actual payload is inspectable, and its ASCII gutter
// surfaces any embedded text); or nothing when the flow is TLS (the bytes are ciphertext noise, and
// the verdict already says so). The wire bytes are never hidden just for being non-text (§6).
func renderFlowBytes(b []byte, plaintext, encrypted bool) string {
	if len(b) == 0 {
		return ""
	}
	// A direction whose OWN bytes are readable is shown even inside a TLS flow; the per-direction
	// plaintext flag beats the flow-level encrypted flag (a TLS connection can carry a cleartext
	// direction in the capture window). Decode HTTP structure + body first, else the raw text.
	if plaintext {
		if decoded, ok := inspect.DecodeCleartext(b); ok {
			return sanitizeMultiline(decoded)
		}
		return sanitizeMultiline(string(b))
	}
	if encrypted {
		return "" // TLS ciphertext: random bytes; surfacing them adds noise, not information
	}
	// Cleartext-but-binary: a gzipped/chunked HTTP body isn't "plaintext" but IS decodable into
	// readable text (#3, the reveal-more goal); only a genuine non-HTTP binary payload hexdumps.
	if decoded, ok := inspect.DecodeCleartext(b); ok {
		return sanitizeMultiline(decoded)
	}
	return hexDump(b)
}

// hexDump renders bytes as a canonical offset / hex / ASCII dump (xxd-style), 16 bytes per line.
func hexDump(b []byte) string {
	const perLine = 16
	var sb strings.Builder
	for off := 0; off < len(b); off += perLine {
		end := off + perLine
		if end > len(b) {
			end = len(b)
		}
		line := b[off:end]
		fmt.Fprintf(&sb, "%04x  ", off)
		for i := 0; i < perLine; i++ {
			if i < len(line) {
				fmt.Fprintf(&sb, "%02x ", line[i])
			} else {
				sb.WriteString("   ")
			}
			if i == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for _, c := range line {
			if c >= 0x20 && c < 0x7f {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

// sanitizeMultiline strips control/escape chars from each line (so a crafted payload can't inject
// ANSI/terminal control) while PRESERVING newlines, so a readable protocol keeps its line structure
// in the content pane. model.Clean alone would flatten the payload to one line.
func sanitizeMultiline(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = model.Clean(ln)
	}
	return strings.Join(lines, "\n")
}

// captureFailVerdict turns an OpenLiveCapture error into the one-line verdict shown in the pane.
// The monitor (nettop/lsof/ps) runs unprivileged, but reading raw packets off /dev/bpf is gated
// by macOS behind root, so the common failure is "not root". That gets an actionable message
// naming the exact fix rather than a raw errno, so inspection reads as the one sudo-only feature,
// not a broken tool. Any other failure is surfaced verbatim.
func captureFailVerdict(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "inspection needs packet-capture access: relaunch with `sudo counterspy console`"
	}
	return "capture failed: " + err.Error()
}

func remoteAddrPort(conn model.Conn) (netip.AddrPort, bool) {
	ip, err := netip.ParseAddr(conn.Endpoint.IP)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(conn.Endpoint.Port)), true
}

// outboundInterface resolves which interface the kernel would route this flow through, so the BPF
// capture binds to the right one. A connected UDP socket reveals the source IP without sending any
// packet (routing-only); we map that IP to its interface. Native (no shell-out); falls back to en0.
func outboundInterface(remote netip.AddrPort) string {
	c, err := net.Dial("udp", remote.String())
	if err != nil {
		return defaultIface
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return defaultIface
	}
	local, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return defaultIface
	}
	local = local.Unmap()
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if p, ok := a.(*net.IPNet); ok {
				if ip, ok2 := netip.AddrFromSlice(p.IP); ok2 && ip.Unmap() == local {
					return ifc.Name
				}
			}
		}
	}
	return defaultIface
}

// newInspector returns the live inspector unless --no-inspect disables inspection for locked-down
// environments (spec §5.3); a nil Inspector makes the `i` overlay report inspection as disabled.
func newInspector(noInspect bool) tui.Inspector {
	if noInspect {
		return nil
	}
	return liveInspector{}
}

// dnsCacheSize bounds the passive-DNS name cache (distinct IPs); ~4k covers a busy session cheaply.
const dnsCacheSize = 4096

// dnsInterface picks the interface the passive DNS observer captures on: the default-route interface
// (probed toward a public resolver), falling back to en0, the same resolution the flow inspector uses.
func dnsInterface() string {
	return outboundInterface(netip.MustParseAddrPort("8.8.8.8:53"))
}
