package main

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"counterspy/internal/inspect"
	"counterspy/internal/model"
	"counterspy/internal/tui"
)

// Inspection capture bounds: a consented `i` capture is a modal action, so it must return quickly.
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
	src, err := inspect.OpenLiveCapture(outboundInterface(remote), remote, inspectMaxWait)
	if err != nil {
		// Fail loud (§9): a real capture failure (e.g. not root) is surfaced, not hidden.
		return model.InspectView{Err: err.Error(), Verdict: "capture failed: " + err.Error()}
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
	v := model.InspectView{SNI: r.SNI, Verdict: r.Verdict}
	if r.Err != nil {
		v.Err = r.Err.Error()
	}
	switch r.Coverage {
	case inspect.CoverageNone:
		v.Coverage = model.InspectNone
	case inspect.CoverageMetadata:
		v.Coverage = model.InspectMetadata
	case inspect.CoveragePlaintext:
		v.Coverage = model.InspectPlaintext
		v.Content = sanitizeMultiline(string(r.Payload))
	default:
		v.Coverage = model.InspectNone // unknown/newer tier — honest, never an overclaim
	}
	return v
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
