package netname

import (
	"encoding/binary"
	"io"

	"counterspy/internal/inspect"
)

// Observer runs a long-lived passive capture, parsing the DNS responses it sees into the name cache.
// The packet source is injected (not opened here) so the observer is testable with a fixture source
// and the darwin /dev/bpf dependency stays in main, keeping this package portable and unit-tested.
type Observer struct {
	cache *Cache
	src   inspect.PacketSource
}

// NewObserver builds an observer over a live (or fixture) packet source, feeding cache.
func NewObserver(cache *Cache, src inspect.PacketSource) *Observer {
	return &Observer{cache: cache, src: src}
}

// Run drains the source, feeding every DNS RESPONSE (src port 53) into the cache, until the source
// ends or is closed. Intended to run in its own goroutine. A malformed or non-DNS packet is skipped.
// It RETURNS the error that stopped it (io.EOF on a clean end/close, else a real read failure) so the
// caller can log a genuine failure instead of the DNS cache silently going stale (Rule 14 / Audit
// cp-p1c F-3). TCP DNS is not parsed (rare for a client; needs the 2-byte length prefix + reassembly).
// Those names are simply missed.
func (o *Observer) Run() error {
	for {
		pkt, err := o.src.Next()
		if err != nil {
			return err
		}
		if len(pkt) == 0 {
			// A source that yields no bytes AND no error violates the PacketSource contract; stop
			// rather than spin the goroutine at 100% CPU (Antagonist cp-p1c F-1). Real sources never
			// do this. bpfCapture.Next returns a packet or an error.
			return io.EOF
		}
		payload, srcPort, _, ok := udpPayload(pkt)
		if !ok || srcPort != 53 { // only a server→client response (src 53) carries the answers we cache
			continue
		}
		recs, ok := ParseDNSResponse(payload)
		if !ok {
			continue
		}
		for _, r := range recs {
			o.cache.Put(r.IP.String(), r.Name)
		}
	}
}

// Close closes the underlying source. Run then returns once its in-flight/next src.Next() reports the
// resulting error. NOTE (Audit cp-p1c F-1): for the live /dev/bpf source, Close runs on a different
// goroutine than Run's read, so it races the read on the fd; the non-blocking device makes the racing
// read return a benign error (which cleanly ends Run) rather than corrupt anything. Hardening
// bpfCapture with an atomic "closed" flag so Close→Run always ends via a clean io.EOF is tracked as
// T-15b/T-16 and done in the darwin-capture checkpoint.
func (o *Observer) Close() error { return o.src.Close() }

// udpPayload strips the IPv4/IPv6 + UDP headers from an IP-layer packet (link header already removed
// by the capture), returning the UDP payload and src/dst ports. ok is false for a non-UDP, truncated,
// or non-first-fragment packet, or an unknown IP version. IPv6 extension headers are not walked
// (matching the kernel filter); such packets return ok=false.
func udpPayload(pkt []byte) (payload []byte, srcPort, dstPort int, ok bool) {
	if len(pkt) < 1 {
		return nil, 0, 0, false
	}
	var hdrLen, proto int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return nil, 0, 0, false
		}
		hdrLen = int(pkt[0]&0x0f) * 4
		if hdrLen < 20 || len(pkt) < hdrLen {
			return nil, 0, 0, false
		}
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 { // non-first fragment → no transport header
			return nil, 0, 0, false
		}
		proto = int(pkt[9])
	case 6:
		if len(pkt) < 40 {
			return nil, 0, 0, false
		}
		hdrLen, proto = 40, int(pkt[6])
	default:
		return nil, 0, 0, false
	}
	if proto != protoUDP {
		return nil, 0, 0, false
	}
	if len(pkt) < hdrLen+8 { // UDP header is 8 bytes
		return nil, 0, 0, false
	}
	srcPort = int(binary.BigEndian.Uint16(pkt[hdrLen : hdrLen+2]))
	dstPort = int(binary.BigEndian.Uint16(pkt[hdrLen+2 : hdrLen+4]))
	return pkt[hdrLen+8:], srcPort, dstPort, true
}

const protoUDP = 17
