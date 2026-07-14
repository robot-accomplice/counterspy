package inspect

import (
	"encoding/binary"
	"net/netip"
)

// TCPSegment is one parsed TCP segment: its 4-tuple and payload (the bytes above TCP, e.g. a
// TLS record or an HTTP request). All fields come from bounds-checked parsing of capture bytes.
type TCPSegment struct {
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Payload []byte
}

// ParseIPPacket parses an IPv4 or IPv6 packet carrying TCP into a TCPSegment. It dispatches on
// the IP version nibble; returns ok=false for anything that isn't well-formed IPv4/IPv6+TCP
// (capture bytes are attacker-influenced, so every length is checked before use).
func ParseIPPacket(pkt []byte) (TCPSegment, bool) {
	if len(pkt) < 1 {
		return TCPSegment{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4TCP(pkt)
	case 6:
		return parseIPv6TCP(pkt)
	default:
		return TCPSegment{}, false
	}
}

const protoTCP = 6

func parseIPv4TCP(pkt []byte) (TCPSegment, bool) {
	if len(pkt) < 20 {
		return TCPSegment{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4 // header length in bytes
	if ihl < 20 || len(pkt) < ihl {
		return TCPSegment{}, false
	}
	if pkt[9] != protoTCP {
		return TCPSegment{}, false
	}
	src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	// The IPv4 total-length field can be smaller than the captured buffer (padding); clamp to it.
	total := int(binary.BigEndian.Uint16(pkt[2:]))
	if total >= ihl && total <= len(pkt) {
		pkt = pkt[:total]
	}
	return parseTCP(src, dst, pkt[ihl:])
}

func parseIPv6TCP(pkt []byte) (TCPSegment, bool) {
	if len(pkt) < 40 {
		return TCPSegment{}, false
	}
	if pkt[6] != protoTCP { // next-header; extension headers are not handled (rare for TLS flows)
		return TCPSegment{}, false
	}
	var s, d [16]byte
	copy(s[:], pkt[8:24])
	copy(d[:], pkt[24:40])
	return parseTCP(netip.AddrFrom16(s), netip.AddrFrom16(d), pkt[40:])
}

// parseTCP reads the TCP header (ports + variable data offset) and returns the segment with its
// payload and the src/dst AddrPorts (zone-free canonical addresses via netip).
func parseTCP(srcIP, dstIP netip.Addr, seg []byte) (TCPSegment, bool) {
	if len(seg) < 20 {
		return TCPSegment{}, false
	}
	dataOff := int(seg[12]>>4) * 4 // header length in bytes
	if dataOff < 20 || len(seg) < dataOff {
		return TCPSegment{}, false
	}
	return TCPSegment{
		Src:     netip.AddrPortFrom(srcIP, binary.BigEndian.Uint16(seg[0:2])),
		Dst:     netip.AddrPortFrom(dstIP, binary.BigEndian.Uint16(seg[2:4])),
		Payload: seg[dataOff:],
	}, true
}
