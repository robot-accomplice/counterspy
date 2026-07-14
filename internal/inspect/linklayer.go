package inspect

import "encoding/binary"

// BPF datalink types we understand (subset of the DLT_* constants).
const (
	dltNull   = 0  // loopback/utun: 4-byte host-endian address family, then the IP packet
	dltEN10MB = 1  // Ethernet: 14-byte header, then IP (selected by ethertype)
	dltRaw    = 12 // raw IP, no link header
)

// stripLinkLayer removes the datalink header from a captured frame, returning the IP packet
// underneath. Handles Ethernet (IPv4/IPv6 ethertypes only), null/loopback (4-byte AF header),
// and raw IP. Returns ok=false for a too-short frame or a non-IP Ethernet payload (ARP, VLAN…).
func stripLinkLayer(dlt uint32, frame []byte) ([]byte, bool) {
	switch dlt {
	case dltEN10MB:
		if len(frame) < 14 {
			return nil, false
		}
		switch binary.BigEndian.Uint16(frame[12:14]) {
		case 0x0800, 0x86DD: // IPv4, IPv6
			return frame[14:], true
		default:
			return nil, false
		}
	case dltNull:
		if len(frame) < 4 {
			return nil, false
		}
		return frame[4:], true // the IP version nibble disambiguates v4/v6
	case dltRaw:
		return frame, true
	default:
		return nil, false
	}
}
