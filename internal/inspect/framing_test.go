package inspect

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// ipv4TCP builds an IPv4+TCP packet with the given endpoints and payload.
func ipv4TCP(src, dst netip.AddrPort, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	tcp[12] = 5 << 4 // data offset = 5 words (20 bytes), no options
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[9] = protoTCP
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	return append(ip, tcp...)
}

func ipv6TCP(src, dst netip.AddrPort, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	tcp[12] = 5 << 4
	tcp = append(tcp, payload...)

	ip := make([]byte, 40)
	ip[0] = 6 << 4
	ip[6] = protoTCP
	s16, d16 := src.Addr().As16(), dst.Addr().As16()
	copy(ip[8:24], s16[:])
	copy(ip[24:40], d16[:])
	return append(ip, tcp...)
}

func TestParseIPPacket_IPv4TCPPayloadAndTuple(t *testing.T) {
	src := netip.MustParseAddrPort("10.0.0.2:51000")
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	ch := buildClientHello("example.com")
	seg, ok := ParseIPPacket(ipv4TCP(src, dst, ch))
	if !ok {
		t.Fatal("expected a parsed TCP segment")
	}
	if seg.Src != src || seg.Dst != dst {
		t.Fatalf("4-tuple: got %v→%v, want %v→%v", seg.Src, seg.Dst, src, dst)
	}
	// End-to-end: the extracted payload is the TLS record → SNI parses out.
	if host, ok := ClientHelloSNI(seg.Payload); !ok || host != "example.com" {
		t.Fatalf("SNI from extracted payload: got (%q,%v)", host, ok)
	}
}

func TestParseIPPacket_IPv6TCP(t *testing.T) {
	src := netip.MustParseAddrPort("[fe80::1]:51000")
	dst := netip.MustParseAddrPort("[2606:2800:220:1:248:1893:25c8:1946]:443")
	seg, ok := ParseIPPacket(ipv6TCP(src, dst, []byte("GET / HTTP/1.1\r\n")))
	if !ok || seg.Dst != dst || string(seg.Payload) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("IPv6 parse: ok=%v dst=%v payload=%q", ok, seg.Dst, seg.Payload)
	}
}

func TestParseIPPacket_RejectsMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x45},          // truncated IPv4 header
		{0x40, 0, 0, 0}, // version 4 but IHL 0
		append([]byte{0x45, 0, 0, 0, 0, 0, 0, 0, 0, 17 /*UDP*/}, make([]byte, 20)...), // not TCP
		{0x70}, // unknown IP version 7
	}
	for i, c := range cases {
		if _, ok := ParseIPPacket(c); ok {
			t.Errorf("case %d: malformed packet must not parse", i)
		}
	}
}
