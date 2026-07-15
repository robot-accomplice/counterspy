package inspect

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
)

// accepts runs the assembled filter over a packet in x/net/bpf's pure-Go VM (no root) and reports
// whether the kernel would keep it (a non-zero accept length).
func accepts(t *testing.T, insns []bpf.Instruction, pkt []byte) bool {
	t.Helper()
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	n, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("vm run: %v", err)
	}
	return n > 0
}

// withProto returns a copy of an IPv4 packet with its protocol byte overwritten (to forge non-TCP).
func withProto(pkt []byte, proto byte) []byte {
	c := append([]byte(nil), pkt...)
	c[9] = proto
	return c
}

func TestFlowFilter_IPv4HostScoped(t *testing.T) {
	host := netip.MustParseAddr("93.184.216.34")
	other := netip.MustParseAddr("8.8.8.8")
	local := netip.MustParseAddrPort("10.0.0.2:51000")
	insns := ipv4HostFilter(0, host.As4())

	outbound := ipv4TCP(local, netip.AddrPortFrom(host, 443), []byte("hi"))
	inbound := ipv4TCP(netip.AddrPortFrom(host, 443), local, []byte("hi"))
	elsewhere := ipv4TCP(local, netip.AddrPortFrom(other, 443), []byte("hi"))

	if !accepts(t, insns, outbound) {
		t.Error("outbound TCP to the host must be kept")
	}
	if !accepts(t, insns, inbound) {
		t.Error("inbound TCP from the host must be kept (both directions of the flow)")
	}
	if accepts(t, insns, elsewhere) {
		t.Error("TCP to a different host must be dropped in-kernel")
	}
	if accepts(t, insns, withProto(outbound, 17)) {
		t.Error("UDP to the host must be dropped (TCP-only scope)")
	}
	// An IPv6 packet must not match an IPv4 filter (version nibble guard).
	if accepts(t, insns, ipv6TCP(local6(), netip.MustParseAddrPort("[2606:2800::1]:443"), nil)) {
		t.Error("IPv6 packet must not match an IPv4 filter")
	}
}

func TestFlowFilter_IPv6HostScoped(t *testing.T) {
	host := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")
	other := netip.MustParseAddr("2001:4860:4860::8888")
	insns := ipv6HostFilter(0, host.As16())

	outbound := ipv6TCP(local6(), netip.AddrPortFrom(host, 443), []byte("hi"))
	inbound := ipv6TCP(netip.AddrPortFrom(host, 443), local6(), []byte("hi"))
	elsewhere := ipv6TCP(local6(), netip.AddrPortFrom(other, 443), []byte("hi"))

	if !accepts(t, insns, outbound) {
		t.Error("outbound TCP to the v6 host must be kept")
	}
	if !accepts(t, insns, inbound) {
		t.Error("inbound TCP from the v6 host must be kept")
	}
	if accepts(t, insns, elsewhere) {
		t.Error("TCP to a different v6 host must be dropped")
	}
	// An IPv4 packet must not match an IPv6 filter.
	if accepts(t, insns, ipv4TCP(netip.MustParseAddrPort("10.0.0.2:5"), netip.MustParseAddrPort("1.1.1.1:443"), nil)) {
		t.Error("IPv4 packet must not match an IPv6 filter")
	}
}

// The filter honors a link-layer header offset (Ethernet): the same match holds when the IP packet
// sits behind a 14-byte Ethernet header.
func TestFlowFilter_EthernetOffset(t *testing.T) {
	host := netip.MustParseAddr("93.184.216.34")
	local := netip.MustParseAddrPort("10.0.0.2:51000")
	ip := ipv4TCP(local, netip.AddrPortFrom(host, 443), []byte("hi"))
	eth := append(make([]byte, 14), ip...) // 14-byte link header + IP packet

	if !accepts(t, ipv4HostFilter(14, host.As4()), eth) {
		t.Error("filter must match the IP host behind a 14-byte Ethernet header")
	}
	if accepts(t, ipv4HostFilter(0, host.As4()), eth) {
		t.Error("a zero-offset filter must NOT match an Ethernet-framed packet (sanity: offset matters)")
	}
}

// The real-world case: an IPv6 flow behind a 14-byte Ethernet header (en0). This offset+family
// combination wasn't covered before, and it's exactly the flow that returned no data live.
func TestFlowFilter_IPv6EthernetOffset(t *testing.T) {
	host := netip.MustParseAddr("2607:6bc0::10")
	ip := ipv6TCP(local6(), netip.AddrPortFrom(host, 443), []byte("hi"))
	eth := append(make([]byte, 14), ip...) // 14-byte Ethernet header + IPv6 packet
	if !accepts(t, ipv6HostFilter(14, host.As16()), eth) {
		t.Error("IPv6 filter must match an IPv6 flow behind a 14-byte Ethernet header (the en0 case)")
	}
}

// buildFlowFilter dispatches on the remote's family and assembles without error for both.
func TestBuildFlowFilter_AssemblesBothFamilies(t *testing.T) {
	for _, ap := range []string{"93.184.216.34:443", "[2606:2800::1]:443"} {
		if _, err := buildFlowFilter(14, netip.MustParseAddrPort(ap)); err != nil {
			t.Fatalf("buildFlowFilter(%s): %v", ap, err)
		}
	}
}

func local6() netip.AddrPort { return netip.MustParseAddrPort("[fe80::1]:51000") }

func ipv4UDP(src, dst netip.AddrPort, payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	ip[9] = protoUDP
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	return append(ip, udp...)
}

func ipv6UDP(src, dst netip.AddrPort, payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	udp = append(udp, payload...)
	ip := make([]byte, 40)
	ip[0] = 0x60
	ip[6] = protoUDP
	binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
	s16, d16 := src.Addr().As16(), dst.Addr().As16()
	copy(ip[8:24], s16[:])
	copy(ip[24:40], d16[:])
	return append(ip, udp...)
}

// The port filter is the highest-risk hand-assembled BPF in the tree; this traces every branch:
// UDP/TCP × v4/v6 × src-port/dst-port ACCEPT, and QUIC/ICMP/wrong-offset REJECT.
func TestBuildPortFilter(t *testing.T) {
	dns := func() netip.AddrPort { return netip.MustParseAddrPort("1.2.3.4:53") }
	cli := netip.MustParseAddrPort("10.0.0.9:51000")
	quic := netip.MustParseAddrPort("93.184.216.34:443")
	insns := portFilterInsns(0, 53)

	// ACCEPT: DNS response (src 53), DNS query (dst 53), over UDP and TCP, v4 and v6.
	for _, pkt := range [][]byte{
		ipv4UDP(dns(), cli, []byte("resp")),    // response: src port 53
		ipv4UDP(cli, dns(), []byte("query")),   // query: dst port 53
		ipv4TCP(dns(), cli, []byte("tcp-dns")), // TCP DNS
		ipv6UDP(netip.MustParseAddrPort("[2001:db8::1]:53"), netip.MustParseAddrPort("[2001:db8::2]:51000"), nil),
	} {
		if !accepts(t, insns, pkt) {
			t.Fatalf("port-53 packet must be accepted: % x", pkt[:12])
		}
	}
	// REJECT: QUIC (udp/443 both sides), plain HTTPS (tcp/443), ICMP, and a v6 non-53.
	for _, pkt := range [][]byte{
		ipv4UDP(quic, netip.MustParseAddrPort("10.0.0.9:44300"), nil), // QUIC-shaped, no 53
		ipv4TCP(quic, netip.MustParseAddrPort("10.0.0.9:44300"), nil), // HTTPS
		withProto(ipv4UDP(dns(), cli, nil), 1),                        // ICMP proto, even with port 53 bytes
		ipv6UDP(netip.MustParseAddrPort("[2001:db8::1]:443"), netip.MustParseAddrPort("[2001:db8::2]:44300"), nil),
	} {
		if accepts(t, insns, pkt) {
			t.Fatalf("non-53 packet must be rejected: % x", pkt[:12])
		}
	}
	// Ethernet offset: with L=14 an eth-framed DNS packet accepts; with the wrong L=0 it does not.
	eth := append(make([]byte, 14), ipv4UDP(dns(), cli, nil)...)
	if !accepts(t, portFilterInsns(14, 53), eth) {
		t.Fatal("ethernet-framed DNS must accept with linkHdrLen=14")
	}
	if accepts(t, portFilterInsns(0, 53), eth) {
		t.Fatal("wrong link offset must not accept")
	}
	// The assembled form must be valid.
	if _, err := buildPortFilter(14, 53); err != nil {
		t.Fatalf("buildPortFilter assemble: %v", err)
	}
}

// Audit cp-p1b F-1: exercise the branches the base test skipped and that are most likely to regress
// silently — IPv4 with options (IHL>5, drives LoadMemShift), a non-first fragment (the 0x1fff drop),
// and an IPv6 packet with an extension header (the documented fixed-40-byte REJECT fallthrough).
func TestBuildPortFilter_VariableHeaderAndFragments(t *testing.T) {
	insns := portFilterInsns(0, 53)
	dns := netip.MustParseAddrPort("1.2.3.4:53")
	cli := netip.MustParseAddrPort("10.0.0.9:51000")

	// IPv4 with 4 bytes of options → IHL=6 (24-byte header). Port 53 sits at X=24, which only the
	// LoadMemShift-computed offset finds; a hardcoded 20-offset would read the wrong bytes.
	opt := make([]byte, 24)
	opt[0] = 0x46 // version 4, IHL 6
	opt[9] = protoUDP
	s4, d4 := dns.Addr().As4(), cli.Addr().As4()
	copy(opt[12:16], s4[:])
	copy(opt[16:20], d4[:])
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 53) // src port
	binary.BigEndian.PutUint16(udp[2:], cli.Port())
	if !accepts(t, insns, append(opt, udp...)) {
		t.Fatal("IPv4 with options (IHL>5) + port 53 must be accepted (LoadMemShift offset)")
	}

	// A non-first fragment (fragment offset != 0) carrying port-53 bytes must be dropped — it has no
	// usable transport header, so the userspace parser could never use it anyway.
	frag := ipv4UDP(dns, cli, nil)
	binary.BigEndian.PutUint16(frag[6:], 100) // fragment offset = 100 (non-first)
	if accepts(t, insns, frag) {
		t.Fatal("non-first fragment must be dropped by the 0x1fff test")
	}
	// The corresponding FIRST fragment (offset 0, MF set) must still pass (it has the UDP header).
	first := ipv4UDP(dns, cli, nil)
	binary.BigEndian.PutUint16(first[6:], 0x2000) // MF flag, offset 0
	if !accepts(t, insns, first) {
		t.Fatal("first fragment (MF set, offset 0) must still be accepted")
	}

	// IPv6 with a Hop-by-Hop extension header (next-header=0) before the real transport → REJECT
	// (we deliberately don't walk ext headers; the name is simply missed, never misattributed).
	v6 := ipv6UDP(netip.MustParseAddrPort("[2001:db8::1]:53"), netip.MustParseAddrPort("[2001:db8::2]:51000"), nil)
	v6[6] = 0 // next header = Hop-by-Hop options, not UDP
	if accepts(t, insns, v6) {
		t.Fatal("IPv6 with an extension header must fall through to REJECT (documented gap)")
	}
}
