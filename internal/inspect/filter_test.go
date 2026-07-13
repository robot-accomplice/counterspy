package inspect

import (
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
