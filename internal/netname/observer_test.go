package netname

import (
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// fakeSource replays a fixed list of IP-layer packets then returns io.EOF, standing in for the live
// /dev/bpf capture so the observer is testable without root.
type fakeSource struct {
	pkts   [][]byte
	i      int
	closed bool
}

func (f *fakeSource) Next() ([]byte, error) {
	if f.i >= len(f.pkts) {
		return nil, io.EOF
	}
	p := f.pkts[f.i]
	f.i++
	return p, nil
}
func (f *fakeSource) Close() error { f.closed = true; return nil }

// ipv4UDPPacket wraps a UDP payload in IPv4 + UDP headers (no link header — the capture strips it).
func ipv4UDPPacket(srcPort, dstPort int, payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	ip[9] = protoUDP
	copy(ip[12:16], []byte{10, 0, 0, 9})
	copy(ip[16:20], []byte{1, 1, 1, 1})
	return append(ip, udp...)
}

func TestObserver_CachesNamesFromDNSResponses(t *testing.T) {
	resp := dnsMsg("api.example.com", true, aRec([4]byte{93, 184, 216, 34}))
	src := &fakeSource{pkts: [][]byte{
		ipv4UDPPacket(53, 51000, resp),                                              // a real DNS response (src 53) → cached
		ipv4UDPPacket(51000, 53, dnsMsg("q.com", false, aRec([4]byte{1, 2, 3, 4}))), // a QUERY (dst 53) → ignored
		ipv4UDPPacket(443, 44300, []byte("quic")),                                   // non-DNS UDP → ignored
		{0x45, 0x00}, // truncated garbage → ignored, no panic
	}}
	o := NewObserver(NewCache(16), src)
	o.Run() // drains to EOF

	if n, ok := o.cache.Lookup("93.184.216.34"); !ok || n != "api.example.com" {
		t.Fatalf("DNS response should have been cached: %q ok=%v", n, ok)
	}
	if _, ok := o.cache.Lookup("1.2.3.4"); ok {
		t.Fatal("a query (dst port 53), not a response, must NOT be cached")
	}
}

func TestObserver_CloseStopsAndClosesSource(t *testing.T) {
	src := &fakeSource{}
	o := NewObserver(NewCache(4), src)
	if err := o.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !src.closed {
		t.Fatal("Close must close the underlying source")
	}
}

func TestUDPPayload(t *testing.T) {
	// IPv4 UDP: ports + payload extracted.
	pkt := ipv4UDPPacket(53, 51000, []byte("dns"))
	pl, sp, dp, ok := udpPayload(pkt)
	if !ok || sp != 53 || dp != 51000 || string(pl) != "dns" {
		t.Fatalf("v4 udp: pl=%q sp=%d dp=%d ok=%v", pl, sp, dp, ok)
	}
	// IPv4 with options (IHL=6): the payload offset must follow the real header length.
	opt := make([]byte, 24)
	opt[0] = 0x46 // IHL 6
	opt[9] = protoUDP
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 53)
	pl, sp, _, ok = udpPayload(append(append(opt, udp...), []byte("x")...))
	if !ok || sp != 53 || string(pl) != "x" {
		t.Fatalf("v4+options: pl=%q sp=%d ok=%v", pl, sp, ok)
	}
	// IPv6 UDP.
	v6 := make([]byte, 40)
	v6[0] = 0x60
	v6[6] = protoUDP
	v6 = append(v6, udp...)
	if _, sp, _, ok := udpPayload(v6); !ok || sp != 53 {
		t.Fatalf("v6 udp: sp=%d ok=%v", sp, ok)
	}
	// Rejects: non-UDP proto, non-first fragment, truncated, unknown version.
	tcp := ipv4UDPPacket(53, 1, nil)
	tcp[9] = protoTCP4
	if _, _, _, ok := udpPayload(tcp); ok {
		t.Fatal("TCP must be rejected by udpPayload (UDP DNS only)")
	}
	frag := ipv4UDPPacket(53, 1, nil)
	binary.BigEndian.PutUint16(frag[6:], 100) // non-first fragment
	if _, _, _, ok := udpPayload(frag); ok {
		t.Fatal("non-first fragment must be rejected")
	}
	if _, _, _, ok := udpPayload([]byte{0x45, 0, 0}); ok {
		t.Fatal("truncated packet must be rejected")
	}
	if _, _, _, ok := udpPayload([]byte{0x50}); ok {
		t.Fatal("unknown IP version must be rejected")
	}
}

const protoTCP4 = 6

// Antagonist cp-p1c F-1: a source that yields (nil, nil) forever must NOT spin the goroutine — Run
// returns instead. Audit cp-p1c F-3: Run surfaces the terminating error.
func TestObserver_NilPacketDoesNotSpin(t *testing.T) {
	spin := &nilSource{}
	o := NewObserver(NewCache(4), spin)
	done := make(chan error, 1)
	go func() { done <- o.Run() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run should return a non-nil (io.EOF) reason for stopping")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run spun on a (nil,nil) source instead of returning")
	}
	if spin.calls > 3 {
		t.Fatalf("Run must stop after the first empty read, not loop (%d calls)", spin.calls)
	}
}

// nilSource always returns (nil, nil) — the contract-violating source the guard defends against.
type nilSource struct{ calls int }

func (n *nilSource) Next() ([]byte, error) { n.calls++; return nil, nil }
func (n *nilSource) Close() error          { return nil }
