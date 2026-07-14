package inspect

import (
	"errors"
	"io"
	"testing"
)

func TestStripLinkLayer(t *testing.T) {
	ip := []byte{0x45, 0, 0, 0} // a stand-in IP packet (version nibble 4)
	// Ethernet frame: 12 bytes MAC + ethertype 0x0800 + IP
	eth := append(make([]byte, 12), 0x08, 0x00)
	eth = append(eth, ip...)
	if got, ok := stripLinkLayer(dltEN10MB, eth); !ok || string(got) != string(ip) {
		t.Fatalf("ethernet strip: ok=%v got=%v", ok, got)
	}
	// Null/loopback: 4-byte AF header + IP
	nullf := append([]byte{2, 0, 0, 0}, ip...)
	if got, ok := stripLinkLayer(dltNull, nullf); !ok || string(got) != string(ip) {
		t.Fatalf("null strip: ok=%v got=%v", ok, got)
	}
	// Raw IP: unchanged
	if got, ok := stripLinkLayer(dltRaw, ip); !ok || string(got) != string(ip) {
		t.Fatalf("raw: ok=%v got=%v", ok, got)
	}
	// Non-IP ethertype (ARP 0x0806) and too-short frames are rejected.
	arp := append(make([]byte, 12), 0x08, 0x06)
	if _, ok := stripLinkLayer(dltEN10MB, arp); ok {
		t.Fatal("ARP ethertype should be rejected")
	}
	if _, ok := stripLinkLayer(dltEN10MB, []byte{1, 2, 3}); ok {
		t.Fatal("too-short ethernet frame should be rejected")
	}
	if _, ok := stripLinkLayer(99, ip); ok {
		t.Fatal("unknown DLT should be rejected")
	}
}

func TestFixtureSource(t *testing.T) {
	fs := &fixtureSource{packets: [][]byte{{1}, {2}}}
	a, _ := fs.Next()
	b, _ := fs.Next()
	_, err := fs.Next()
	if len(a) != 1 || a[0] != 1 || b[0] != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("fixtureSource replay wrong: %v %v %v", a, b, err)
	}
}
