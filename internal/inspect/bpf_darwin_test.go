//go:build darwin

package inspect

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bpfRecord frames one captured frame as the kernel would: a bpf_hdr (Hdrlen/Caplen set) followed
// by the frame bytes, padded to the next BPF_ALIGNMENT boundary. Layout-agnostic; it writes the
// real unix.BpfHdr so the test doesn't hardcode darwin offsets.
func bpfRecord(frame []byte) []byte {
	hdrlen := int(unix.SizeofBpfHdr)
	buf := make([]byte, bpfWordAlign(hdrlen+len(frame)))
	h := (*unix.BpfHdr)(unsafe.Pointer(&buf[0]))
	h.Hdrlen = uint16(hdrlen)
	h.Caplen = uint32(len(frame))
	h.Datalen = uint32(len(frame))
	copy(buf[hdrlen:], frame)
	return buf
}

// bpfRecordHdrlen frames a record with an explicit bh_hdrlen (the data offset), mirroring how
// macOS varies it per datalink to align the payload: 18 for Ethernet, not the struct's padded 20.
func bpfRecordHdrlen(frame []byte, hdrlen int) []byte {
	buf := make([]byte, bpfWordAlign(hdrlen+len(frame)))
	h := (*unix.BpfHdr)(unsafe.Pointer(&buf[0]))
	h.Hdrlen = uint16(hdrlen)
	h.Caplen = uint32(len(frame))
	h.Datalen = uint32(len(frame))
	copy(buf[hdrlen:], frame)
	return buf
}

// macOS writes bh_hdrlen=18 for Ethernet (payload-aligned), which is LESS than SizeofBpfHdr (20).
// The walk must accept it, not reject it as "too small": the live-capture EFAULT-free-but-empty bug.
func TestParseBPFRecords_EthernetHdrlen18(t *testing.T) {
	ip := ipv4TCP(netip.MustParseAddrPort("10.0.0.2:5"), netip.MustParseAddrPort("3.3.3.3:443"), []byte("x"))
	buf := bpfRecordHdrlen(ethFrame(0x0800, ip), 18) // en0's real header length

	got := parseBPFRecords(buf, dltEN10MB)
	if len(got) != 1 || !bytes.Equal(got[0], ip) {
		t.Fatalf("a record with bh_hdrlen=18 must parse, got %d packets", len(got))
	}
}

func ethFrame(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14)
	binary.BigEndian.PutUint16(f[12:14], etherType)
	return append(f, payload...)
}

// A well-formed multi-record buffer (raw IP) yields each IP packet in order, word-alignment honored.
func TestParseBPFRecords_MultiRecordRawIP(t *testing.T) {
	local := netip.MustParseAddrPort("10.0.0.2:51000")
	p1 := ipv4TCP(local, netip.MustParseAddrPort("1.1.1.1:443"), []byte("one"))
	p2 := ipv4TCP(local, netip.MustParseAddrPort("2.2.2.2:80"), []byte("two"))
	buf := append(bpfRecord(p1), bpfRecord(p2)...)

	got := parseBPFRecords(buf, dltRaw)
	if len(got) != 2 || !bytes.Equal(got[0], p1) || !bytes.Equal(got[1], p2) {
		t.Fatalf("want 2 IP packets in order, got %d", len(got))
	}
}

// The Ethernet link header is stripped; a non-IP frame (ARP) in the same buffer is dropped, not fatal.
func TestParseBPFRecords_EthernetStripAndDropNonIP(t *testing.T) {
	ip := ipv4TCP(netip.MustParseAddrPort("10.0.0.2:5"), netip.MustParseAddrPort("3.3.3.3:443"), []byte("x"))
	buf := append(bpfRecord(ethFrame(0x0800, ip)), bpfRecord(ethFrame(0x0806, []byte("arp")))...)

	got := parseBPFRecords(buf, dltEN10MB)
	if len(got) != 1 || !bytes.Equal(got[0], ip) {
		t.Fatalf("want the IP packet only (ARP dropped), got %d packets", len(got))
	}
}

// Hostile header fields must terminate the walk safely: no panic, no over-read.
func TestParseBPFRecords_HostileHeadersDontPanic(t *testing.T) {
	hdrlen := int(unix.SizeofBpfHdr)

	// Hdrlen smaller than the header's own fields (below minBpfHdr) → must break immediately, so
	// the header bytes can't be mistaken for frame data.
	tooSmall := make([]byte, hdrlen+8)
	(*unix.BpfHdr)(unsafe.Pointer(&tooSmall[0])).Hdrlen = uint16(minBpfHdr - 1)
	if got := parseBPFRecords(tooSmall, dltRaw); len(got) != 0 {
		t.Fatalf("under-size Hdrlen must yield nothing, got %d", len(got))
	}

	// Caplen claiming more than the buffer holds → must break, not over-read.
	overrun := make([]byte, hdrlen+4)
	h := (*unix.BpfHdr)(unsafe.Pointer(&overrun[0]))
	h.Hdrlen = uint16(hdrlen)
	h.Caplen = 1 << 20
	if got := parseBPFRecords(overrun, dltRaw); len(got) != 0 {
		t.Fatalf("overrun Caplen must yield nothing, got %d", len(got))
	}

	// A buffer shorter than a header → loop never enters.
	if got := parseBPFRecords(make([]byte, hdrlen-1), dltRaw); len(got) != 0 {
		t.Fatalf("sub-header buffer must yield nothing, got %d", len(got))
	}
}
