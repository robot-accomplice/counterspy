//go:build darwin

package inspect

import (
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bpfCapture reads IP packets from a /dev/bpf device bound to an interface. This is the untested
// I/O edge; the record framing + link-layer strip it relies on are pure (stripLinkLayer is
// unit-tested; parseBPFRecords is standard bpf_hdr walking).
type bpfCapture struct {
	fd   int
	dlt  uint32
	buf  []byte
	pend [][]byte
}

// openLiveCapture opens the first free /dev/bpf, binds it to iface in immediate mode, and returns
// a PacketSource of IP-layer packets. Requires root (opening /dev/bpf).
func openLiveCapture(iface string) (PacketSource, error) {
	var fd int
	var err error
	for i := 0; i < 256; i++ {
		fd, err = unix.Open("/dev/bpf"+strconv.Itoa(i), unix.O_RDONLY, 0)
		if err != unix.EBUSY {
			break // opened, or a non-busy error
		}
	}
	if err != nil {
		return nil, err
	}
	blen := 1 << 16
	if err := unix.IoctlSetInt(fd, unix.BIOCSBLEN, blen); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if got, e := unix.IoctlGetInt(fd, unix.BIOCGBLEN); e == nil && got > 0 {
		blen = got
	}
	// Bind the BPF device to the interface via BIOCSETIF (ifreq with the name). x/sys/unix has
	// no darwin helper, so issue the ioctl directly.
	var ifr struct {
		name [16]byte
		_    [16]byte // ifr_ifru union — unused for BIOCSETIF
	}
	copy(ifr.name[:15], iface)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifr))); e != 0 {
		unix.Close(fd)
		return nil, e
	}
	if err := unix.IoctlSetInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		unix.Close(fd)
		return nil, err
	}
	dlt, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &bpfCapture{fd: fd, dlt: uint32(dlt), buf: make([]byte, blen)}, nil
}

func (c *bpfCapture) Next() ([]byte, error) {
	for len(c.pend) == 0 {
		n, err := unix.Read(c.fd, c.buf)
		if err != nil {
			return nil, err
		}
		c.pend = parseBPFRecords(c.buf[:n], c.dlt)
	}
	p := c.pend[0]
	c.pend = c.pend[1:]
	return p, nil
}

func (c *bpfCapture) Close() error { return unix.Close(c.fd) }

// parseBPFRecords walks a BPF read buffer (a sequence of bpf_hdr-prefixed, word-aligned frames),
// strips each frame's link layer, and returns the IP packets.
func parseBPFRecords(buf []byte, dlt uint32) [][]byte {
	var out [][]byte
	for len(buf) >= int(unix.SizeofBpfHdr) {
		h := (*unix.BpfHdr)(unsafe.Pointer(&buf[0]))
		hdrlen, caplen := int(h.Hdrlen), int(h.Caplen)
		if hdrlen < int(unix.SizeofBpfHdr) || caplen < 0 || hdrlen+caplen > len(buf) {
			break
		}
		if ip, ok := stripLinkLayer(dlt, buf[hdrlen:hdrlen+caplen]); ok {
			out = append(out, append([]byte(nil), ip...))
		}
		adv := bpfWordAlign(hdrlen + caplen)
		if adv <= 0 || adv > len(buf) {
			break
		}
		buf = buf[adv:]
	}
	return out
}

func bpfWordAlign(n int) int {
	const a = unix.BPF_ALIGNMENT
	return (n + (a - 1)) &^ (a - 1)
}
