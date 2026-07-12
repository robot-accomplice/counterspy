//go:build darwin

package inspect

import (
	"io"
	"net/netip"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifreq mirrors the darwin C `struct ifreq` (a 16-byte interface name followed by a 16-byte
// ifr_ifru union) as passed to the BIOCSETIF ioctl. Only the name is set here.
type ifreq struct {
	name [16]byte
	_    [16]byte // ifr_ifru union — unused for BIOCSETIF
}

// Compile-time guard: a raw ioctl reads the kernel struct by layout, so a silent size/layout drift
// would corrupt BIOCSETIF undetectably. Both constants are non-negative ONLY when Sizeof == 32.
const _ = unsafe.Sizeof(ifreq{}) - 32
const _ = 32 - unsafe.Sizeof(ifreq{})

// readPoll is how long Next sleeps between empty (EAGAIN) non-blocking reads, so an idle flow
// polls its wall-clock deadline cheaply instead of busy-spinning or blocking forever (T-11).
const readPoll = 20 * time.Millisecond

// bpfCapture reads IP packets from a /dev/bpf device bound to an interface. This is the untested
// I/O edge; the record framing + link-layer strip + BPF filter it relies on are pure (stripLinkLayer
// and buildFlowFilter are unit/VM-tested; parseBPFRecords is standard bpf_hdr walking).
type bpfCapture struct {
	fd       int
	dlt      uint32
	buf      []byte
	pend     [][]byte
	deadline time.Time // zero = no wall-clock bound
}

// OpenLiveCapture opens the first free /dev/bpf, binds it to iface in immediate mode, installs a
// kernel BPF filter scoped to the flow's remote host (so the whole interface is NOT copied to
// userspace — spec §6 least-privilege), and returns a PacketSource of IP-layer packets. maxWait
// bounds the total capture window so an idle flow can't hang the caller. Requires root (/dev/bpf).
func OpenLiveCapture(iface string, remote netip.AddrPort, maxWait time.Duration) (PacketSource, error) {
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
	var ifr ifreq
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
	// Make the fd non-blocking so a read on a silent flow returns EAGAIN immediately instead of
	// blocking forever — this is what GUARANTEES the maxWait deadline is honored (T-11). It must
	// succeed (unlike the best-effort filter), so a failure fails the capture loudly rather than
	// risking a hung UI loop.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Scope the capture to the remote host in-kernel. Best-effort: if the datalink is one we have
	// no header-length for, or the filter can't be installed, we fall back to whole-interface
	// capture (the userspace correlation in Inspect still yields the correct flow) rather than
	// installing a filter that might silently drop everything — capture correctness over privacy.
	installFlowFilter(fd, uint32(dlt), remote)

	c := &bpfCapture{fd: fd, dlt: uint32(dlt), buf: make([]byte, blen)}
	if maxWait > 0 {
		c.deadline = time.Now().Add(maxWait)
	}
	return c, nil
}

// installFlowFilter assembles and installs (BIOCSETF) a host-scoped TCP filter. Best-effort: on an
// unknown datalink or an assembly/ioctl error it returns without installing, leaving the capture
// unfiltered (never blinded).
func installFlowFilter(fd int, dlt uint32, remote netip.AddrPort) {
	hdr, ok := linkHdrLen(dlt)
	if !ok {
		return
	}
	raw, err := buildFlowFilter(hdr, remote)
	if err != nil || len(raw) == 0 {
		return
	}
	insns := make([]unix.BpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = unix.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETF), uintptr(unsafe.Pointer(&prog)))
}

// linkHdrLen maps a datalink type to the byte length of its link header (the offset the IP packet
// sits behind), for the BPF filter's absolute loads. ok=false for datalinks we don't filter.
func linkHdrLen(dlt uint32) (int, bool) {
	switch dlt {
	case dltEN10MB:
		return 14, true
	case dltNull:
		return 4, true
	case dltRaw:
		return 0, true
	default:
		return 0, false
	}
}

func (c *bpfCapture) Next() ([]byte, error) {
	for len(c.pend) == 0 {
		if !c.deadline.IsZero() && time.Now().After(c.deadline) {
			return nil, io.EOF // capture window elapsed — a clean end, not a failure
		}
		n, err := unix.Read(c.fd, c.buf)
		if err != nil {
			if err == unix.EAGAIN { // no packets buffered — sleep briefly, then re-check the deadline
				time.Sleep(readPoll)
				continue
			}
			if err == unix.EINTR {
				continue
			}
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
