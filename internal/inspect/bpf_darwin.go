//go:build darwin

package inspect

import (
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
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
	deadline time.Time   // zero = no wall-clock bound
	closed   atomic.Bool // set by Close() so a concurrent Next() ends via a clean io.EOF (T-16)
}

// openBPF opens the first free /dev/bpf, binds it to iface in immediate + non-blocking mode, and
// returns the fd, its datalink type, and the kernel buffer length. Shared by OpenLiveCapture (flow-
// scoped, bounded) and OpenPortCapture (port-scoped, long-lived) so both use one battle-tested open
// sequence. Requires root (/dev/bpf). Each step names itself so a failure localizes the exact ioctl
// + interface (RCA): a bare errno like EFAULT is otherwise ambiguous across six syscalls.
// BIOCSBLEN/BIOCIMMEDIATE are _IOWR/_IOW over a u_int — the kernel reads the value THROUGH a pointer,
// so they need IoctlSetPointerInt (IoctlSetInt would pass by value → EFAULT). Non-blocking is what
// GUARANTEES a silent flow returns EAGAIN instead of hanging (T-11).
func openBPF(iface string) (fd int, dlt uint32, blen int, err error) {
	for i := 0; i < 256; i++ {
		fd, err = unix.Open("/dev/bpf"+strconv.Itoa(i), unix.O_RDONLY, 0)
		if err != unix.EBUSY {
			break
		}
	}
	if err != nil {
		return 0, 0, 0, fmt.Errorf("open /dev/bpf: %w", err)
	}
	blen = 1 << 16
	if err = unix.IoctlSetPointerInt(fd, unix.BIOCSBLEN, blen); err != nil {
		unix.Close(fd)
		return 0, 0, 0, fmt.Errorf("bpf %s BIOCSBLEN: %w", iface, err)
	}
	if got, e := unix.IoctlGetInt(fd, unix.BIOCGBLEN); e == nil && got > 0 {
		blen = got
	}
	var ifr ifreq
	copy(ifr.name[:15], iface)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifr))); e != 0 {
		unix.Close(fd)
		return 0, 0, 0, fmt.Errorf("bpf %s BIOCSETIF: %w", iface, e)
	}
	if err = unix.IoctlSetPointerInt(fd, unix.BIOCIMMEDIATE, 1); err != nil {
		unix.Close(fd)
		return 0, 0, 0, fmt.Errorf("bpf %s BIOCIMMEDIATE: %w", iface, err)
	}
	d, err := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	if err != nil {
		unix.Close(fd)
		return 0, 0, 0, fmt.Errorf("bpf %s BIOCGDLT: %w", iface, err)
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return 0, 0, 0, fmt.Errorf("bpf %s set-nonblock: %w", iface, err)
	}
	return fd, uint32(d), blen, nil
}

// OpenLiveCapture opens a /dev/bpf capture on iface scoped to the flow's remote host (so the whole
// interface is NOT copied to userspace — spec §6 least-privilege) and returns a PacketSource of
// IP-layer packets. maxWait bounds the total capture window so an idle flow can't hang the caller.
// Requires root. The flow filter is best-effort: on an unknown datalink or install error the capture
// falls back to whole-interface (userspace Inspect correlation still yields the flow), never blinded.
func OpenLiveCapture(iface string, remote netip.AddrPort, maxWait time.Duration) (PacketSource, error) {
	fd, dlt, blen, err := openBPF(iface)
	if err != nil {
		return nil, err
	}
	installFlowFilter(fd, dlt, remote)
	c := &bpfCapture{fd: fd, dlt: dlt, buf: make([]byte, blen)}
	if maxWait > 0 {
		c.deadline = time.Now().Add(maxWait)
	}
	return c, nil
}

// OpenPortCapture opens a LONG-LIVED (no deadline) capture on iface scoped to UDP/TCP `port` — 53 for
// the passive DNS observer — so the kernel drops the rest of the interface (esp. high-volume QUIC)
// before userspace. Requires root. The caller runs Next() in a loop and Close()s to stop it (#3).
func OpenPortCapture(iface string, port int) (PacketSource, error) {
	fd, dlt, blen, err := openBPF(iface)
	if err != nil {
		return nil, err
	}
	installPortFilter(fd, dlt, port)
	return &bpfCapture{fd: fd, dlt: dlt, buf: make([]byte, blen)}, nil
}

// installFlowFilter assembles and installs (BIOCSETF) a host-scoped TCP filter. Best-effort: on an
// unknown datalink or an assembly error it returns without installing, leaving the capture unfiltered
// (never blinded).
func installFlowFilter(fd int, dlt uint32, remote netip.AddrPort) {
	hdr, ok := linkHdrLen(dlt)
	if !ok {
		return
	}
	if raw, err := buildFlowFilter(hdr, remote); err == nil {
		installFilter(fd, raw)
	}
}

// installPortFilter assembles and installs (BIOCSETF) a UDP/TCP port filter for the passive DNS
// capture. Same best-effort contract as installFlowFilter — an unfiltered fallback is safe here too
// (the observer re-checks the port + parses DNS in userspace).
func installPortFilter(fd int, dlt uint32, port int) {
	hdr, ok := linkHdrLen(dlt)
	if !ok {
		return
	}
	if raw, err := buildPortFilter(hdr, port); err == nil {
		installFilter(fd, raw)
	}
}

// installFilter copies an assembled cBPF program into kernel form and installs it via BIOCSETF.
func installFilter(fd int, raw []bpf.RawInstruction) {
	if len(raw) == 0 {
		return
	}
	insns := make([]unix.BpfInsn, len(raw))
	for i, r := range raw {
		insns[i] = unix.BpfInsn{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	prog := unix.BpfProgram{Len: uint32(len(insns)), Insns: &insns[0]}
	unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETF), uintptr(unsafe.Pointer(&prog)))
	// prog.Insns points into insns, but the syscall machinery only keeps &prog alive — pin insns
	// across the call so the GC can't reclaim the instruction buffer mid-copyin (T-13).
	runtime.KeepAlive(insns)
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
		if c.closed.Load() {
			return nil, io.EOF // Close() was called (T-16) — end cleanly, not as a read failure
		}
		if !c.deadline.IsZero() && time.Now().After(c.deadline) {
			return nil, io.EOF // capture window elapsed — a clean end, not a failure
		}
		n, err := unix.Read(c.fd, c.buf)
		if err != nil {
			// A read that RACED a concurrent Close() (e.g. the long-lived observer's Close on another
			// goroutine) errors on the now-closed fd; since we asked to close, report a clean io.EOF
			// rather than a scary "bpf read: bad file descriptor" (T-16 / Observer.Close).
			if c.closed.Load() {
				return nil, io.EOF
			}
			if err == unix.EAGAIN { // no packets buffered — sleep briefly, then re-check
				time.Sleep(readPoll)
				continue
			}
			if err == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("bpf read: %w", err) // localizes a read failure vs a setup ioctl
		}
		c.pend = parseBPFRecords(c.buf[:n], c.dlt)
	}
	p := c.pend[0]
	c.pend = c.pend[1:]
	return p, nil
}

// Close marks the capture closed (so a concurrent Next() ends via a clean io.EOF, T-16) and closes
// the fd. Safe to call from a different goroutine than Next() — the atomic flag turns the resulting
// close-during-read into a clean stop.
func (c *bpfCapture) Close() error {
	c.closed.Store(true)
	return unix.Close(c.fd)
}

// parseBPFRecords walks a BPF read buffer (a sequence of bpf_hdr-prefixed, word-aligned frames),
// strips each frame's link layer, and returns the IP packets plus the total record count walked
// (records >= len(out); the gap is frames stripLinkLayer rejected — a link-layer/DLT mismatch).
// minBpfHdr is the smallest valid bh_hdrlen: the offset just past the last header field we read.
// The kernel sets bh_hdrlen to the payload offset, which it varies per datalink to align the frame
// and can be SMALLER than SizeofBpfHdr (that includes trailing struct padding) — macOS writes 18
// for Ethernet, 20 for loopback. Guarding against SizeofBpfHdr wrongly rejected every Ethernet
// record (read succeeds, zero frames parsed); guard against this field-end minimum instead.
const minBpfHdr = int(unsafe.Offsetof(unix.BpfHdr{}.Hdrlen)) + 2

func parseBPFRecords(buf []byte, dlt uint32) [][]byte {
	var out [][]byte
	for len(buf) >= minBpfHdr {
		h := (*unix.BpfHdr)(unsafe.Pointer(&buf[0]))
		hdrlen, caplen := int(h.Hdrlen), int(h.Caplen)
		if hdrlen < minBpfHdr || caplen < 0 || hdrlen+caplen > len(buf) {
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
