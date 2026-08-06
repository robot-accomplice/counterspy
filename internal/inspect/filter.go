package inspect

import (
	"net/netip"

	"golang.org/x/net/bpf"
)

// retAccept is the BPF "accept" return: keep the whole packet (larger than any frame). retReject
// (0) drops it in-kernel before it is ever copied to userspace.
const retAccept = 0xffffffff

const protoUDP = 17

// buildPortFilter assembles a classic-BPF program keeping only UDP or TCP packets whose src OR dst
// port equals `port`, across IPv4 and IPv6. It scopes the passive DNS capture to port 53 so the
// kernel doesn't copy the whole interface (especially high-volume QUIC on UDP/443) into userspace.
// Unlike buildFlowFilter it can't specialize on address family at build time (the observer sees both
// families on one interface), so it dispatches on the IP version nibble at runtime.
//
// This is a VOLUME cut, not a correctness gate: the observer re-checks the port and parses DNS in
// userspace, so an over-strict filter merely misses some names and an over-loose one merely wastes a
// little CPU; neither can produce a wrong name. IPv6 extension headers are not walked (rare for DNS);
// such packets fall through to REJECT (their names are simply missed).
func buildPortFilter(linkHdrLen, port int) ([]bpf.RawInstruction, error) {
	return bpf.Assemble(portFilterInsns(uint32(linkHdrLen), uint32(port)))
}

// portFilterInsns is the unassembled program (split out so the VM tests can run it directly). Indices
// in the comments are load-bearing for the jump skips: REJECT is idx 23 (and the early idx 4/15),
// ACCEPT is idx 24. Verified branch-by-branch by TestBuildPortFilter.
func portFilterInsns(L, p uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: L, Size: 1},                        // 0: version/IHL byte
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},           // 1: isolate version nibble
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipTrue: 2},  // 2: IPv4 -> v4 block(5)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipTrue: 12}, // 3: IPv6 -> v6 block(16)
		bpf.RetConstant{Val: 0},                                  // 4: neither family -> REJECT
		// --- IPv4 block ---
		bpf.LoadAbsolute{Off: L + 9, Size: 1},                           // 5: protocol
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipTrue: 1},     // 6: UDP -> frag check(8)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoTCP, SkipTrue: 15}, // 7: not TCP -> REJECT(23)
		bpf.LoadAbsolute{Off: L + 6, Size: 2},                           // 8: flags+fragment offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 13},    // 9: non-first fragment -> REJECT(23)
		bpf.LoadMemShift{Off: L},                                        // 10: X = IHL*4 (IPv4 header length)
		bpf.LoadIndirect{Off: L, Size: 2},                               // 11: src port (at X+L)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: p, SkipTrue: 11},           // 12: src==port -> ACCEPT(24)
		bpf.LoadIndirect{Off: L + 2, Size: 2},                           // 13: dst port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: p, SkipTrue: 9},            // 14: dst==port -> ACCEPT(24)
		bpf.RetConstant{Val: 0},                                         // 15: v4, port miss -> REJECT
		// --- IPv6 block (no extension-header walking; fixed 40-byte header) ---
		bpf.LoadAbsolute{Off: L + 6, Size: 1},                          // 16: next header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipTrue: 1},    // 17: UDP -> ports(19)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoTCP, SkipTrue: 4}, // 18: not TCP -> REJECT(23)
		bpf.LoadAbsolute{Off: L + 40, Size: 2},                         // 19: src port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: p, SkipTrue: 3},           // 20: src==port -> ACCEPT(24)
		bpf.LoadAbsolute{Off: L + 42, Size: 2},                         // 21: dst port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: p, SkipTrue: 1},           // 22: dst==port -> ACCEPT(24)
		bpf.RetConstant{Val: 0},                                        // 23: REJECT
		bpf.RetConstant{Val: retAccept},                                // 24: ACCEPT
	}
}

// buildFlowFilter assembles a classic-BPF program that keeps only TCP packets to/from the flow's
// remote host, so the kernel never copies the rest of the interface's traffic into our process
// (spec §6 least-privilege). The program is family-specific; we know the remote's address family
// at build time, so no runtime v4/v6 dispatch is needed. Port precision stays in the (tested)
// userspace Inspect correlation; the kernel filter's job is the coarse, high-volume cut: one host,
// TCP only. linkHdrLen is the datalink header length (Ethernet 14, null 4, raw 0) that the IP
// header sits behind in each captured frame. Pure + VM-testable; the ioctl install is the I/O edge.
func buildFlowFilter(linkHdrLen int, remote netip.AddrPort) ([]bpf.RawInstruction, error) {
	L := uint32(linkHdrLen)
	addr := remote.Addr().Unmap()
	var insns []bpf.Instruction
	if addr.Is4() {
		insns = ipv4HostFilter(L, addr.As4())
	} else {
		insns = ipv6HostFilter(L, addr.As16())
	}
	return bpf.Assemble(insns)
}

// ipv4HostFilter keeps IPv4/TCP packets whose src OR dst address equals host. Layout (indices are
// load-bearing for the jump skips): version+proto guards jump to REJECT; a src/dst match jumps to
// ACCEPT; everything else falls through to REJECT. Verified branch-by-branch by the VM tests.
func ipv4HostFilter(L uint32, host [4]byte) []bpf.Instruction {
	ip := uint32(host[0])<<24 | uint32(host[1])<<16 | uint32(host[2])<<8 | uint32(host[3])
	// 0..8 build to REJECT at idx 9, ACCEPT at idx 10.
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: L, Size: 1},                              // 0: version/IHL byte
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},                 // 1: isolate version nibble
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x40, SkipTrue: 6},     // 2: not IPv4 -> REJECT(9)
		bpf.LoadAbsolute{Off: L + 9, Size: 1},                          // 3: protocol
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoTCP, SkipTrue: 4}, // 4: not TCP -> REJECT(9)
		bpf.LoadAbsolute{Off: L + 12, Size: 4},                         // 5: src IP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip, SkipTrue: 3},          // 6: src==host -> ACCEPT(10)
		bpf.LoadAbsolute{Off: L + 16, Size: 4},                         // 7: dst IP
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip, SkipTrue: 1},          // 8: dst==host -> ACCEPT(10)
		bpf.RetConstant{Val: 0},                                        // 9: REJECT
		bpf.RetConstant{Val: retAccept},                                // 10: ACCEPT
	}
}

// ipv6HostFilter keeps IPv6/TCP packets whose src OR dst 128-bit address equals host. The address
// is compared word-by-word (four 32-bit loads each); any src mismatch jumps to the dst block, any
// dst mismatch jumps to REJECT. Indices are load-bearing; the VM tests cover src-match, dst-match,
// wrong-host, and non-TCP so a bad skip fails a test.
func ipv6HostFilter(L uint32, host [16]byte) []bpf.Instruction {
	w := func(i int) uint32 {
		return uint32(host[i])<<24 | uint32(host[i+1])<<16 | uint32(host[i+2])<<8 | uint32(host[i+3])
	}
	// REJECT is at idx 23, ACCEPT at idx 22, the DST block starts at idx 14.
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: L, Size: 1},                               // 0: version byte
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},                  // 1
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x60, SkipTrue: 20},     // 2: not IPv6 -> REJECT(23)
		bpf.LoadAbsolute{Off: L + 6, Size: 1},                           // 3: next header
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoTCP, SkipTrue: 18}, // 4: not TCP -> REJECT(23)
		bpf.LoadAbsolute{Off: L + 8, Size: 4},                           // 5: src word0
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(0), SkipTrue: 7},      // 6: mismatch -> DST(14)
		bpf.LoadAbsolute{Off: L + 12, Size: 4},                          // 7: src word1
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(4), SkipTrue: 5},      // 8: -> DST(14)
		bpf.LoadAbsolute{Off: L + 16, Size: 4},                          // 9: src word2
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(8), SkipTrue: 3},      // 10: -> DST(14)
		bpf.LoadAbsolute{Off: L + 20, Size: 4},                          // 11: src word3
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(12), SkipTrue: 1},     // 12: -> DST(14); all-match falls to 13
		bpf.Jump{Skip: 8},                                           // 13: src matched -> ACCEPT(22)
		bpf.LoadAbsolute{Off: L + 24, Size: 4},                      // 14: dst word0 (DST block)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(0), SkipTrue: 7},  // 15: -> REJECT(23)
		bpf.LoadAbsolute{Off: L + 28, Size: 4},                      // 16: dst word1
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(4), SkipTrue: 5},  // 17: -> REJECT(23)
		bpf.LoadAbsolute{Off: L + 32, Size: 4},                      // 18: dst word2
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(8), SkipTrue: 3},  // 19: -> REJECT(23)
		bpf.LoadAbsolute{Off: L + 36, Size: 4},                      // 20: dst word3
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: w(12), SkipTrue: 1}, // 21: -> REJECT(23); all-match falls to 22
		bpf.RetConstant{Val: retAccept},                             // 22: ACCEPT
		bpf.RetConstant{Val: 0},                                     // 23: REJECT
	}
}
