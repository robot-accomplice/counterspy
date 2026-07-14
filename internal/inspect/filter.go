package inspect

import (
	"net/netip"

	"golang.org/x/net/bpf"
)

// retAccept is the BPF "accept" return: keep the whole packet (larger than any frame). retReject
// (0) drops it in-kernel before it is ever copied to userspace.
const retAccept = 0xffffffff

// buildFlowFilter assembles a classic-BPF program that keeps only TCP packets to/from the flow's
// remote host, so the kernel never copies the rest of the interface's traffic into our process
// (spec §6 least-privilege). The program is family-specific — we know the remote's address family
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
// dst mismatch jumps to REJECT. Indices are load-bearing — the VM tests cover src-match, dst-match,
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
