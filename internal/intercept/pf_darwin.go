//go:build darwin

package intercept

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ─────────────────────────────────────────────────────────────────────────────
// UNVERIFIED — requires a root smoke test. This file is the pf/ioctl edge: it is
// compile-guarded (darwin-only) and struct-size-guarded, but it CANNOT be unit
// tested (needs root + a live pf). The crypto pump and sinks it feeds are CI-tested
// over loopback; this redirect layer must be exercised by hand. Smoke test:
//
//	sudo counterspy intercept --socket /tmp/cs.sock      # installs trust + rdr, runs proxy
//	# in another shell:
//	curl https://example.com/                            # should appear, decrypted, in:
//	counterspy console --intercept /tmp/cs.sock
//	# Ctrl-C the daemon → verify teardown restored pf:
//	sudo pfctl -a counterspy -s nat                      # empty
//	sudo pfctl -s info                                   # ref count back down
//
// KNOWN CAVEAT (must be resolved during the smoke test): macOS pf `rdr` redirects
// packets arriving INBOUND on an interface. Traffic that ORIGINATES on this host
// (the counter-surveillance target — the user's own outbound TLS) is seen OUTBOUND,
// which rdr does not translate. Redirecting locally-originated flows on macOS
// requires the packets to transit a redirect interface (e.g. routing them via lo0)
// — the interface/direction below is the documented starting point, not a proven
// config. Adjust `rdrRules` against the smoke test before claiming this works.
// ─────────────────────────────────────────────────────────────────────────────

// pfAnchor is the named pf anchor counterspy owns. All our rdr rules live here so teardown is a single
// anchor flush that never touches the user's own ruleset.
const pfAnchor = "counterspy"

// pfctlTimeout bounds each pfctl call so a wedged pf subsystem can't hang install/teardown.
const pfctlTimeout = 15 * time.Second

// runPfctl is the seam over the macOS `pfctl` CLI (mirrors ca.runSecurity), so install/teardown logic is
// testable with a fake that captures args + stdin, without touching the real firewall. Fail loud: the
// tool's diagnostic output is folded into the error (Rule 13/14).
var runPfctl = func(stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfctlTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pfctl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("pfctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// rdrRules builds the anchor's translation ruleset: optional `no rdr` bypass exceptions FIRST (pf
// translation rules are first-match, so exceptions must precede the catch-all), then the rdr that sends
// TCP:443 to the local proxy. See the KNOWN CAVEAT above re: interface/direction.
func rdrRules(proxyPort int, bypass []netip.Addr) string {
	var b strings.Builder
	for _, a := range bypass {
		if a.Is4() { // v6 bypass is handled by the v6 rdr being absent for now (see OrigDest)
			fmt.Fprintf(&b, "no rdr proto tcp from any to %s port 443\n", a)
		}
	}
	// lo0 catches flows we route locally; the plain rule is the general inbound case. Both target the
	// proxy on loopback so the re-dialed upstream (which leaves via the real iface, not rdr'd) can't loop.
	fmt.Fprintf(&b, "rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port %d\n", proxyPort)
	fmt.Fprintf(&b, "rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port %d\n", proxyPort)
	return b.String()
}

var pfTokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// InstallRedirect installs the rdr rule that transparently sends TCP:443 to the local proxy on
// proxyPort, with `bypass` addresses excepted. It returns a teardown that flushes our anchor and
// releases the pf-enable reference — leaving the user's own pf state exactly as it was. Requires root.
//
// It wires our anchor into the main ruleset non-destructively: the current ruleset is re-loaded with our
// `rdr-anchor`/`anchor` references appended, so we never overwrite the user's rules; teardown reloads
// /etc/pf.conf to drop the references. UNVERIFIED — see the file header smoke test.
func InstallRedirect(proxyPort int, bypass []netip.Addr) (func() error, error) {
	// 1) Load our translation rules into our OWN anchor (isolated from the user's ruleset).
	if _, err := runPfctl(rdrRules(proxyPort, bypass), "-a", pfAnchor, "-f", "-"); err != nil {
		return nil, err
	}
	// 2) Reference the anchor from the main ruleset without clobbering it: current rules + our anchor refs.
	current, err := runPfctl("", "-s", "rules")
	if err != nil {
		runPfctl("", "-a", pfAnchor, "-F", "all") // best-effort undo of step 1
		return nil, err
	}
	mainRuleset := current + fmt.Sprintf("\nrdr-anchor \"%s\"\nanchor \"%s\"\n", pfAnchor, pfAnchor)
	if _, err := runPfctl(mainRuleset, "-f", "-"); err != nil {
		runPfctl("", "-a", pfAnchor, "-F", "all")
		return nil, err
	}
	// 3) Enable pf, capturing our reference token so teardown decrements exactly our hold (pfctl -E is
	// reference-counted — a bare `pfctl -d` at teardown would disable pf even if the user had it on).
	token := ""
	if out, err := runPfctl("", "-E"); err == nil {
		if m := pfTokenRe.FindStringSubmatch(out); m != nil {
			token = m[1]
		}
	}
	teardown := func() error {
		var firstErr error
		if _, err := runPfctl("", "-a", pfAnchor, "-F", "all"); err != nil && firstErr == nil {
			firstErr = err
		}
		if _, err := runPfctl("", "-f", "/etc/pf.conf"); err != nil && firstErr == nil {
			firstErr = err
		}
		if token != "" {
			if _, err := runPfctl("", "-X", token); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return teardown, nil
}

// ── DIOCNATLOOK: recover a redirected connection's original destination ───────

// pfAddr / pfXport mirror the darwin C `struct pf_addr` (a 16-byte v4/v6 union) and `union
// pf_state_xport` (4 bytes — it includes a u_int32_t spi member, unlike the 2-byte port union on the
// BSDs; this is the load-bearing macOS layout difference).
type pfAddr [16]byte
type pfXport [4]byte

// pfiocNatlook mirrors darwin's `struct pfioc_natlook` (bsd/net/pfvar.h) EXACTLY, by field layout, for
// the DIOCNATLOOK ioctl. A raw ioctl reads this by memory layout, so a silent size drift would corrupt
// the lookup undetectably — hence the compile-time size guard below.
type pfiocNatlook struct {
	saddr        pfAddr
	daddr        pfAddr
	rsaddr       pfAddr
	rdaddr       pfAddr
	sxport       pfXport
	dxport       pfXport
	rsxport      pfXport
	rdxport      pfXport
	af           uint8
	proto        uint8
	protoVariant uint8
	_            uint8 // pad so `direction` lands on its 4-byte alignment (matches the C struct's padding)
	direction    int32
}

// Compile-time guard: pfioc_natlook is 88 bytes on darwin (4×16 addrs + 4×4 xports + af/proto/variant +
// 1 pad + int32 direction). Non-negative in BOTH directions ONLY when Sizeof == 88.
const _ = unsafe.Sizeof(pfiocNatlook{}) - 88
const _ = 88 - unsafe.Sizeof(pfiocNatlook{})

const (
	pfDirOut = 2 // PF_OUT — the direction convention for a rdr orig-dest lookup

	iocOut   = 0x40000000
	iocIn    = 0x80000000
	iocInOut = iocIn | iocOut
)

// iowr computes a darwin _IOWR ioctl request number. Sizing off unsafe.Sizeof(pfiocNatlook{}) means the
// request number tracks the guarded struct automatically instead of hardcoding a magic 0xC0584417.
func iowr(group byte, num, size uintptr) uintptr {
	return iocInOut | ((size & 0x1fff) << 16) | (uintptr(group) << 8) | num
}

var diocNatlook = iowr('D', 23, unsafe.Sizeof(pfiocNatlook{}))

// OrigDest recovers the pre-redirect destination of a connection the proxy accepted after rdr, by asking
// /dev/pf's state table (DIOCNATLOOK) to reverse the translation. It fills the lookup key from the
// connection's real peer (source) and local (redirected-to) addresses; pf returns the original dest.
// Assignable to Proxy.OrigDest. Requires root. IPv4 only for now — see the deferral note below.
func OrigDest(conn net.Conn) (netip.AddrPort, error) {
	src, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("origdest: parse remote: %w", err)
	}
	dst, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("origdest: parse local: %w", err)
	}
	// IPv6 orig-dest is DEFERRED (Rule 16): it needs the AF_INET6 path (full 16-byte pf_addr + the v6 rdr
	// rule) and doubles the unverified ioctl surface, while IPv4 covers the smoke test. Fail loud, don't
	// silently mis-report a v4 dest for a v6 flow.
	if !src.Addr().Is4() || !dst.Addr().Is4() {
		return netip.AddrPort{}, fmt.Errorf("origdest: IPv6 not yet supported (flow %s → %s)", src, dst)
	}

	fd, err := unix.Open("/dev/pf", unix.O_RDWR, 0)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("origdest: open /dev/pf: %w", err)
	}
	defer unix.Close(fd)

	nl := pfiocNatlook{af: unix.AF_INET, proto: unix.IPPROTO_TCP, direction: pfDirOut}
	sb, db := src.Addr().As4(), dst.Addr().As4()
	copy(nl.saddr[:4], sb[:])
	copy(nl.daddr[:4], db[:])
	binary.BigEndian.PutUint16(nl.sxport[:2], src.Port()) // pf stores ports in network byte order
	binary.BigEndian.PutUint16(nl.dxport[:2], dst.Port())

	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), diocNatlook, uintptr(unsafe.Pointer(&nl))); e != 0 {
		return netip.AddrPort{}, fmt.Errorf("origdest: DIOCNATLOOK: %w", e)
	}
	origIP := netip.AddrFrom4(*(*[4]byte)(nl.rdaddr[:4]))
	origPort := binary.BigEndian.Uint16(nl.rdxport[:2])
	return netip.AddrPortFrom(origIP, origPort), nil
}
