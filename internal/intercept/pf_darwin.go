//go:build darwin

package intercept

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
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
// over loopback; this redirect layer must be exercised by hand. Smoke test — run
// from the repo root against a FRESH build (counterspy is not installed on PATH by
// default, and `sudo` would not resolve it there anyway; use the ./ path):
//
//	go build -o counterspy .            # Phase 2 is not in any older binary
//	sudo ./counterspy intercept         # consent, install trust + rdr, run the proxy
//	# in a SECOND shell, as your normal user (the daemon hands it the socket):
//	./counterspy console --intercept
//	# in a THIRD shell:
//	curl https://example.com/           # should appear, decrypted, in the console
//	# Ctrl-C the daemon → verify teardown restored pf:
//	sudo pfctl -a counterspy -s nat     # empty
//	sudo pfctl -sr ; sudo pfctl -sn     # user's rules back, no counterspy ref
//	sudo pfctl -s info                  # ref count back down
//
// THINGS THE SMOKE TEST MUST RESOLVE (not provable statically):
//  1. LOCAL-OUTBOUND direction. macOS pf `rdr` translates packets arriving INBOUND
//     on an interface. Traffic that ORIGINATES on this host (the target — the user's
//     own outbound TLS) is seen OUTBOUND, which rdr does not translate. Redirecting
//     locally-originated flows on macOS requires the packets to transit a redirect
//     interface (e.g. routing via lo0). The rules in rdrRules are the documented
//     starting point, NOT a proven config — adjust interface/direction against a real
//     `curl` before trusting this.
//  2. RE-DIAL LOOP. If (1) is solved by redirecting local outbound, the proxy's OWN
//     re-dial to the real server:443 is also local outbound and would be redirected
//     back into the proxy — an infinite loop. The `bypass` list is the current escape
//     hatch (caller passes known upstreams to except); a general fix is excepting the
//     proxy's own uid on the rdr rule if macOS pf honors `user` there. Verify no loop.
//  3. RULESET ORDERING. We insert `rdr-anchor "counterspy"` into the main ruleset in
//     the translation section (pf requires translation rules before filter rules).
//     insertRdrAnchor targets the standard /etc/pf.conf layout; confirm the reload
//     succeeds on your system (`pfctl -f -` errors loudly if ordering is wrong).
//  4. WHERE ~/.counterspy LANDS UNDER SUDO. The daemon resolves its CA (and the
//     default --log path) via os.UserHomeDir(), which depends on whether sudo
//     preserves HOME on this machine — unverified here, since reading the sudoers
//     policy needs root. Either result is self-consistent (intercept is always run
//     under sudo), but confirm which: if it resolves to /var/root/.counterspy the CA
//     is fine, but a default --log would be unreadable to you without sudo. Check
//     with: sudo ./counterspy intercept --yes --log  (then note the printed path).
// ─────────────────────────────────────────────────────────────────────────────

// pfAnchor is the named pf anchor counterspy owns. All our rdr rules live here so teardown is a single
// anchor flush that never touches the user's own ruleset.
const pfAnchor = "counterspy"

// pfConfPath is the authoritative macOS main-ruleset source. We build the active ruleset from THIS file
// (which contains every ruleset class — options, scrub, nat/rdr anchors, filter anchors) rather than
// from `pfctl -s rules`, which prints only the FILTER class and would silently drop the user's
// nat/rdr/scrub/table config on reload (Audit cp-p2e F-1). Assumes the active ruleset was loaded from
// this file (the standard macOS state) — the smoke test confirms restore fidelity.
const pfConfPath = "/etc/pf.conf"

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

// readPfConf is a seam over reading the main ruleset file, so InstallRedirect is testable without root.
var readPfConf = func() (string, error) {
	b, err := os.ReadFile(pfConfPath)
	return string(b), err
}

// rdrRules builds the anchor's translation ruleset: optional `no rdr` bypass exceptions FIRST (pf
// translation rules are first-match, so exceptions must precede the catch-all), then the rdr that sends
// TCP:443 to the local proxy. See the file header caveats re: interface/direction and loop prevention.
func rdrRules(proxyPort int, bypass []netip.Addr) string {
	var b strings.Builder
	for _, a := range bypass {
		if a.Is4() { // v6 bypass is unnecessary while the rdr is inet-only (see OrigDest's v6 deferral)
			fmt.Fprintf(&b, "no rdr proto tcp from any to %s port 443\n", a)
		}
	}
	fmt.Fprintf(&b, "rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port %d\n", proxyPort)
	fmt.Fprintf(&b, "rdr pass inet proto tcp from any to any port 443 -> 127.0.0.1 port %d\n", proxyPort)
	return b.String()
}

// translationLine matches a main-ruleset line that belongs to (or ends) the translation section — the
// last such line is where our rdr-anchor must go (pf enforces: options → scrub → queue → translation →
// filter; a translation anchor placed after a filter rule is rejected on load).
var translationLine = regexp.MustCompile(`^\s*(nat-anchor|rdr-anchor|nat|rdr|scrub-anchor|scrub|dummynet-anchor)\b`)

// firstFilterLine matches the first line of the filter section, the fallback insertion point when the
// ruleset has no translation lines at all (insert immediately BEFORE it).
var firstFilterLine = regexp.MustCompile(`^\s*(anchor|pass|block|match|antispoof)\b`)

// insertRdrAnchor returns pfconf with a single `rdr-anchor "<anchor>"` line inserted in the correct
// translation-section position. Our anchor holds only rdr (translation) rules, so ONLY an rdr-anchor
// reference is needed — no filter `anchor` line (which would add its own ordering constraint). See
// header caveat 3: this targets the standard /etc/pf.conf layout.
func insertRdrAnchor(pfconf, anchor string) string {
	ref := fmt.Sprintf("rdr-anchor \"%s\"", anchor)
	lines := strings.Split(pfconf, "\n")
	insertAt := -1
	for i, ln := range lines {
		if translationLine.MatchString(ln) {
			insertAt = i + 1 // after the last translation line
		}
	}
	if insertAt == -1 { // no translation section — go just before the first filter line
		for i, ln := range lines {
			if firstFilterLine.MatchString(ln) {
				insertAt = i
				break
			}
		}
	}
	if insertAt == -1 { // neither present — append
		insertAt = len(lines)
	}
	out := make([]string, 0, len(lines)+1)
	out = append(out, lines[:insertAt]...)
	out = append(out, ref)
	out = append(out, lines[insertAt:]...)
	return strings.Join(out, "\n")
}

var pfTokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// InstallRedirect installs the rdr rule that transparently sends TCP:443 to the local proxy on
// proxyPort, with `bypass` addresses excepted. It returns a teardown that restores the captured main
// ruleset, flushes our anchor, and releases exactly our pf-enable reference. Requires root.
//
// Non-destructive by construction: the active ruleset is rebuilt from pristine /etc/pf.conf plus one
// inserted rdr-anchor reference, and teardown restores that same captured base — so it never persists
// our reference to disk and never accumulates stale refs across crash-restarts (Audit cp-p2e F-1/F-2/F-5).
// UNVERIFIED — see the file header smoke test.
func InstallRedirect(proxyPort int, bypass []netip.Addr) (func() error, error) {
	base, err := readPfConf()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", pfConfPath, err)
	}
	// 1) Load our translation rules into our OWN anchor (isolated from the user's ruleset).
	if _, err := runPfctl(rdrRules(proxyPort, bypass), "-a", pfAnchor, "-f", "-"); err != nil {
		return nil, err
	}
	// undo unwinds steps completed so far — used on every partial-failure path so pf is never left dirty
	// without a teardown handed back to the caller (Audit cp-p2e F-2 partial-failure window).
	undo := func() {
		runPfctl("", "-a", pfAnchor, "-F", "all")
		runPfctl(base, "-f", "-")
	}
	// 2) Reference the anchor from the main ruleset, inserted in the correct translation position, without
	// dropping any of the user's rules (we start from the complete /etc/pf.conf, not `pfctl -s rules`).
	if _, err := runPfctl(insertRdrAnchor(base, pfAnchor), "-f", "-"); err != nil {
		undo()
		return nil, err
	}
	// 3) Enable pf, capturing our reference token. pfctl -E is reference-counted and returns a token even
	// if pf was already on, so `-E`/`-X token` is the correct symmetric pair regardless of prior state. A
	// failed enable, or an enable whose token we can't parse, is fatal (Rule 13) — we can't guarantee a
	// clean teardown without the token, so unwind and fail loud rather than return a false success
	// (Audit/Antagonist cp-p2e: silent -E failure returning (teardown, nil)).
	out, err := runPfctl("", "-E")
	if err != nil {
		undo()
		return nil, err
	}
	m := pfTokenRe.FindStringSubmatch(out)
	if m == nil {
		runPfctl("", "-X", "0") // best-effort; can't target our ref without the token
		undo()
		return nil, fmt.Errorf("pfctl -E: could not parse enable token from %q", strings.TrimSpace(out))
	}
	token := m[1]
	teardown := func() error {
		var firstErr error
		if _, err := runPfctl("", "-a", pfAnchor, "-F", "all"); err != nil && firstErr == nil {
			firstErr = err
		}
		if _, err := runPfctl(base, "-f", "-"); err != nil && firstErr == nil { // restore the captured base
			firstErr = err
		}
		if _, err := runPfctl("", "-X", token); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
	return teardown, nil
}

// ── DIOCNATLOOK: recover a redirected connection's original destination ───────

// pfAddr / pfXport mirror the darwin C `struct pf_addr` (a 16-byte v4/v6 union) and `union
// pf_state_xport` (4 bytes — it includes a u_int32_t spi member, unlike the 2-byte port union on the
// BSDs; this is the load-bearing macOS layout difference). Verified against xnu bsd/net/pfvar.h.
type pfAddr [16]byte
type pfXport [4]byte

// pfiocNatlook mirrors darwin's `struct pfioc_natlook` (xnu bsd/net/pfvar.h) EXACTLY, by field layout,
// for the DIOCNATLOOK ioctl. A raw ioctl reads this by memory layout, so a silent size drift would
// corrupt the lookup undetectably — hence the compile-time size guard below. NOTE: `direction` is a
// `u_int8_t` in the real struct (NOT an int), so the struct is 84 bytes, not 88 — verified against the
// header, because the size guard alone can only prove internal self-consistency, not that the constant
// is right (Audit cp-p2e F-6).
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
	direction    uint8
}

// Compile-time guard: pfioc_natlook is 84 bytes on darwin (4×16 addrs + 4×4 xports + af/proto/variant +
// u_int8_t direction; struct alignment 4, already a multiple of 4 → no trailing pad). Non-negative in
// BOTH directions ONLY when Sizeof == 84 (a wrong size makes one uintptr const negative → won't compile).
const _ = unsafe.Sizeof(pfiocNatlook{}) - 84
const _ = 84 - unsafe.Sizeof(pfiocNatlook{})

const (
	pfDirOut uint8 = 2 // PF_OUT — the direction convention for a rdr orig-dest lookup

	iocOut   = 0x40000000
	iocIn    = 0x80000000
	iocInOut = iocIn | iocOut
)

// iowr computes a darwin _IOWR ioctl request number. Sizing off unsafe.Sizeof(pfiocNatlook{}) means the
// request number tracks the guarded struct automatically (→ 0xc0544417 for the 84-byte struct) instead
// of hardcoding a magic that could silently disagree with the struct.
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
	// IPv6 orig-dest is DEFERRED (Rule 16): it needs the AF_INET6 path (full 16-byte pf_addr + a v6 rdr
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
