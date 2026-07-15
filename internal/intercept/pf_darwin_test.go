//go:build darwin

package intercept

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"unsafe"
)

// stockPfConf approximates the standard macOS /etc/pf.conf ordering: options/scrub/nat/rdr anchors
// (translation), then filter anchors. Our rdr-anchor must land in the translation section.
const stockPfConf = `#
# Default PF configuration file.
#
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
`

// TestInsertRdrAnchor_TranslationSection: the ref goes AFTER the last translation-section line and
// BEFORE the first filter anchor — pf rejects a translation anchor placed after a filter rule (F-3).
func TestInsertRdrAnchor_TranslationSection(t *testing.T) {
	out := insertRdrAnchor(stockPfConf, pfAnchor)
	ref := `rdr-anchor "counterspy"`
	lines := strings.Split(out, "\n")
	refIdx, dummynetIdx, filterAnchorIdx := -1, -1, -1
	for i, ln := range lines {
		switch {
		case strings.TrimSpace(ln) == ref:
			refIdx = i
		case strings.HasPrefix(ln, "dummynet-anchor"):
			dummynetIdx = i
		case strings.HasPrefix(ln, `anchor "com.apple`):
			filterAnchorIdx = i
		}
	}
	if refIdx == -1 {
		t.Fatalf("rdr-anchor ref not inserted:\n%s", out)
	}
	// Inserted after the last translation line (rdr-anchor/dummynet region) and before the filter anchor.
	if refIdx <= dummynetIdx-1 || refIdx > filterAnchorIdx {
		t.Fatalf("ref at %d not in translation section (dummynet=%d, filterAnchor=%d)", refIdx, dummynetIdx, filterAnchorIdx)
	}
	if strings.Count(out, ref) != 1 {
		t.Fatalf("ref must appear exactly once, got %d", strings.Count(out, ref))
	}
}

// TestInsertRdrAnchor_NoTranslation: with no translation lines, the ref goes just before the first
// filter line so ordering is still valid.
func TestInsertRdrAnchor_NoTranslation(t *testing.T) {
	conf := "pass in all\nblock out all\n"
	out := insertRdrAnchor(conf, pfAnchor)
	lines := strings.Split(out, "\n")
	if lines[0] != `rdr-anchor "counterspy"` {
		t.Fatalf("ref should precede the first filter line, got:\n%s", out)
	}
}

// TestRdrRules_BypassFirst: bypass `no rdr` exceptions must precede the catch-all (pf translation is
// first-match).
func TestRdrRules_BypassFirst(t *testing.T) {
	rules := rdrRules(8443, []netip.Addr{netip.MustParseAddr("1.2.3.4")})
	noIdx := strings.Index(rules, "no rdr proto tcp from any to 1.2.3.4 port 443")
	rdrIdx := strings.Index(rules, "rdr pass")
	if noIdx == -1 || rdrIdx == -1 || noIdx > rdrIdx {
		t.Fatalf("bypass must come before the catch-all rdr:\n%s", rules)
	}
	if !strings.Contains(rules, "port 8443") {
		t.Fatalf("proxy port not in rules:\n%s", rules)
	}
}

// pfctlCall records one runPfctl invocation for assertions.
type pfctlCall struct {
	stdin string
	args  []string
}

// withFakePfctl swaps the runPfctl/readPfConf seams and returns the recorded call log + a restore func.
func withFakePfctl(t *testing.T, respond func(args []string) (string, error)) (*[]pfctlCall, func()) {
	t.Helper()
	calls := &[]pfctlCall{}
	origRun, origRead := runPfctl, readPfConf
	runPfctl = func(stdin string, args ...string) (string, error) {
		*calls = append(*calls, pfctlCall{stdin: stdin, args: args})
		return respond(args)
	}
	readPfConf = func() (string, error) { return stockPfConf, nil }
	return calls, func() { runPfctl, readPfConf = origRun, origRead }
}

func hasArg(args []string, a string) bool {
	for _, x := range args {
		if x == a {
			return true
		}
	}
	return false
}

// TestInstallRedirect_EnableFailsLoud: a failed `pfctl -E` must return an error and NO teardown, and
// must unwind steps 1–2 (flush anchor + restore base) — never a false success (Audit/Antagonist F).
func TestInstallRedirect_EnableFailsLoud(t *testing.T) {
	calls, restore := withFakePfctl(t, func(args []string) (string, error) {
		if hasArg(args, "-E") {
			return "", errors.New("pf: not permitted")
		}
		return "", nil
	})
	defer restore()

	teardown, err := InstallRedirect(8443, nil)
	if err == nil || teardown != nil {
		t.Fatalf("enable failure must return (nil, err); got teardown=%v err=%v", teardown != nil, err)
	}
	// Must have attempted an unwind: a flush of our anchor after the -E failure.
	flushed := false
	for _, c := range *calls {
		if hasArg(c.args, "-a") && hasArg(c.args, pfAnchor) && hasArg(c.args, "-F") {
			flushed = true
		}
	}
	if !flushed {
		t.Fatal("must flush the counterspy anchor when unwinding a failed enable")
	}
}

// TestInstallRedirect_UnparseableTokenFailsLoud: `pfctl -E` succeeding but with no parseable Token must
// also fail loud (we can't guarantee a clean `-X` teardown without the token) and unwind.
func TestInstallRedirect_UnparseableTokenFailsLoud(t *testing.T) {
	_, restore := withFakePfctl(t, func(args []string) (string, error) {
		if hasArg(args, "-E") {
			return "pf enabled\n(no token here)\n", nil
		}
		return "", nil
	})
	defer restore()

	teardown, err := InstallRedirect(8443, nil)
	if err == nil || teardown != nil {
		t.Fatalf("unparseable token must fail loud; got teardown=%v err=%v", teardown != nil, err)
	}
}

// TestInstallRedirect_HappyPathTeardownReleasesToken: a clean install returns a teardown that flushes
// the anchor, restores the base ruleset, and releases exactly our token via `-X`.
func TestInstallRedirect_HappyPathTeardownReleasesToken(t *testing.T) {
	calls, restore := withFakePfctl(t, func(args []string) (string, error) {
		if hasArg(args, "-E") {
			return "pf enabled\nToken : 4242424242\n", nil
		}
		return "", nil
	})
	defer restore()

	teardown, err := InstallRedirect(8443, nil)
	if err != nil || teardown == nil {
		t.Fatalf("happy path must return a teardown; got err=%v", err)
	}
	if err := teardown(); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	releasedToken := false
	for _, c := range *calls {
		if hasArg(c.args, "-X") && hasArg(c.args, "4242424242") {
			releasedToken = true
		}
	}
	if !releasedToken {
		t.Fatal("teardown must release the exact -E token via -X")
	}
}

// TestNatlookLayout pins the ioctl contract that a raw DIOCNATLOOK depends on: the struct is 84 bytes
// and the request number is the darwin _IOWR('D',23,84) = 0xc0544417 (verified against xnu pfvar.h).
func TestNatlookLayout(t *testing.T) {
	if got := unsafe.Sizeof(pfiocNatlook{}); got != 84 {
		t.Fatalf("pfioc_natlook must be 84 bytes (xnu), got %d", got)
	}
	if diocNatlook != 0xc0544417 {
		t.Fatalf("DIOCNATLOOK must be 0xc0544417, got %#x", diocNatlook)
	}
}
