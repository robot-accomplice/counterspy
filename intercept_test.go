package main

import (
	"bytes"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"counterspy/internal/intercept"
	"counterspy/internal/intercept/ca"
	"counterspy/internal/intercept/publish"
	"counterspy/internal/model"
)

// recSink records its Close into the shared ordering log.
type recSink struct{ log *[]string }

func (r recSink) Publish(model.InterceptedMessage) error { return nil }
func (r recSink) Close() error                           { *r.log = append(*r.log, "sink-close"); return nil }

// fakeIntercept swaps every intercept seam with a recorder writing into `log`, and restores on cleanup.
// serveHook lets a test drive the serve phase (return, error, or panic).
func fakeIntercept(t *testing.T, log *[]string, serveHook func()) {
	t.Helper()
	caObj, err := ca.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	origLoad := interceptCALoadOrCreate
	origCALoad := interceptCALoad
	origTrust := interceptInstallTrust
	origUntrust := interceptUninstallTrust
	origRedir := interceptInstallProxy
	origSock := interceptNewSocketSink
	origLog := interceptNewLogSink
	origServe := interceptServe
	origStdin := interceptStdin
	origHome := interceptUserHomeDir
	origChown := interceptChownSocket
	t.Cleanup(func() {
		interceptCALoadOrCreate = origLoad
		interceptCALoad = origCALoad
		interceptInstallTrust = origTrust
		interceptUninstallTrust = origUntrust
		interceptInstallProxy = origRedir
		interceptNewSocketSink = origSock
		interceptNewLogSink = origLog
		interceptServe = origServe
		interceptStdin = origStdin
		interceptUserHomeDir = origHome
		interceptChownSocket = origChown
	})

	interceptUserHomeDir = func() (string, error) { return t.TempDir(), nil }
	interceptChownSocket = func(string) error { return nil }
	interceptCALoadOrCreate = func(string) (*ca.CA, error) { return caObj, nil }
	interceptCALoad = func(string) (*ca.CA, bool, error) { return caObj, true, nil }
	interceptInstallTrust = func([]byte) error { *log = append(*log, "trust-install"); return nil }
	interceptUninstallTrust = func([]byte) error { *log = append(*log, "trust-uninstall"); return nil }
	interceptInstallProxy = func(int) (func() error, error) {
		*log = append(*log, "proxy-install")
		return func() error { *log = append(*log, "proxy-teardown"); return nil }, nil
	}
	interceptNewSocketSink = func(path string) (publish.Sink, error) {
		*log = append(*log, "sink-open:"+path)
		return recSink{log: log}, nil
	}
	interceptNewLogSink = func(path string) (publish.Sink, error) {
		*log = append(*log, "log-open:"+path)
		return recSink{log: log}, nil
	}
	interceptServe = func(_ *intercept.Proxy, _ net.Listener) error {
		*log = append(*log, "serve")
		if serveHook != nil {
			serveHook()
		}
		return nil
	}
	// listen must not bind a real port in tests.
	origListen := interceptListen
	interceptListen = func() (net.Listener, error) { return fakeListener{}, nil }
	t.Cleanup(func() { interceptListen = origListen })
}

type fakeListener struct{}

func (fakeListener) Accept() (net.Conn, error) { return nil, errors.New("closed") }
func (fakeListener) Close() error              { return nil }
func (fakeListener) Addr() net.Addr            { return &net.TCPAddr{} }

func idx(log []string, s string) int {
	for i, x := range log {
		if x == s {
			return i
		}
	}
	return -1
}

// (b) A normal run installs trust THEN the redirect THEN serves; teardown reverts in reverse order.
func TestIntercept_ArmThenServeThenReverse(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	if code := runIntercept([]string{"--yes"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("code=%d", code)
	}
	order := []string{"trust-install", "proxy-install", "serve", "proxy-teardown", "trust-uninstall"}
	last := -1
	for _, step := range order {
		i := idx(log, step)
		if i == -1 {
			t.Fatalf("missing %q in %v", step, log)
		}
		if i < last {
			t.Fatalf("step %q out of order in %v", step, log)
		}
		last = i
	}
}

// (b) A mid-run panic still disarms in the right order and exits non-zero.
func TestIntercept_PanicStillDisarms(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, func() { panic("boom") })
	code := runIntercept([]string{"--yes"}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("panic path must return 1, got %d", code)
	}
	if idx(log, "proxy-teardown") == -1 || idx(log, "trust-uninstall") == -1 {
		t.Fatalf("teardown must run on panic: %v", log)
	}
	if idx(log, "proxy-teardown") > idx(log, "trust-uninstall") {
		t.Fatalf("redirect must revert before trust: %v", log)
	}
}

// (c) With neither --stream nor --log, it defaults to the live socket at the short default path.
func TestIntercept_DefaultsToStream(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	runIntercept([]string{"--yes"}, &bytes.Buffer{})
	if idx(log, "sink-open:"+interceptSocketPath) == -1 {
		t.Fatalf("default output must be the stream socket at %s: %v", interceptSocketPath, log)
	}
}

// (c') --log alone opens only the log sink (no default stream when an output was explicitly chosen).
func TestIntercept_LogOnlyNoStream(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	runIntercept([]string{"--yes", "--log=/tmp/cs-flows.jsonl"}, &bytes.Buffer{})
	if idx(log, "log-open:/tmp/cs-flows.jsonl") == -1 {
		t.Fatalf("--log should open the log sink: %v", log)
	}
	for _, e := range log {
		if strings.HasPrefix(e, "sink-open:") {
			t.Fatalf("no stream socket should open when --log is chosen: %v", log)
		}
	}
}

// (a) --uninstall reverts pf + trust and exits 0, and is idempotent (safe to run twice).
func TestIntercept_UninstallIdempotent(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	for i := 0; i < 2; i++ {
		if code := runIntercept([]string{"--uninstall"}, &bytes.Buffer{}); code != 0 {
			t.Fatalf("uninstall run %d: code=%d", i, code)
		}
	}
	if idx(log, "trust-uninstall") == -1 || idx(log, "proxy-teardown") == -1 {
		t.Fatalf("uninstall must revert both trust and redirect: %v", log)
	}
}

// A redirect-install failure AFTER trust was installed must roll the trust back (no orphaned root).
func TestIntercept_RedirectFailRollsBackTrust(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptInstallProxy = func(int) (func() error, error) {
		log = append(log, "proxy-install-FAIL")
		return nil, errors.New("pf: not permitted")
	}
	code := runIntercept([]string{"--yes"}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("redirect failure must return 1, got %d", code)
	}
	if idx(log, "trust-install") == -1 || idx(log, "trust-uninstall") == -1 {
		t.Fatalf("trust must be rolled back when redirect install fails: %v", log)
	}
	if idx(log, "serve") != -1 {
		t.Fatalf("must not serve after a redirect failure: %v", log)
	}
}

// An unknown flag on this dangerous command must be REJECTED (exit 2), never treated as an arming run.
func TestIntercept_UnknownFlagRejected(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	if code := runIntercept([]string{"--uninstal"}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("unknown flag must return 2, got %d", code)
	}
	if idx(log, "trust-install") != -1 || idx(log, "proxy-teardown") != -1 {
		t.Fatalf("a typo'd flag must neither arm nor revert: %v", log)
	}
}

// Home-dir resolution failure must fail loud, not fall back to a relative ".counterspy".
func TestIntercept_HomeDirFailure(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptUserHomeDir = func() (string, error) { return "", errors.New("no home") }
	if code := runIntercept([]string{"--yes"}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("home-dir failure must return 1, got %d", code)
	}
	if idx(log, "trust-install") != -1 {
		t.Fatalf("must not arm when home is unresolved: %v", log)
	}
}

// --uninstall with no CA on disk must NOT mint one and must exit 0 (nothing to untrust).
func TestIntercept_UninstallNoCADoesNotMint(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptCALoad = func(string) (*ca.CA, bool, error) { return nil, false, nil }
	interceptCALoadOrCreate = func(string) (*ca.CA, error) {
		t.Fatal("--uninstall must never mint a CA")
		return nil, nil
	}
	if code := runIntercept([]string{"--uninstall"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("uninstall with no CA must return 0, got %d", code)
	}
	if idx(log, "trust-uninstall") != -1 {
		t.Fatalf("no CA → nothing to untrust: %v", log)
	}
}

// --uninstall stays idempotent when trust removal reports an error (cert already gone): exit 0.
func TestIntercept_UninstallToleratesRemovalError(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptUninstallTrust = func([]byte) error { return errors.New("cert not found") }
	if code := runIntercept([]string{"--uninstall"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("uninstall must tolerate a removal error (idempotent), got %d", code)
	}
}

// Consent: without --yes, a "no" answer aborts before any arming happens.
func TestIntercept_ConsentDeclineAborts(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptStdin = strings.NewReader("n\n")
	if code := runIntercept(nil, &bytes.Buffer{}); code != 1 {
		t.Fatalf("declined consent must return 1, got %d", code)
	}
	if idx(log, "trust-install") != -1 {
		t.Fatalf("must NOT arm without consent: %v", log)
	}
}

// Consent: a "yes" answer proceeds to arm.
func TestIntercept_ConsentAcceptArms(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptStdin = strings.NewReader("y\n")
	runIntercept(nil, &bytes.Buffer{})
	if idx(log, "trust-install") == -1 {
		t.Fatalf("consented run must arm: %v", log)
	}
}

// (d) Usage lists intercept and exactly the four approved flags; no other new option crept in.
func TestUsage_ListsInterceptAndApprovedFlagsOnly(t *testing.T) {
	var b bytes.Buffer
	usage(&b)
	out := b.String()
	for _, want := range []string{"intercept", "--stream", "--log", "--uninstall", "--yes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("usage missing %q", want)
		}
	}
	// Guard against an unapproved flag sneaking into the intercept surface.
	for _, forbidden := range []string{"--socket", "--capture-all", "--port", "--proxy"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("unapproved flag %q in usage", forbidden)
		}
	}
}

// The root daemon must hand the stream socket to the invoking (sudo) user; macOS enforces write
// permission on unix connect(), so a root-owned 0755 socket would refuse the non-root console.
func TestSudoInvoker_ReadsSudoEnv(t *testing.T) {
	t.Setenv("SUDO_UID", "501")
	t.Setenv("SUDO_GID", "20")
	uid, gid, ok := sudoInvoker()
	if !ok || uid != 501 || gid != 20 {
		t.Fatalf("expected 501/20/true, got %d/%d/%v", uid, gid, ok)
	}
	// Not under sudo → no-op (don't chown a socket we already own).
	t.Setenv("SUDO_UID", "")
	if _, _, ok := sudoInvoker(); ok {
		t.Fatal("no SUDO_UID must report not-under-sudo")
	}
	// A root SUDO_UID (uid 0) is not a meaningful hand-off target.
	t.Setenv("SUDO_UID", "0")
	t.Setenv("SUDO_GID", "0")
	if _, _, ok := sudoInvoker(); ok {
		t.Fatal("uid 0 must not be treated as an invoking user")
	}
}

// A chown failure must abort BEFORE arming (the stream is the primary output; don't MITM for nothing).
func TestIntercept_ChownFailureAbortsBeforeArming(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptChownSocket = func(string) error { return errors.New("chown: not permitted") }
	if code := runIntercept([]string{"--yes"}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("chown failure must return 1, got %d", code)
	}
	if idx(log, "trust-install") != -1 || idx(log, "proxy-install") != -1 {
		t.Fatalf("must not arm when the stream socket is unusable: %v", log)
	}
}

// --install-daemon takes its OWN consent: the session prompt buys "until Ctrl-C", not "across reboots".
func TestInstallDaemon_RequiresItsOwnConsent(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	installed := false
	interceptInstallDaemon = func(exe, home string) error { installed = true; return nil }
	interceptStdin = strings.NewReader("n\n")
	if code := runIntercept([]string{"--install-daemon"}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("declined consent must return 1, got %d", code)
	}
	if installed {
		t.Fatal("a persistent daemon must NOT be installed without its own consent")
	}
}

// The consent text must state the things that make it different from a session: persistence, no further
// prompts, and that it logs while unattended.
func TestInstallDaemon_ConsentStatesPersistence(t *testing.T) {
	var b bytes.Buffer
	confirmDaemonConsent(&b, strings.NewReader("n\n"), "/usr/local/bin/counterspy")
	out := b.String()
	for _, want := range []string{"PERSISTENT", "EVERY BOOT", "without asking again", "--uninstall-daemon"} {
		if !strings.Contains(out, want) {
			t.Fatalf("daemon consent must state %q:\n%s", want, out)
		}
	}
}

// A consented install passes an ABSOLUTE exe + the invoking user's home (so the daemon shares ONE CA:
// launchd sets no HOME, so it would otherwise mint a second CA at /var/root that --uninstall never reverts).
func TestInstallDaemon_PassesAbsoluteExeAndHome(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	home := t.TempDir()
	interceptUserHomeDir = func() (string, error) { return home, nil }
	interceptExecutable = func() (string, error) { return "/usr/local/bin/counterspy", nil }
	var gotExe, gotHome string
	interceptInstallDaemon = func(exe, h string) error { gotExe, gotHome = exe, h; return nil }
	if code := runIntercept([]string{"--install-daemon", "--yes"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !filepath.IsAbs(gotExe) || gotExe != "/usr/local/bin/counterspy" {
		t.Fatalf("exe = %q", gotExe)
	}
	if gotHome != home {
		t.Fatalf("home = %q, want %q (the daemon must share the user's CA)", gotHome, home)
	}
}

// --uninstall-daemon removes the service AND force-reverts trust/proxy: bootout signals the daemon to
// tear down, but a crash/power loss means it may never have run.
func TestUninstallDaemon_AlsoForcesTheRevert(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	removed := false
	interceptUninstallDaemon = func() error { removed = true; return nil }
	if code := runIntercept([]string{"--uninstall-daemon"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !removed {
		t.Fatal("the daemon must be removed")
	}
	if idx(log, "trust-uninstall") == -1 || idx(log, "proxy-teardown") == -1 {
		t.Fatalf("uninstall-daemon must force-revert trust + proxy: %v", log)
	}
}

// The daemon flags are part of the approved surface; a typo near them is still rejected.
func TestInterceptFlags_DaemonSurfaceAcceptedTyposRejected(t *testing.T) {
	for _, ok := range []string{"--install-daemon", "--uninstall-daemon"} {
		if bad, isBad := unknownInterceptFlag([]string{ok}); isBad {
			t.Fatalf("%q must be accepted, got rejected as %q", ok, bad)
		}
	}
	if _, isBad := unknownInterceptFlag([]string{"--install-deamon"}); !isBad {
		t.Fatal("a typo'd daemon flag must be rejected, not silently ignored")
	}
}
