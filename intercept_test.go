package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
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

func (r recSink) Publish(model.InterceptedFlow) error { return nil }
func (r recSink) Close() error                        { *r.log = append(*r.log, "sink-close"); return nil }

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
	origRedir := interceptInstallRedirect
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
		interceptInstallRedirect = origRedir
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
	interceptInstallRedirect = func(int, []netip.Addr) (func() error, error) {
		*log = append(*log, "redirect-install")
		return func() error { *log = append(*log, "redirect-teardown"); return nil }, nil
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
	order := []string{"trust-install", "redirect-install", "serve", "redirect-teardown", "trust-uninstall"}
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
	if idx(log, "redirect-teardown") == -1 || idx(log, "trust-uninstall") == -1 {
		t.Fatalf("teardown must run on panic: %v", log)
	}
	if idx(log, "redirect-teardown") > idx(log, "trust-uninstall") {
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
	if idx(log, "trust-uninstall") == -1 || idx(log, "redirect-teardown") == -1 {
		t.Fatalf("uninstall must revert both trust and redirect: %v", log)
	}
}

// A redirect-install failure AFTER trust was installed must roll the trust back (no orphaned root).
func TestIntercept_RedirectFailRollsBackTrust(t *testing.T) {
	var log []string
	fakeIntercept(t, &log, nil)
	interceptInstallRedirect = func(int, []netip.Addr) (func() error, error) {
		log = append(log, "redirect-install-FAIL")
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
	if idx(log, "trust-install") != -1 || idx(log, "redirect-teardown") != -1 {
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

// --uninstall stays idempotent when trust removal reports an error (cert already gone) — exit 0.
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

// (d) Usage lists intercept and exactly the four approved flags — no other new option crept in.
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

// liveSock creates a REAL unix socket at a SHORT path — the viewer now Lstats the path to dispatch, and
// macOS caps sun_path at ~104B so t.TempDir()'s long name can't be used (T-19).
func liveSock(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cs")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); os.RemoveAll(dir) })
	return p
}

// The --intercept viewer streams flows from a live socket and renders a decrypted flow's masked body.
func TestInterceptView_RendersDecryptedFlow(t *testing.T) {
	origRead := interceptReadSocket
	t.Cleanup(func() { interceptReadSocket = origRead })
	sock := liveSock(t)
	interceptReadSocket = func(path string, fn func(model.InterceptedFlow)) error {
		if path != sock {
			t.Fatalf("socket path expected %q, got %q", sock, path)
		}
		fn(model.InterceptedFlow{At: "T", DestName: "api.example.com", Status: model.FlowDecrypted,
			SentText: "GET /v1 HTTP/1.1\nAuthorization: ***", RecvText: "HTTP/1.1 200 OK", SentBytes: 5, RecvBytes: 9})
		return nil
	}
	var b bytes.Buffer
	if code := runInterceptView(sock, &b); code != 0 {
		t.Fatalf("code=%d", code)
	}
	out := b.String()
	for _, want := range []string{"api.example.com", "decrypted", "GET /v1", "HTTP/1.1 200 OK"} {
		if !strings.Contains(out, want) {
			t.Fatalf("viewer output missing %q:\n%s", want, out)
		}
	}
}

// A pinned/opaque/error flow shows its status and NO content (never implies plaintext it lacks).
func TestInterceptView_NonDecryptedShowsNoContent(t *testing.T) {
	out := formatFlow(model.InterceptedFlow{At: "T", DestName: "pinned.example", Status: model.FlowPinned,
		SentText: "should-not-render", RecvText: "should-not-render"})
	if strings.Contains(out, "should-not-render") {
		t.Fatalf("non-decrypted flow must not render captured text:\n%s", out)
	}
	if !strings.Contains(out, "pinned") {
		t.Fatalf("status must be shown:\n%s", out)
	}
}

// A LIVE socket whose stream then errors surfaces it and exits non-zero. Must use a real socket: a
// nonexistent path now short-circuits with a not-found message, which would pass this test for the
// wrong reason (never reaching the stream at all).
func TestInterceptView_StreamErrorNonZero(t *testing.T) {
	origRead := interceptReadSocket
	t.Cleanup(func() { interceptReadSocket = origRead })
	reached := false
	interceptReadSocket = func(string, func(model.InterceptedFlow)) error {
		reached = true
		return errors.New("stream broke")
	}
	if code := runInterceptView(liveSock(t), &bytes.Buffer{}); code != 1 || !reached {
		t.Fatalf("stream error must return 1 via the stream; code=%d reached=%v", code, reached)
	}
}

// cp-p2g review: a multi-line body must render as MULTIPLE lines (clean runs per-line, after the split),
// and a single enormous line must be width-capped — neither can collapse or flood.
func TestFormatFlow_MultilineAndWidthCapped(t *testing.T) {
	body := "GET /v1 HTTP/1.1\nAuthorization: ***\nHost: api.example.com"
	out := formatFlow(model.InterceptedFlow{At: "T", DestName: "api.example.com", Status: model.FlowDecrypted, SentText: body})
	// Three body lines must survive as separate lines (not glued into one).
	if !strings.Contains(out, "→ GET /v1 HTTP/1.1\n") || !strings.Contains(out, "Host: api.example.com") {
		t.Fatalf("multi-line body must stay multi-line:\n%q", out)
	}
	// A single 10k-rune line must be width-capped (nowhere near 10k on one line).
	huge := formatFlow(model.InterceptedFlow{At: "T", Status: model.FlowDecrypted, SentText: strings.Repeat("A", 10000)})
	for _, ln := range strings.Split(huge, "\n") {
		if len([]rune(ln)) > flowMaxWidth+10 {
			t.Fatalf("a line escaped the width cap: %d runes", len([]rune(ln)))
		}
	}
}

// cp-p2g review: a forged At with an escape sequence must be stripped at render (untrusted socket input).
func TestFormatFlow_CleansUntrustedAt(t *testing.T) {
	out := formatFlow(model.InterceptedFlow{At: "\x1b[31mHACK\x1b[0m", DestName: "x", Status: model.FlowError})
	if strings.Contains(out, "\x1b") {
		t.Fatalf("escape sequence in At must be stripped:\n%q", out)
	}
}

// The root daemon must hand the stream socket to the invoking (sudo) user — macOS enforces write
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
	if idx(log, "trust-install") != -1 || idx(log, "redirect-install") != -1 {
		t.Fatalf("must not arm when the stream socket is unusable: %v", log)
	}
}

// --intercept dispatches on what the path IS: a regular file reads the rotating --log (previously
// unreachable — publish.ReadLog had no production caller), a socket streams live.
func TestInterceptView_RegularFileReadsLog(t *testing.T) {
	origLog, origSock := interceptReadLog, interceptReadSocket
	t.Cleanup(func() { interceptReadLog, interceptReadSocket = origLog, origSock })

	f := filepath.Join(t.TempDir(), "flows.jsonl")
	if err := os.WriteFile(f, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logRead := false
	interceptReadLog = func(p string, fn func(model.InterceptedFlow)) error {
		logRead = true
		if p != f {
			t.Fatalf("log path %q != %q", p, f)
		}
		fn(model.InterceptedFlow{At: "T", DestName: "logged.example", Status: model.FlowDecrypted, SentText: "GET /x"})
		return nil
	}
	interceptReadSocket = func(string, func(model.InterceptedFlow)) error {
		t.Fatal("a regular file must NOT be dialed as a socket")
		return nil
	}
	var b bytes.Buffer
	if code := runInterceptView(f, &b); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !logRead || !strings.Contains(b.String(), "logged.example") {
		t.Fatalf("log flows must render: read=%v out=%q", logRead, b.String())
	}
}

// A path that is neither socket nor log is reported PLAINLY — never as a bogus "dial unix" against an
// obvious .jsonl (the confusing error a real run produced) — and a bare --intercept names the default
// socket so "is the daemon running?" reads correctly.
func TestInterceptView_MissingPathReportsPlainly(t *testing.T) {
	origLog, origSock := interceptReadLog, interceptReadSocket
	t.Cleanup(func() { interceptReadLog, interceptReadSocket = origLog, origSock })
	interceptReadLog = func(string, func(model.InterceptedFlow)) error {
		t.Fatal("a missing path must not be read as a log")
		return nil
	}
	interceptReadSocket = func(string, func(model.InterceptedFlow)) error {
		t.Fatal("a missing path must not be dialed as a socket")
		return nil
	}
	var b bytes.Buffer
	if code := runInterceptView("/tmp/definitely-not-here.jsonl", &b); code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
	if !strings.Contains(b.String(), "no intercept socket or log at") || strings.Contains(b.String(), "dial unix") {
		t.Fatalf("expected a plain not-found message, got:\n%s", b.String())
	}
	var d bytes.Buffer
	runInterceptView("", &d)
	if !strings.Contains(d.String(), interceptSocketPath) {
		t.Fatalf("bare --intercept must name the default socket:\n%s", d.String())
	}
}

// An unexpanded tilde (zsh does not expand ~ after `=`) is called out specifically, rather than left to
// read as a plain "not found" — the exact trap a real `--intercept=~/…` run hit.
func TestInterceptView_UnexpandedTildeHint(t *testing.T) {
	var b bytes.Buffer
	if code := runInterceptView("~/.counterspy/flows.jsonl", &b); code != 1 {
		t.Fatalf("expected 1, got %d", code)
	}
	if !strings.Contains(b.String(), "did not expand") {
		t.Fatalf("expected a tilde hint, got:\n%s", b.String())
	}
}
