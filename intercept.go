package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"counterspy/internal/intercept"
	"counterspy/internal/intercept/ca"
	"counterspy/internal/intercept/publish"
	"counterspy/internal/model"
	"counterspy/internal/report"
)

// interceptProxyPort is the fixed loopback port the decrypt proxy listens on and the pf rdr targets.
// It is intentionally NOT a flag (the CLI surface is frozen — no new options without approval); a
// constant keeps the redirect rule and the listener in lockstep.
const interceptProxyPort = 62443

// Rotating-log parameters for --log. Fixed constants (the approved surface is --log[=path] only, no
// size/keep/age tuning): a 0600 JSONL log capped at 50MB × 5 files, pruned after 7 days. The content is
// decrypted (already masked) so the log is a sensitive, short-lived artifact.
const (
	interceptLogMaxSize = 50 << 20
	interceptLogKeep    = 5
	interceptLogMaxAge  = 7 * 24 * time.Hour
)

// interceptSocketPath is a SHORT unix-socket path. macOS caps sun_path at ~104 bytes, and os.TempDir()
// on macOS is a long per-user /var/folders/... path that overruns it (T-19) — so the default lives
// directly under /tmp.
const interceptSocketPath = "/tmp/counterspy-intercept.sock"

// Seams: the side-effectful operations are package vars so intercept_test.go can inject fakes and assert
// ordering (install trust → install redirect → serve; teardown reverts in reverse) without root/pf.
var (
	interceptInstallTrust    = ca.InstallTrust
	interceptUninstallTrust  = ca.UninstallTrust
	interceptInstallRedirect = intercept.InstallRedirect
	interceptOrigDest        = intercept.OrigDest
	interceptCALoadOrCreate  = ca.LoadOrCreate
	interceptCALoad          = ca.Load
	interceptNewSocketSink   = publish.NewSocketSink
	interceptReadSocket      = publish.ReadSocket
	interceptNewLogSink      = func(path string) (publish.Sink, error) {
		return publish.NewLogSink(path, interceptLogMaxSize, interceptLogKeep, interceptLogMaxAge)
	}
	interceptListen = func() (net.Listener, error) {
		return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", interceptProxyPort))
	}
	// interceptServe blocks serving until the listener closes. Overridable so a test can drive the
	// teardown paths (return, panic) without a real proxy.
	interceptServe = func(p *intercept.Proxy, l net.Listener) error { return p.Serve(l) }
	// interceptStdin is the consent reader (os.Stdin in production).
	interceptStdin io.Reader = os.Stdin
	// interceptUserHomeDir is a seam so the home-resolution-failure path is testable.
	interceptUserHomeDir = os.UserHomeDir
	// interceptChownSocket hands the stream socket to the invoking user (seam for tests).
	interceptChownSocket = chownSocketToInvoker
)

// sudoInvoker returns the uid/gid of the human who ran `sudo`, from the environment sudo sets. ok is
// false when not running under sudo (or the values are unusable), in which case the caller keeps the
// current owner. Deliberately reads SUDO_UID/SUDO_GID rather than looking the user up by name: os/user
// lookups are unreliable on macOS without cgo, and these are plain integers sudo always provides.
func sudoInvoker() (uid, gid int, ok bool) {
	us, gs := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if us == "" || gs == "" {
		return 0, 0, false
	}
	uid, uerr := strconv.Atoi(us)
	gid, gerr := strconv.Atoi(gs)
	if uerr != nil || gerr != nil || uid <= 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// chownSocketToInvoker gives the live stream socket to the user who ran sudo. `intercept` runs as root,
// so a socket it creates is root-owned at mode 0755 under the usual umask — and macOS ENFORCES write
// permission on unix-socket connect(), so the human's NON-root `console --intercept` would be refused
// with "permission denied". Handing it to the invoker makes the documented viewer flow work while still
// denying every OTHER local user (the stream carries decrypted traffic). A no-op when not under sudo.
func chownSocketToInvoker(path string) error {
	uid, gid, ok := sudoInvoker()
	if !ok {
		return nil // not under sudo — the socket already belongs to the running user
	}
	return os.Chown(path, uid, gid)
}

// interceptDir is where the reusable CA (and default log) live — installed-once trust reused across
// runs. ok is false when the home directory can't be resolved: we must NOT fall back to a relative
// ".counterspy" (that would create a different CA per working directory and orphan trusted roots).
func interceptDir() (string, bool) {
	home, err := interceptUserHomeDir()
	if err != nil || home == "" {
		return "", false
	}
	return filepath.Join(home, ".counterspy"), true
}

// optFlag reports whether an optional-value flag (--name or --name=value) is present, and its value if
// given with `=`. Unlike flagValue it never consumes a following positional arg — these flags stand alone.
func optFlag(flags []string, name string) (bool, string) {
	for _, f := range flags {
		if f == name {
			return true, ""
		}
		if strings.HasPrefix(f, name+"=") {
			return true, strings.TrimPrefix(f, name+"=")
		}
	}
	return false, ""
}

// unknownInterceptFlag returns the first arg that isn't one of the frozen intercept flags. `intercept`
// arms/reverts a MITM, so a typo (e.g. `--uninstal`) must be REJECTED, not silently ignored and treated
// as an arming run — this command validates its surface strictly (unlike scan/console).
func unknownInterceptFlag(flags []string) (string, bool) {
	for _, f := range flags {
		switch {
		case f == "--uninstall", f == "--yes", f == "--stream", f == "--log":
		case strings.HasPrefix(f, "--stream="), strings.HasPrefix(f, "--log="):
		default:
			return f, true
		}
	}
	return "", false
}

// runIntercept is the `counterspy intercept` daemon: consent → install trust + pf redirect → serve the
// decrypt proxy, publishing flows to the chosen sink(s) → revert everything reliably on exit. Requires
// root (pf + System keychain). See internal/intercept for the read-only-mirror contract.
func runIntercept(flags []string, stdout io.Writer) (code int) {
	if bad, ok := unknownInterceptFlag(flags); ok {
		fmt.Fprintln(stdout, "intercept: unknown flag:", bad)
		return 2
	}
	stream, streamPath := optFlag(flags, "--stream")
	logOn, logPath := optFlag(flags, "--log")
	uninstall := has(flags, "--uninstall")
	yes := has(flags, "--yes")

	dir, ok := interceptDir()
	if !ok {
		fmt.Fprintln(stdout, "intercept: cannot determine home directory")
		return 1
	}

	if uninstall {
		return runInterceptUninstall(dir, stdout)
	}

	caObj, err := interceptCALoadOrCreate(dir)
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot load CA:", report.Clean(err.Error()))
		return 1
	}

	if !yes && !confirmConsent(stdout, interceptStdin) {
		fmt.Fprintln(stdout, "intercept: aborted (no consent).")
		return 1
	}

	// Default to the live socket when neither output is chosen (the approved default).
	if !stream && !logOn {
		stream, streamPath = true, ""
	}
	if stream && streamPath == "" {
		streamPath = interceptSocketPath
	}
	if logOn && logPath == "" {
		logPath = filepath.Join(dir, "flows.jsonl")
	}

	var sinks publish.Fanout
	if stream {
		s, err := interceptNewSocketSink(streamPath)
		if err != nil {
			fmt.Fprintln(stdout, "intercept: cannot open stream socket:", report.Clean(err.Error()))
			return 1
		}
		// Hand the socket to the invoking user BEFORE arming: root's socket is otherwise unreachable to
		// the non-root console the flow tells them to run. Fail loud — the stream is the primary output.
		if err := interceptChownSocket(streamPath); err != nil {
			s.Close()
			fmt.Fprintln(stdout, "intercept: cannot hand the stream socket to the invoking user:", report.Clean(err.Error()))
			return 1
		}
		sinks = append(sinks, s)
		fmt.Fprintln(stdout, "  live stream:", streamPath, dim("(view: counterspy console --intercept="+streamPath+")"))
	}
	if logOn {
		l, err := interceptNewLogSink(logPath)
		if err != nil {
			sinks.Close()
			fmt.Fprintln(stdout, "intercept: cannot open log:", report.Clean(err.Error()))
			return 1
		}
		sinks = append(sinks, l)
		fmt.Fprintln(stdout, "  log:", logPath, dim("(0600, rotating)"))
	}

	// Teardown reverts whatever has been armed SO FAR (guarded state), in REVERSE order (redirect before
	// trust, so traffic stops being redirected before the CA loses trust), exactly once, and REPORTS any
	// revert failure — a MITM that armed must always disarm, loudly if it can't (Rule 13/14).
	var (
		mu               sync.Mutex
		trustInstalled   bool
		redirectTeardown func() error
		once             sync.Once
	)
	teardown := func() {
		once.Do(func() {
			mu.Lock()
			defer mu.Unlock()
			if redirectTeardown != nil {
				if err := redirectTeardown(); err != nil {
					fmt.Fprintln(os.Stderr, "intercept: pf redirect teardown FAILED:", report.Clean(err.Error()))
				}
			}
			if trustInstalled {
				if err := interceptUninstallTrust(caObj.CertPEM()); err != nil {
					fmt.Fprintln(os.Stderr, "intercept: CA trust removal FAILED (run `counterspy intercept --uninstall`):", report.Clean(err.Error()))
				}
			}
			sinks.Close()
		})
	}
	// Register the signal handler + teardown defers BEFORE arming: a SIGINT/TERM/HUP arriving in the
	// arming window (which shells out to security/pfctl, up to ~20s) would otherwise hit the default
	// disposition and kill the process with NO defer running — leaving a trusted MITM root behind
	// (Audit cp-p2f F-1). Registering first means teardown reverts whatever got installed.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	sigDone := make(chan struct{})
	defer func() { signal.Stop(sigCh); close(sigDone) }()
	go func() {
		select {
		case <-sigCh:
			teardown()
			os.Exit(130)
		case <-sigDone:
		}
	}()
	defer func() {
		if r := recover(); r != nil {
			teardown()
			fmt.Fprintln(os.Stderr, "intercept: internal error:", r)
			code = 1
		}
	}()
	defer teardown()

	// Arm: trust FIRST, then the redirect. Each success is recorded so the deferred teardown above knows
	// exactly what to revert if a later step (or a signal) interrupts.
	if err := interceptInstallTrust(caObj.CertPEM()); err != nil {
		fmt.Fprintln(stdout, "intercept: cannot install CA trust:", report.Clean(err.Error()))
		return 1
	}
	mu.Lock()
	trustInstalled = true
	mu.Unlock()

	td, err := interceptInstallRedirect(interceptProxyPort, nil)
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot install pf redirect:", report.Clean(err.Error()))
		return 1 // deferred teardown rolls back the trust just installed
	}
	mu.Lock()
	redirectTeardown = td
	mu.Unlock()

	l, err := interceptListen()
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot listen:", report.Clean(err.Error()))
		return 1 // deferred teardown reverts trust + redirect
	}
	fmt.Fprintln(stdout, dim("  armed — decrypting TLS on :443 → 127.0.0.1 proxy. Ctrl-C to stop and revert."))
	p := &intercept.Proxy{CA: caObj, OrigDest: interceptOrigDest, Sink: sinks}
	if err := interceptServe(p, l); err != nil {
		fmt.Fprintln(stdout, "intercept: serve ended:", report.Clean(err.Error()))
	}
	return 0
}

// runInterceptUninstall reverts a prior arming and self-heals after an unclean exit: flush any stale pf
// redirect, then remove CA trust. It NEVER mints a CA (Audit cp-p2f F-4) — with no CA on disk there is
// nothing to untrust. Idempotent: a trust-removal error (e.g. the cert is already gone on a second run)
// is surfaced but not fatal, so repeated reverts still succeed (Rule 13/14: loud, not crashing).
func runInterceptUninstall(dir string, stdout io.Writer) int {
	// Flush any stale pf redirect regardless of CA state (InstallRedirect owns the anchor flush + ruleset
	// restore). Best-effort — pf may already be clean.
	if td, err := interceptInstallRedirect(interceptProxyPort, nil); err == nil {
		td()
	}
	caObj, found, err := interceptCALoad(dir)
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot read CA:", report.Clean(err.Error()))
		return 1
	}
	if !found {
		fmt.Fprintln(stdout, "intercept: no local CA on disk — nothing to untrust (pf redirect flushed).")
		return 0
	}
	if err := interceptUninstallTrust(caObj.CertPEM()); err != nil {
		fmt.Fprintln(stdout, "intercept: CA trust removal reported:", report.Clean(err.Error()), dim("(may already be removed)"))
		return 0
	}
	fmt.Fprintln(stdout, "intercept: reverted (pf redirect flushed, CA trust removed).")
	return 0
}

// runInterceptView is `counterspy console --intercept[=sock]`: connect to the intercept daemon's live
// socket and print each decrypted flow as it arrives (a plain live tail, not the alt-screen TUI —
// mirrors how console --json/--once are non-TUI exits). It ends when the socket closes or on Ctrl-C.
func runInterceptView(path string, stdout io.Writer) int {
	if path == "" {
		path = interceptSocketPath
	}
	fmt.Fprintln(stdout, dim("counterspy — intercepted flows from "+path+" (Ctrl-C to stop)"))
	err := interceptReadSocket(path, func(fl model.InterceptedFlow) {
		fmt.Fprint(stdout, formatFlow(fl))
	})
	if err != nil {
		fmt.Fprintln(stdout, "console: intercept stream ended:", report.Clean(err.Error()))
		return 1
	}
	return 0
}

// Display bounds for a decrypted body: at most flowMaxLines lines, each at most flowMaxWidth runes, so a
// large or single-enormous-line payload can't flood the terminal (the proxy caps captured BYTES; these
// cap the DISPLAY). report.Clean (which strips control bytes INCLUDING newlines) must run PER LINE,
// after the raw split — cleaning first would delete the newlines and collapse the body into one line,
// defeating the line cap (Audit cp-p2g).
const (
	flowMaxLines = 6
	flowMaxWidth = 120
)

// formatFlow renders one flow: a header line (time, destination, status, byte counts) and — only for a
// decrypted flow — its masked request/response. A pinned/opaque/error flow shows its status and NO
// content, so the viewer never implies plaintext it doesn't have. EVERY field that reaches the terminal
// is report.Clean'd (the socket is untrusted input; even At/Status could carry an escape sequence).
func formatFlow(fl model.InterceptedFlow) string {
	name := fl.DestName
	if name == "" {
		name = fl.SNI
	}
	if name == "" {
		name = fl.DestIP
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s  %s  ↑%d ↓%d\n", report.Clean(fl.At), report.Clean(name), report.Clean(fl.Status), fl.SentBytes, fl.RecvBytes)
	if fl.Status == model.FlowDecrypted {
		b.WriteString(renderFlowBody("→", fl.SentText))
		b.WriteString(renderFlowBody("←", fl.RecvText))
	}
	return b.String()
}

// renderFlowBody indents a decoded body under its header, splitting on the RAW newlines first, then
// cleaning + width-capping each line, arrow-marking the first, and capping the line count. Empty → "".
func renderFlowBody(arrow, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	lines := strings.Split(raw, "\n")
	var b strings.Builder
	for i, ln := range lines {
		if i >= flowMaxLines {
			fmt.Fprintf(&b, "     %s\n", dim(fmt.Sprintf("… (%d more lines)", len(lines)-flowMaxLines)))
			break
		}
		ln = report.Clean(ln)
		if len([]rune(ln)) > flowMaxWidth {
			ln = string([]rune(ln)[:flowMaxWidth]) + "…"
		}
		if i == 0 {
			fmt.Fprintf(&b, "   %s %s\n", arrow, ln)
		} else {
			fmt.Fprintf(&b, "     %s\n", ln)
		}
	}
	return b.String()
}

// confirmConsent prints what arming does and requires an explicit y/yes. A MITM that installs a trusted
// root and redirects all TLS must be an informed, per-launch decision — default is No.
func confirmConsent(w io.Writer, r io.Reader) bool {
	fmt.Fprintln(w, "counterspy intercept will:")
	fmt.Fprintln(w, "  • install a local CA as a trusted root in your System keychain")
	fmt.Fprintln(w, "  • redirect this machine's outbound TLS (:443) through a local decrypt proxy")
	fmt.Fprintln(w, "  • DECRYPT and display your TLS traffic (read-only mirror; nothing is modified)")
	fmt.Fprintln(w, dim("  Everything is reverted on exit (or `counterspy intercept --uninstall`)."))
	fmt.Fprint(w, "Proceed? [y/N] ")
	line, _ := bufio.NewReader(r).ReadString('\n')
	switch strings.TrimSpace(strings.ToLower(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
