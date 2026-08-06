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
	"counterspy/internal/report"
)

// interceptProxyPort is the fixed loopback port the decrypt proxy listens on and the system
// secure-web-proxy setting points at. It is intentionally NOT a flag (the CLI surface is frozen; no
// new options without approval); a constant keeps the proxy setting and the listener in lockstep.
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
// on macOS is a long per-user /var/folders/... path that overruns it (T-19), so the default lives
// directly under /tmp.
const interceptSocketPath = "/tmp/counterspy-intercept.sock"

// Seams: the side-effectful operations are package vars so intercept_test.go can inject fakes and assert
// ordering (install trust → register system proxy → serve; teardown reverts in reverse) without root.
var (
	interceptInstallTrust   = ca.InstallTrust
	interceptUninstallTrust = ca.UninstallTrust
	interceptInstallProxy   = intercept.InstallProxy
	interceptCALoadOrCreate = ca.LoadOrCreate
	interceptCALoad         = ca.Load
	interceptNewSocketSink  = publish.NewSocketSink
	interceptNewLogSink     = func(path string) (publish.Sink, error) {
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
	interceptChownSocket     = chownSocketToInvoker
	interceptInstallDaemon   = intercept.InstallDaemon
	interceptUninstallDaemon = intercept.UninstallDaemon
	interceptExecutable      = os.Executable
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
// so a socket it creates is root-owned at mode 0755 under the usual umask, and macOS ENFORCES write
// permission on unix-socket connect(), so the human's NON-root `console --intercept` would be refused
// with "permission denied". Handing it to the invoker makes the documented viewer flow work while still
// denying every OTHER local user (the stream carries decrypted traffic). A no-op when not under sudo.
func chownSocketToInvoker(path string) error {
	uid, gid, ok := sudoInvoker()
	if !ok {
		return nil // not under sudo; the socket already belongs to the running user
	}
	return os.Chown(path, uid, gid)
}

// interceptDir is where the reusable CA (and default log) live: installed-once trust reused across
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
// given with `=`. Unlike flagValue it never consumes a following positional arg; these flags stand alone.
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
// as an arming run; this command validates its surface strictly (unlike scan/console).
func unknownInterceptFlag(flags []string) (string, bool) {
	for _, f := range flags {
		switch {
		case f == "--uninstall", f == "--yes", f == "--stream", f == "--log":
		case f == "--install-daemon", f == "--uninstall-daemon":
		case strings.HasPrefix(f, "--stream="), strings.HasPrefix(f, "--log="):
		default:
			return f, true
		}
	}
	return "", false
}

// runIntercept is the `counterspy intercept` daemon: consent → install trust + register as the system
// HTTPS proxy → serve the decrypt proxy, publishing flows to the chosen sink(s) → revert everything
// reliably on exit. Requires root (networksetup + System keychain). See internal/intercept for the
// read-only-mirror contract and why this is a CONNECT proxy rather than a transparent pf redirect.
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

	if has(flags, "--uninstall-daemon") {
		return runUninstallDaemon(dir, stdout)
	}
	if has(flags, "--install-daemon") {
		return runInstallDaemon(dir, yes, stdout)
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
		// the non-root console the flow tells them to run. Fail loud; the stream is the primary output.
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
	// revert failure: a MITM that armed must always disarm, loudly if it can't (Rule 13/14).
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
					fmt.Fprintln(os.Stderr, "intercept: system proxy teardown FAILED:", report.Clean(err.Error()))
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
	// disposition and kill the process with NO defer running, leaving a trusted MITM root behind
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

	td, err := interceptInstallProxy(interceptProxyPort)
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot register the system proxy:", report.Clean(err.Error()))
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
	fmt.Fprintf(stdout, "%s\n", dim(fmt.Sprintf("  armed: system HTTPS proxy → 127.0.0.1:%d, decrypting. Ctrl-C to stop and revert.", interceptProxyPort)))
	p := &intercept.Proxy{CA: caObj, Sink: sinks}
	if err := interceptServe(p, l); err != nil {
		fmt.Fprintln(stdout, "intercept: serve ended:", report.Clean(err.Error()))
	}
	return 0
}

// runInterceptUninstall reverts a prior arming and self-heals after an unclean exit: restore the system
// proxy setting, then remove CA trust. It NEVER mints a CA (Audit cp-p2f F-4). With no CA on disk there is
// nothing to untrust. Idempotent: a trust-removal error (e.g. the cert is already gone on a second run)
// is surfaced but not fatal, so repeated reverts still succeed (Rule 13/14: loud, not crashing).
func runInterceptUninstall(dir string, stdout io.Writer) int {
	// Restore the system proxy regardless of CA state: registering then immediately tearing down puts each
	// service back to its captured prior setting. Best-effort; it may already be clean.
	if td, err := interceptInstallProxy(interceptProxyPort); err == nil {
		td()
	}
	caObj, found, err := interceptCALoad(dir)
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot read CA:", report.Clean(err.Error()))
		return 1
	}
	if !found {
		fmt.Fprintln(stdout, "intercept: no local CA on disk; nothing to untrust (system proxy restored).")
		return 0
	}
	if err := interceptUninstallTrust(caObj.CertPEM()); err != nil {
		fmt.Fprintln(stdout, "intercept: CA trust removal reported:", report.Clean(err.Error()), dim("(may already be removed)"))
		return 0
	}
	fmt.Fprintln(stdout, "intercept: reverted (system proxy restored, CA trust removed).")
	return 0
}

// runInstallDaemon installs the persistent LaunchDaemon. Requires root.
//
// It takes its OWN consent, separate from the session prompt, because it is a different decision: the
// session prompt asks "decrypt my traffic until I press Ctrl-C"; this one asks "stay armed across
// reboots, with no further prompts". Reusing the session prompt would let the smaller yes buy the
// larger thing.
func runInstallDaemon(dir string, yes bool, stdout io.Writer) int {
	exe, err := interceptExecutable()
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot resolve my own path:", report.Clean(err.Error()))
		return 1
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved // launchd needs the real target, not a symlink that may move
	}
	home, herr := interceptUserHomeDir()
	if herr != nil || home == "" {
		fmt.Fprintln(stdout, "intercept: cannot determine home directory")
		return 1
	}
	// A daemon whose program lives in a build tree or home dir breaks when that tree moves, and
	// counterspy's own scanner treats user-path persistence as a signal, so this is the shape the tool
	// teaches people to distrust. Warn loudly; don't refuse (it's the user's machine).
	if intercept.UnstableExePath(exe) {
		fmt.Fprintln(stdout, "  ⚠", exe)
		fmt.Fprintln(stdout, dim("    this is not a stable location for a root LaunchDaemon; it breaks if you move or"))
		fmt.Fprintln(stdout, dim("    delete it. Install to /usr/local/bin first, then run --install-daemon from there."))
	}
	if !yes && !confirmDaemonConsent(stdout, interceptStdin, exe) {
		fmt.Fprintln(stdout, "intercept: aborted (no consent).")
		return 1
	}
	if err := interceptInstallDaemon(exe, home); err != nil {
		fmt.Fprintln(stdout, "intercept: cannot install the daemon:", report.Clean(err.Error()))
		return 1
	}
	fmt.Fprintln(stdout, "intercept: daemon installed and started.")
	fmt.Fprintln(stdout, "  definition:", intercept.DaemonPlistPath(), dim("(auditable, read it)"))
	fmt.Fprintln(stdout, "  flow log:  ", intercept.DaemonFlowLog, dim("(0600; view: sudo counterspy console --intercept="+intercept.DaemonFlowLog+")"))
	fmt.Fprintln(stdout, dim("  It is armed NOW and will re-arm at every boot until you run --uninstall-daemon."))
	fmt.Fprintln(stdout, dim("  `counterspy scan` will flag this daemon. That is correct: it is a machine-wide MITM."))
	return 0
}

// runUninstallDaemon removes the daemon and force-reverts the trust + proxy. Idempotent: this is the
// self-heal path, so "nothing was installed" is a success, not an error.
func runUninstallDaemon(dir string, stdout io.Writer) int {
	if err := interceptUninstallDaemon(); err != nil {
		fmt.Fprintln(stdout, "intercept: cannot remove the daemon:", report.Clean(err.Error()))
		return 1
	}
	fmt.Fprintln(stdout, "intercept: daemon removed.")
	// bootout signals the daemon, whose own teardown reverts trust + proxy, but it may have been
	// killed uncleanly (a crash/power loss can't run teardown), so force the revert regardless.
	return runInterceptUninstall(dir, stdout)
}

// confirmDaemonConsent is the PERSISTENT-install gate. It states the thing the session prompt does not:
// this survives reboots and will not ask again.
func confirmDaemonConsent(w io.Writer, r io.Reader, exe string) bool {
	fmt.Fprintln(w, "counterspy intercept --install-daemon will install a PERSISTENT root daemon:")
	fmt.Fprintln(w, "  •", exe, "intercept --yes --log")
	fmt.Fprintln(w, "  • it starts NOW and re-arms at EVERY BOOT, without asking again")
	fmt.Fprintln(w, "  • your local CA stays a trusted root and the system HTTPS proxy stays redirected")
	fmt.Fprintln(w, "  • it decrypts and LOGS your TLS traffic to", intercept.DaemonFlowLog, "while you are not watching")
	fmt.Fprintln(w, dim("  This is the point of it, and it is a standing machine-wide MITM, not a session."))
	fmt.Fprintln(w, dim("  macOS will pop up a system authorization dialog for the keychain change; expect it now."))
	fmt.Fprintln(w, dim("  NOTE: a boot-time daemon has no desktop session to answer such a dialog. If macOS decides"))
	fmt.Fprintln(w, dim("  to re-prompt at boot, the daemon cannot arm and will say so in /var/log/counterspy/daemon.err"))
	fmt.Fprintln(w, dim("  It will not silently half-arm. Check that log after your first reboot."))
	fmt.Fprintln(w, dim("  Remove it with: counterspy intercept --uninstall-daemon"))
	fmt.Fprint(w, "Install the persistent daemon? [y/N] ")
	line, _ := bufio.NewReader(r).ReadString('\n')
	switch strings.TrimSpace(strings.ToLower(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// confirmConsent prints what arming does and requires an explicit y/yes. A MITM that installs a trusted
// root and redirects all TLS must be an informed, per-launch decision; default is No.
func confirmConsent(w io.Writer, r io.Reader) bool {
	fmt.Fprintln(w, "counterspy intercept will:")
	fmt.Fprintln(w, "  • install a local CA as a trusted root in your System keychain")
	fmt.Fprintln(w, "  • set this machine's system HTTPS proxy to a local decrypt proxy")
	fmt.Fprintln(w, "  • DECRYPT and display your TLS traffic (read-only mirror; nothing is modified)")
	fmt.Fprintln(w, dim("  macOS will pop up a system authorization dialog for the keychain change. That is expected;"))
	fmt.Fprintln(w, dim("  it is asking you to approve THIS. Arming waits on it, so answer it to continue."))
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
