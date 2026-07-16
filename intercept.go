package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"counterspy/internal/intercept"
	"counterspy/internal/intercept/ca"
	"counterspy/internal/intercept/publish"
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
	interceptNewSocketSink   = publish.NewSocketSink
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
)

// interceptDir is where the reusable CA (and default log) live — installed-once trust reused across runs.
func interceptDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".counterspy")
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

// runIntercept is the `counterspy intercept` daemon: consent → install trust + pf redirect → serve the
// decrypt proxy, publishing flows to the chosen sink(s) → revert everything reliably on exit. Requires
// root (pf + System keychain). See internal/intercept for the read-only-mirror contract.
func runIntercept(flags []string, stdout io.Writer) (code int) {
	stream, streamPath := optFlag(flags, "--stream")
	logOn, logPath := optFlag(flags, "--log")
	uninstall := has(flags, "--uninstall")
	yes := has(flags, "--yes")

	dir := interceptDir()
	caObj, err := interceptCALoadOrCreate(dir)
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot load CA:", report.Clean(err.Error()))
		return 1
	}

	if uninstall {
		return runInterceptUninstall(caObj, stdout)
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

	// Arm: install trust FIRST, then the redirect. Teardown reverts in REVERSE (redirect, then trust) so
	// traffic stops being redirected before the CA loses trust — and runs exactly once whether triggered
	// by normal return, panic, or an external signal (Rule 13/14: a MITM that armed must always disarm).
	if err := interceptInstallTrust(caObj.CertPEM()); err != nil {
		sinks.Close()
		fmt.Fprintln(stdout, "intercept: cannot install CA trust:", report.Clean(err.Error()))
		return 1
	}
	teardownRedirect, err := interceptInstallRedirect(interceptProxyPort, nil)
	if err != nil {
		interceptUninstallTrust(caObj.CertPEM()) // undo the trust we just installed
		sinks.Close()
		fmt.Fprintln(stdout, "intercept: cannot install pf redirect:", report.Clean(err.Error()))
		return 1
	}

	var once sync.Once
	teardown := func() {
		once.Do(func() {
			if teardownRedirect != nil {
				teardownRedirect()
			}
			interceptUninstallTrust(caObj.CertPEM())
			sinks.Close()
		})
	}
	// External kill (SIGINT/TERM/HUP) bypasses defers — disarm then exit.
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
	// Panic mid-serve must still disarm (LIFO: teardown runs, then the panic is reported).
	defer func() {
		if r := recover(); r != nil {
			teardown()
			fmt.Fprintln(os.Stderr, "intercept: internal error:", r)
			code = 1
		}
	}()
	defer teardown()

	l, err := interceptListen()
	if err != nil {
		fmt.Fprintln(stdout, "intercept: cannot listen:", report.Clean(err.Error()))
		return 1
	}
	fmt.Fprintln(stdout, dim("  armed — decrypting TLS on :443 → 127.0.0.1 proxy. Ctrl-C to stop and revert."))
	p := &intercept.Proxy{CA: caObj, OrigDest: interceptOrigDest, Sink: sinks}
	if err := interceptServe(p, l); err != nil {
		fmt.Fprintln(stdout, "intercept: serve ended:", report.Clean(err.Error()))
	}
	return 0
}

// runInterceptUninstall reverts a prior arming: remove the pf redirect (a fresh install+teardown flushes
// our anchor and restores pf) and remove CA trust. Idempotent — a not-found removal is not a hard
// failure (self-heal after an unclean exit), but a real error is surfaced (fail loud).
func runInterceptUninstall(caObj *ca.CA, stdout io.Writer) int {
	// Flush any stale pf redirect by installing then immediately tearing it down (InstallRedirect owns the
	// anchor flush + ruleset restore). Best-effort: pf may already be clean.
	if td, err := interceptInstallRedirect(interceptProxyPort, nil); err == nil {
		td()
	}
	if err := interceptUninstallTrust(caObj.CertPEM()); err != nil {
		fmt.Fprintln(stdout, "intercept: cannot remove CA trust:", report.Clean(err.Error()))
		return 1
	}
	fmt.Fprintln(stdout, "intercept: reverted (pf redirect flushed, CA trust removed).")
	return 0
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
