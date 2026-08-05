//go:build darwin

package intercept

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The persistent daemon.
//
// This INVERTS Phase 2's central invariant. Foreground `intercept` guarantees armed ⇒ eventually
// disarmed: teardown runs on exit, panic and signal, and consent is taken per launch. A LaunchDaemon is
// armed across reboots with a one-time consent, so the CA is trusted and the system proxy is redirected
// indefinitely. That is a deliberate, user-approved trade for the one thing the foreground mode cannot
// answer, what does this machine send when nobody is watching (at 3am, at boot, lid closed), and it is
// why the install prompt is separate and explicit rather than reusing the session prompt.
//
// Honest consequence: `counterspy scan` WILL flag this. A persistent, root, network-touching
// LaunchDaemon is exactly what the persistence collector hunts, and a machine-wide MITM *should* trip a
// counter-surveillance tool. That is correct behaviour, not a bug to suppress.
//
// UNVERIFIED: requires a root smoke test (install, reboot, uninstall).

const (
	daemonLabel     = "com.counterspy.intercept"
	daemonPlistPath = "/Library/LaunchDaemons/" + daemonLabel + ".plist"

	// daemonLogDir holds the daemon's artifacts. Explicitly under /var/log rather than the
	// HOME-derived default: launchd sets no HOME, so the default would land in /var/root/.counterspy,
	// findable by nobody.
	daemonLogDir = "/var/log/counterspy"
	// DaemonFlowLog is the flow log the daemon writes (0600, it holds decrypted traffic).
	DaemonFlowLog = daemonLogDir + "/flows.jsonl"
	// The daemon has no terminal, so its diagnostics must land somewhere durable (Rule 14): without
	// these, a daemon that fails to arm fails invisibly.
	daemonStdout = daemonLogDir + "/daemon.log"
	daemonStderr = daemonLogDir + "/daemon.err"

	// launchctlBin is absolute because install/uninstall run as root: resolving the tool through PATH
	// would let any writable PATH entry substitute it, turning a privileged call into an exec of
	// attacker-chosen code (go:S4036).
	launchctlBin     = "/bin/launchctl"
	launchctlTimeout = 20 * time.Second
)

// runLaunchctl is the seam over `launchctl`, so install/uninstall is unit-testable without touching the
// real service database. Fail loud: the tool's output is folded into the error.
var runLaunchctl = func(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), launchctlTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, launchctlBin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Filesystem seams (tests inject fakes rather than writing to /Library).
var (
	writePlist  = func(path string, b []byte) error { return os.WriteFile(path, b, 0o644) }
	removePlist = os.Remove
	statPlist   = os.Stat
	mkdirLogDir = func() error { return os.MkdirAll(daemonLogDir, 0o700) }
)

// xmlEscape escapes a value for plist XML. Paths are attacker-adjacent only in the sense that a user
// can name a directory anything; an unescaped `&` or `<` would produce a plist launchd silently refuses.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// daemonPlist renders the LaunchDaemon definition.
//
// HOME is pinned to the INSTALLING user's home deliberately: launchd sets no HOME, so the daemon would
// otherwise resolve ~/.counterspy to /var/root/.counterspy and mint a SECOND CA, one the user's
// `intercept --uninstall` would never revert, because that command resolves HOME to their own. One CA,
// one trust decision, one thing to remove.
//
// KeepAlive restarts a crashed proxy: while it is down the system proxy still points at 127.0.0.1:62443,
// so every proxy-honoring app's TLS fails. ThrottleInterval keeps a crash-loop from hammering.
func daemonPlist(exe, home string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + daemonLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(exe) + `</string>
		<string>intercept</string>
		<string>--yes</string>
		<string>--log=` + xmlEscape(DaemonFlowLog) + `</string>
	</array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>10</integer>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key><string>` + xmlEscape(home) + `</string>
	</dict>
	<key>StandardOutPath</key><string>` + xmlEscape(daemonStdout) + `</string>
	<key>StandardErrorPath</key><string>` + xmlEscape(daemonStderr) + `</string>
</dict>
</plist>
`
}

// DaemonInstalled reports whether our LaunchDaemon plist is present.
func DaemonInstalled() bool {
	_, err := statPlist(daemonPlistPath)
	return err == nil
}

// DaemonPlistPath is where the definition lives (surfaced to the user so it is auditable, not hidden).
func DaemonPlistPath() string { return daemonPlistPath }

// UnstableExePath reports whether exe sits somewhere a LaunchDaemon should not point. A daemon whose
// program lives in a build tree or home directory breaks the moment that tree is moved or deleted, and
// counterspy's own persistence collector treats user-path persistence as a signal, so pointing root
// launchd at /Users is precisely the shape this tool teaches people to distrust.
func UnstableExePath(exe string) bool {
	return strings.HasPrefix(exe, "/Users/") || strings.Contains(exe, "/tmp/")
}

// InstallDaemon writes the plist and bootstraps it. exe must be an absolute path to the counterspy
// binary; home is the installing user's home (pinned so the daemon shares their CA). Requires root.
//
// A failed bootstrap removes the plist rather than leaving a definition that will load at next boot;
// a half-install that silently arms on reboot is worse than a clean failure (Rule 13).
func InstallDaemon(exe, home string) error {
	if !filepath.IsAbs(exe) {
		return fmt.Errorf("daemon: program path must be absolute, got %q", exe)
	}
	if err := mkdirLogDir(); err != nil {
		return fmt.Errorf("daemon: create %s: %w", daemonLogDir, err)
	}
	if err := writePlist(daemonPlistPath, []byte(daemonPlist(exe, home))); err != nil {
		return fmt.Errorf("daemon: write %s: %w", daemonPlistPath, err)
	}
	// Replace any previous instance: bootstrap fails outright if the label is already loaded.
	runLaunchctl("bootout", "system/"+daemonLabel)
	if _, err := runLaunchctl("bootstrap", "system", daemonPlistPath); err != nil {
		removePlist(daemonPlistPath)
		return err
	}
	return nil
}

// UninstallDaemon boots the service out and removes the plist. Idempotent: a service that is not loaded
// and a plist that is already gone are both fine; this is also the self-heal path after an unclean
// state, so it must never fail just because there is nothing to do.
//
// It does NOT revert the CA trust or the system proxy: bootout signals the daemon, whose own teardown
// does that. The caller force-reverts afterwards in case the daemon never got the chance.
func UninstallDaemon() error {
	runLaunchctl("bootout", "system/"+daemonLabel) // not-loaded is not an error
	// errors.Is (not os.IsNotExist); the latter does not unwrap %w-wrapped errors, so a wrapped
	// "not exist" would be treated as a real failure and break idempotency.
	if err := removePlist(daemonPlistPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("daemon: remove %s: %w", daemonPlistPath, err)
	}
	return nil
}
