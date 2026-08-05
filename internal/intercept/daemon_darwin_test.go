//go:build darwin

package intercept

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The plist MUST pin HOME to the installing user. launchd sets no HOME, so without this the daemon
// resolves ~/.counterspy to /var/root/.counterspy, mints a SECOND CA, and installs ITS trust, which the
// user's `intercept --uninstall` (resolving HOME to their own) would never revert. One CA, one trust.
func TestDaemonPlist_PinsHomeSoThereIsOneCA(t *testing.T) {
	p := daemonPlist("/usr/local/bin/counterspy", "/Users/jmachen")
	if !strings.Contains(p, "<key>HOME</key><string>/Users/jmachen</string>") {
		t.Fatalf("plist must pin HOME to the installing user:\n%s", p)
	}
}

// The daemon must run non-interactively (no TTY to prompt on) and log where a human can find it, not
// the HOME-derived default, which under launchd would land in /var/root.
func TestDaemonPlist_RunsNonInteractiveAndLogsFindably(t *testing.T) {
	p := daemonPlist("/usr/local/bin/counterspy", "/Users/j")
	for _, want := range []string{
		"<string>intercept</string>", "<string>--yes</string>",
		"<string>--log=" + DaemonFlowLog + "</string>",
		"<key>RunAtLoad</key><true/>", "<key>KeepAlive</key><true/>",
		"<key>StandardErrorPath</key>", // no terminal: diagnostics must be durable (Rule 14)
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("plist missing %q:\n%s", want, p)
		}
	}
}

// A path with XML metacharacters must not produce a plist launchd silently refuses.
func TestDaemonPlist_EscapesXML(t *testing.T) {
	p := daemonPlist("/opt/a&b/counterspy", "/Users/x<y>")
	if strings.Contains(p, "/opt/a&b/") || strings.Contains(p, "<string>/Users/x<y></string>") {
		t.Fatalf("XML metacharacters must be escaped:\n%s", p)
	}
	if !strings.Contains(p, "a&amp;b") || !strings.Contains(p, "x&lt;y&gt;") {
		t.Fatalf("expected escaped values:\n%s", p)
	}
}

// A relative program path is rejected: launchd needs an absolute one, and a plist that fails to load is
// a half-install that would surprise at next boot.
func TestInstallDaemon_RejectsRelativeExe(t *testing.T) {
	if err := InstallDaemon("./counterspy", "/Users/j"); err == nil {
		t.Fatal("a relative program path must be rejected")
	}
}

// A failed bootstrap must REMOVE the plist. Leaving it would arm the machine at next boot with no
// running daemon and no consent; a half-install is worse than a clean failure (Rule 13).
func TestInstallDaemon_FailedBootstrapRemovesThePlist(t *testing.T) {
	var wrote, removed bool
	origW, origR, origM, origL := writePlist, removePlist, mkdirLogDir, runLaunchctl
	t.Cleanup(func() { writePlist, removePlist, mkdirLogDir, runLaunchctl = origW, origR, origM, origL })
	writePlist = func(string, []byte) error { wrote = true; return nil }
	removePlist = func(string) error { removed = true; return nil }
	mkdirLogDir = func() error { return nil }
	runLaunchctl = func(args ...string) (string, error) {
		if len(args) > 0 && args[0] == "bootstrap" {
			return "", errors.New("Load failed: 5: Input/output error")
		}
		return "", nil
	}
	if err := InstallDaemon("/usr/local/bin/counterspy", "/Users/j"); err == nil {
		t.Fatal("a failed bootstrap must fail loud")
	}
	if !wrote || !removed {
		t.Fatalf("a failed bootstrap must not leave a plist behind (wrote=%v removed=%v)", wrote, removed)
	}
}

// Install replaces any previous instance: bootstrap fails outright if the label is already loaded.
func TestInstallDaemon_BootsOutAnyPreviousInstance(t *testing.T) {
	var calls []string
	origW, origM, origL := writePlist, mkdirLogDir, runLaunchctl
	t.Cleanup(func() { writePlist, mkdirLogDir, runLaunchctl = origW, origM, origL })
	writePlist = func(string, []byte) error { return nil }
	mkdirLogDir = func() error { return nil }
	runLaunchctl = func(args ...string) (string, error) { calls = append(calls, strings.Join(args, " ")); return "", nil }
	if err := InstallDaemon("/usr/local/bin/counterspy", "/Users/j"); err != nil {
		t.Fatal(err)
	}
	if len(calls) < 2 || !strings.HasPrefix(calls[0], "bootout") || !strings.HasPrefix(calls[1], "bootstrap") {
		t.Fatalf("expected bootout then bootstrap, got %v", calls)
	}
}

// Uninstall is the SELF-HEAL path: nothing loaded and no plist are both success, not errors.
func TestUninstallDaemon_IsIdempotent(t *testing.T) {
	origR, origL := removePlist, runLaunchctl
	t.Cleanup(func() { removePlist, runLaunchctl = origR, origL })
	runLaunchctl = func(...string) (string, error) { return "", errors.New("Boot-out failed: 3: No such process") }
	removePlist = func(string) error { return os.ErrNotExist }
	if err := UninstallDaemon(); err != nil {
		t.Fatalf("uninstalling nothing must succeed: %v", err)
	}
}

// A LaunchDaemon pointing into a build tree or home dir is flagged: it breaks when that tree moves, and
// it is the exact shape counterspy's own persistence collector teaches users to distrust.
func TestUnstableExePath(t *testing.T) {
	for _, bad := range []string{"/Users/jmachen/code/counterspy/counterspy", "/tmp/counterspy"} {
		if !UnstableExePath(bad) {
			t.Fatalf("%q should be flagged as unstable for a root LaunchDaemon", bad)
		}
	}
	if UnstableExePath("/usr/local/bin/counterspy") {
		t.Fatal("/usr/local/bin is a stable location")
	}
}

// A WRAPPED not-exist must also count as idempotent. os.IsNotExist does NOT unwrap %w-wrapped errors,
// so it would report a real failure here; errors.Is does. This is why UninstallDaemon uses errors.Is.
func TestUninstallDaemon_IdempotentOnWrappedNotExist(t *testing.T) {
	origR, origL := removePlist, runLaunchctl
	t.Cleanup(func() { removePlist, runLaunchctl = origR, origL })
	runLaunchctl = func(...string) (string, error) { return "", nil }
	removePlist = func(string) error { return fmt.Errorf("remove plist: %w", os.ErrNotExist) }
	if err := UninstallDaemon(); err != nil {
		t.Fatalf("a wrapped not-exist must still be idempotent: %v", err)
	}
	if os.IsNotExist(fmt.Errorf("x: %w", os.ErrNotExist)) {
		t.Skip("os.IsNotExist now unwraps; the errors.Is choice is moot")
	}
}
