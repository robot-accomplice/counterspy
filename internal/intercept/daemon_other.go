//go:build !darwin

package intercept

import "errors"

var errDaemonUnsupported = errors.New("the intercept daemon is only supported on macOS (launchd)")

// InstallDaemon is macOS-only (launchd). The stub keeps cross-platform callers building.
func InstallDaemon(string, string) error { return errDaemonUnsupported }

// UninstallDaemon is macOS-only (launchd).
func UninstallDaemon() error { return errDaemonUnsupported }

// DaemonInstalled is false off darwin; there is no launchd service to find.
func DaemonInstalled() bool { return false }

// DaemonPlistPath has no meaning off darwin.
func DaemonPlistPath() string { return "" }

// UnstableExePath is darwin-only advice; off darwin there is no daemon to point anywhere.
func UnstableExePath(string) bool { return false }

// DaemonFlowLog is unused off darwin but referenced by cross-platform command wiring.
const DaemonFlowLog = ""
