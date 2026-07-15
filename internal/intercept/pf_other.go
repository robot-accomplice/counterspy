//go:build !darwin

package intercept

import (
	"errors"
	"net"
	"net/netip"
)

// errPfUnsupported keeps the message identical across the two refusing stubs.
var errPfUnsupported = errors.New("transparent pf redirect is only supported on macOS")

// InstallRedirect is macOS-only (pf). The stub keeps cross-platform callers (the `intercept` command
// wiring in main) building; the redirect is simply unavailable off darwin.
func InstallRedirect(int, []netip.Addr) (func() error, error) {
	return nil, errPfUnsupported
}

// OrigDest is macOS-only (DIOCNATLOOK). Off darwin there is no pf state table to consult.
func OrigDest(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errPfUnsupported
}
