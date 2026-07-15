//go:build !darwin

package inspect

import (
	"errors"
	"net/netip"
	"time"
)

// OpenLiveCapture is macOS-only (BPF). On other platforms inspection capture is unavailable.
func OpenLiveCapture(string, netip.AddrPort, time.Duration) (PacketSource, error) {
	return nil, errors.New("packet capture is only supported on macOS")
}

// OpenPortCapture is macOS-only (BPF). The stub keeps cross-platform callers (e.g. the console
// wiring in main) building on other platforms; passive name resolution is simply unavailable there
// (Audit cp-p1d F-1).
func OpenPortCapture(string, int) (PacketSource, error) {
	return nil, errors.New("packet capture is only supported on macOS")
}
