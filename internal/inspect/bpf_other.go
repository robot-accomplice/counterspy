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
