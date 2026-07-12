//go:build !darwin

package inspect

import "errors"

// openLiveCapture is macOS-only (BPF). On other platforms inspection capture is unavailable.
func openLiveCapture(string) (PacketSource, error) {
	return nil, errors.New("packet capture is only supported on macOS")
}
