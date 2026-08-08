//go:build !darwin

package intercept

import "errors"

// InstallProxy is macOS-only (networksetup). The stub keeps cross-platform callers (the `intercept`
// command wiring in main) building; system-proxy registration is unavailable off darwin.
func InstallProxy(int) (func() error, error) {
	return nil, errors.New("system proxy registration is only supported on macOS")
}
