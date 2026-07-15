//go:build !darwin

package ca

import "errors"

// Trust management is macOS-only (the `security` keychain). On other platforms interception is
// unavailable; these stubs keep cross-platform builds green (mirrors bpf_other.go).
func InstallTrust([]byte) error   { return errors.New("CA trust install is only supported on macOS") }
func UninstallTrust([]byte) error { return errors.New("CA trust removal is only supported on macOS") }
