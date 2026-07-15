//go:build darwin

package ca

import (
	"fmt"
	"os"
	"os/exec"
)

// runSecurity is the seam over the macOS `security` CLI, so trust install/uninstall is unit-testable
// (a fake captures the args) without touching the real keychain. Default = exec.
var runSecurity = func(args ...string) error {
	return exec.Command("security", args...).Run()
}

// writeTempCert writes certPEM to a private temp file and returns its path + a cleanup func.
func writeTempCert(certPEM []byte) (string, func(), error) {
	f, err := os.CreateTemp("", "counterspy-ca-*.pem")
	if err != nil {
		return "", nil, err
	}
	if _, err := f.Write(certPEM); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", nil, err
	}
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// InstallTrust adds the CA as a trusted root so the host's apps accept the proxy's minted leaves.
// `-d` targets the admin/System trust domain (root, which `intercept` already holds) for broad
// coverage — native apps and daemons, not just login-keychain ones. Consent is the caller's job.
// Reversible via UninstallTrust / `intercept --uninstall`.
func InstallTrust(certPEM []byte) error {
	path, cleanup, err := writeTempCert(certPEM)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := runSecurity("add-trusted-cert", "-d", "-r", "trustRoot", path); err != nil {
		return fmt.Errorf("install CA trust: %w", err)
	}
	return nil
}

// UninstallTrust removes the CA from the trust store. Idempotent-ish: a not-found removal is not a
// hard failure for the caller's self-heal path (the caller decides), but the raw error is returned
// so a real failure is visible (fail loud).
func UninstallTrust(certPEM []byte) error {
	path, cleanup, err := writeTempCert(certPEM)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := runSecurity("remove-trusted-cert", "-d", path); err != nil {
		return fmt.Errorf("remove CA trust: %w", err)
	}
	return nil
}
