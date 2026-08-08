//go:build darwin

package ca

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// systemKeychain is where a root daemon's trusted roots live; passing it explicitly avoids relying on
// an ambient "default keychain" that is undefined for a headless process (Audit cp-p2b F-3).
const systemKeychain = "/Library/Keychains/System.keychain"

// securityBin is absolute for the same reason the keychain is named explicitly: a root daemon must
// resolve nothing about its own execution from ambient state. A writable PATH entry would otherwise
// substitute the tool that installs a trusted root (go:S4036).
const securityBin = "/usr/bin/security"

// securityTimeout bounds the `security` call so a GUI authorization prompt (e.g. under MDM/TCC policy)
// can't hang the background daemon forever (Audit cp-p2b F-4).
const securityTimeout = 20 * time.Second

// runSecurity is the seam over the macOS `security` CLI, so trust install/uninstall is unit-testable
// (a fake captures the args) without touching the real keychain. The default captures the tool's
// diagnostic output into the error so a failure is actionable, and so the self-heal path can tell a
// "cert not found" removal from a real failure (Audit cp-p2b F-2). Fail loud (Rule 13).
var runSecurity = func(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), securityTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, securityBin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("security %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
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
// coverage: native apps and daemons, not just login-keychain ones. Consent is the caller's job.
// Reversible via UninstallTrust / `intercept --uninstall`.
func InstallTrust(certPEM []byte) error {
	path, cleanup, err := writeTempCert(certPEM)
	if err != nil {
		return err
	}
	defer cleanup()
	// -p ssl restricts trust to TLS ONLY; a local intercept CA must not become a trusted code-signing
	// / S-MIME / IPsec anchor (Audit cp-p2b F-1). -k targets the System keychain explicitly (F-3).
	if err := runSecurity("add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl", "-k", systemKeychain, path); err != nil {
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
