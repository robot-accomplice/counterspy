package ca

import (
	"fmt"
	"os"
	"path/filepath"
)

// CA file names under the persistence dir. The key is sensitive (it mints trusted leaves), so it's
// written 0600 under a 0700 dir.
const (
	certFile = "ca.pem"
	keyFile  = "ca.key"
)

// LoadOrCreate returns the persisted intercept CA under dir, creating (and saving) a fresh one if none
// exists yet — so trust is installed ONCE and the same CA is reused across runs (re-generating would
// orphan the trusted root and re-prompt every launch). A partially-present or unreadable pair is a hard
// error (fail loud, Rule 13): silently regenerating would leave a stale trusted root in the keychain.
func LoadOrCreate(dir string) (*CA, error) {
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		return LoadCA(certPEM, keyPEM)
	case certErr != nil && !os.IsNotExist(certErr):
		return nil, certErr // a real read error on the cert (not just absence)
	case keyErr != nil && !os.IsNotExist(keyErr):
		return nil, keyErr // a real read error on the key
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		// Neither present — fall through to mint + persist a fresh CA.
	default:
		// Exactly one of the pair is present. Fail loud rather than regenerate: a silent regen would
		// orphan the already-trusted root in the keychain (Rule 13).
		return nil, fmt.Errorf("ca: incomplete CA in %s (one of %s/%s is missing); refusing to regenerate", dir, certFile, keyFile)
	}
	// Neither present — mint and persist a fresh CA.
	c, err := NewCA()
	if err != nil {
		return nil, err
	}
	cp, kp, err := c.PEM()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, cp, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, kp, 0o600); err != nil {
		return nil, err
	}
	return c, nil
}
