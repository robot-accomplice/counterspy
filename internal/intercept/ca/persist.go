package ca

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CA file names under the persistence dir. The key is sensitive (it mints trusted leaves), so it's
// written 0600 under a 0700 dir.
const (
	certFile = "ca.pem"
	keyFile  = "ca.key"
)

// Load returns the persisted CA under dir WITHOUT minting. found is false when neither file exists
// (nothing was ever created); a partial or unreadable pair is a hard error. Used by the --uninstall
// self-heal, which must not fabricate new key material just to revert (Audit cp-p2f F-4).
func Load(dir string) (c *CA, found bool, err error) {
	certPEM, certErr := os.ReadFile(filepath.Join(dir, certFile))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, keyFile))
	switch {
	case certErr == nil && keyErr == nil:
		c, err = LoadCA(certPEM, keyPEM)
		return c, err == nil, err
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		return nil, false, nil
	case certErr != nil && !os.IsNotExist(certErr):
		return nil, false, certErr // a real read error on the cert (not just absence)
	case keyErr != nil && !os.IsNotExist(keyErr):
		return nil, false, keyErr // a real read error on the key
	default:
		// Exactly one of the pair is present. Fail loud rather than regenerate: a silent regen would
		// orphan the already-trusted root in the keychain (Rule 13).
		return nil, false, fmt.Errorf("ca: incomplete CA in %s (one of %s/%s is missing); refusing to regenerate", dir, certFile, keyFile)
	}
}

// LoadOrCreate returns the persisted intercept CA under dir, creating (and saving) a fresh one if none
// exists, so trust is installed ONCE and the same CA is reused across runs (re-generating would orphan
// the trusted root and re-prompt every launch).
//
// Concurrency-safe: the key file is an exclusive create gate (O_EXCL). If two intercepts start at once,
// exactly one wins the create and persists its pair; the loser re-reads the winner's pair instead of
// orphaning a second trusted root (Audit/Antagonist cp-p2f: the "trust once" invariant under a race).
func LoadOrCreate(dir string) (*CA, error) {
	if c, found, err := Load(dir); err != nil || found {
		return c, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, keyFile)
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadAfterRace(dir) // another process won the create; use its pair
		}
		return nil, err
	}
	// We own the gate. Mint, then write key (into the held fd) and cert.
	c, err := NewCA()
	if err != nil {
		kf.Close()
		os.Remove(keyPath)
		return nil, err
	}
	cp, kp, err := c.PEM()
	if err != nil {
		kf.Close()
		os.Remove(keyPath)
		return nil, err
	}
	if _, err := kf.Write(kp); err != nil {
		kf.Close()
		os.Remove(keyPath)
		return nil, err
	}
	if err := kf.Close(); err != nil {
		os.Remove(keyPath)
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), cp, 0o600); err != nil {
		os.Remove(keyPath) // don't leave a key without its cert (a partial pair)
		return nil, err
	}
	return c, nil
}

// loadAfterRace re-reads the pair the race winner is writing. The winner creates the key gate, then
// writes the key and the cert, so the cert may lag briefly; retry a bounded window before giving up.
func loadAfterRace(dir string) (*CA, error) {
	var lastErr error
	for i := 0; i < 100; i++ {
		c, found, err := Load(dir)
		if err == nil && found {
			return c, nil
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ca: raced CA creation in %s did not settle", dir)
	}
	return nil, lastErr
}
