// Package act performs the only mutating phase: it isolates flagged items by
// disabling and MOVING them (never deleting) into a quarantine folder that mirrors
// their original path, and can fully restore them from the manifest. The manifest is
// both the undo and the RCA trail (Rule 14).
package act

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"counterspy/internal/model"
	"counterspy/internal/score"
)

// launchctlTimeout bounds the actor's launchctl calls so a wedged launchd can't hang
// a quarantine or restore (ABORT C1).
const launchctlTimeout = 15 * time.Second

// protectedPrefixes are paths CounterSpy refuses to move, even under sudo. SIP already
// blocks /System, but we refuse explicitly so a bug can never even attempt it
// (spec §9 hard refusal; success criterion #5). /Library is intentionally NOT here —
// a malicious /Library/LaunchDaemons item is a legitimate quarantine target.
var protectedPrefixes = []string{"/system/", "/usr/lib/", "/usr/bin/", "/bin/", "/sbin/"}

// isProtected reports whether a path is off-limits. It canonicalizes first
// (filepath.Clean resolves ".." so it can't smuggle a protected path past the check)
// and compares case-insensitively, since macOS's default filesystem is case-insensitive
// (cp-11 Audit F-4 / QA F-4/F-6).
func isProtected(p string) bool {
	c := strings.ToLower(filepath.Clean(p))
	for _, pre := range protectedPrefixes {
		if strings.HasPrefix(c, pre) {
			return true
		}
	}
	return false
}

// refuseUnsafe rejects a move source that is protected, is itself a symlink, or
// resolves (via any symlinked component) into a protected path — closing the
// stat-then-rename TOCTOU window a local attacker could race (ABORT C1).
func refuseUnsafe(p string) error {
	if isProtected(p) {
		return fmt.Errorf("refusing to move protected system path: %s", p)
	}
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to move a symlink (possible TOCTOU): %s", p)
	}
	if real, err := filepath.EvalSymlinks(p); err == nil && isProtected(real) {
		return fmt.Errorf("refusing: %s resolves into a protected path (%s)", p, real)
	}
	return nil
}

// bootout disables a launch item so it can't respawn. Best-effort and swappable in
// tests; "already booted out" is not an error we care about, and the subsequent move
// keeps the item from reloading regardless.
var bootout = func(target string) {
	ctx, cancel := context.WithTimeout(context.Background(), launchctlTimeout)
	defer cancel()
	_ = exec.CommandContext(ctx, "launchctl", "bootout", target).Run()
}

// Quarantine performs a finding's actions in order: disable launch items, then MOVE
// each artifact into root under its original path (collision-proof, provenance-
// preserving), never deleting. It ALWAYS records a manifest for whatever it completed —
// even on a mid-way failure — so a partial quarantine is never an unrecoverable orphan
// (cp-11 Audit F-3). Refuses allowlisted subjects and protected paths (§9 two-clause
// refusal). On the first move failure it stops and returns the partial item + error.
func Quarantine(root, timestamp string, as model.Assessment) (model.ManifestItem, error) {
	f := as.Finding
	if a := allowlistedAuthority(f); a != "" {
		return model.ManifestItem{}, fmt.Errorf("refusing to quarantine %s: trusted signature %q", f.Subject.Key(), a)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return model.ManifestItem{}, err
	}
	item := model.ManifestItem{
		Subject: f.Subject, Evidence: f.Evidence,
		Score: f.Score, Tripwire: f.Tripwire,
		Category: as.Category, Recommendation: as.Recommendation, Verdict: as.Verdict,
	}
	// Always persist what completed, success or failure.
	defer func() { _ = appendManifest(root, timestamp, item) }()

	for _, a := range f.Actions {
		switch a.Kind {
		case model.ActionMove:
			from := filepath.Clean(a.From)
			if err := refuseUnsafe(from); err != nil {
				return item, err
			}
			to := filepath.Join(root, strings.TrimPrefix(from, "/"))
			if _, err := os.Stat(to); err == nil {
				return item, fmt.Errorf("quarantine destination already exists (collision): %s", to)
			}
			if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
				return item, err
			}
			if err := os.Rename(from, to); err != nil {
				return item, fmt.Errorf("move %s: %w", from, err)
			}
			a.From, a.To = from, to
			item.Actions = append(item.Actions, a)
		case model.ActionBootout:
			// bootout operates on a launchd label, not a path; refuse Apple system
			// labels as defense-in-depth (ABORT C1/C2 — the protected-path check can't
			// apply to a non-path target).
			if strings.HasPrefix(a.From, "com.apple.") {
				return item, fmt.Errorf("refusing to bootout an Apple system launch item: %s", a.From)
			}
			bootout(a.From)
			item.Actions = append(item.Actions, a)
		}
	}
	return item, nil
}

func allowlistedAuthority(f model.Finding) string {
	for _, e := range f.Evidence {
		if score.IsAllowlisted(e.Facts["authority"]) {
			return e.Facts["authority"]
		}
	}
	return ""
}

// appendManifest reads the run manifest (if any), appends this item, and writes it
// back. It stamps a UTC timestamp when the caller didn't supply one so the RCA trail
// always records "when" (cp-11 Audit F-5).
func appendManifest(root, timestamp string, item model.ManifestItem) error {
	if len(item.Actions) == 0 {
		return nil // nothing completed → nothing to record
	}
	p := filepath.Join(root, "manifest.json")
	var m model.Manifest
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m.Timestamp == "" {
		if timestamp == "" {
			timestamp = time.Now().UTC().Format(time.RFC3339)
		}
		m.Timestamp = timestamp
	}
	m.ToolVersion = model.Version
	m.Items = append(m.Items, item)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
