// Package act performs the only mutating phase: it isolates flagged items by
// disabling and MOVING them (never deleting) into a timestamped quarantine folder,
// and can fully restore them from the manifest. The manifest is both the undo and
// the RCA trail (Rule 14).
package act

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"counterspy/internal/model"
)

// protectedPrefixes are paths CounterSpy refuses to move, even under sudo.
// Belt-and-suspenders: SIP already blocks /System, but we refuse explicitly so a
// bug can never even attempt it (spec §9 hard refusal; success criterion #5).
var protectedPrefixes = []string{"/System/", "/usr/lib/", "/usr/bin/", "/bin/", "/sbin/"}

func isProtected(p string) bool {
	for _, pre := range protectedPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// bootout disables a launch item so it can't respawn. Best-effort and swappable in
// tests; "already booted out" is not an error we care about.
var bootout = func(target string) { _ = exec.Command("launchctl", "bootout", target).Run() }

// Quarantine performs a finding's actions in order: disable launch items, then MOVE
// each artifact under quarantineRoot (base name preserved). It returns the manifest
// item with To paths filled. On the first move failure it stops and returns the
// partial item + error — the caller reports partial state rather than pretending success.
func Quarantine(quarantineRoot string, f model.Finding) (model.ManifestItem, error) {
	if err := os.MkdirAll(quarantineRoot, 0o755); err != nil {
		return model.ManifestItem{}, err
	}
	item := model.ManifestItem{Subject: f.Subject, Evidence: f.Evidence}
	for _, a := range f.Actions {
		switch a.Kind {
		case model.ActionMove:
			if isProtected(a.From) {
				return item, fmt.Errorf("refusing to move protected system path: %s", a.From)
			}
			to := filepath.Join(quarantineRoot, filepath.Base(a.From))
			if err := os.Rename(a.From, to); err != nil {
				return item, fmt.Errorf("move %s: %w", a.From, err)
			}
			a.To = to
			item.Actions = append(item.Actions, a)
		case model.ActionBootout:
			bootout(a.From)
			item.Actions = append(item.Actions, a)
		default:
			item.Actions = append(item.Actions, a)
		}
	}
	return item, nil
}

// WriteManifest persists the manifest JSON (undo + RCA trail) and returns its path.
func WriteManifest(dir string, m model.Manifest) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "manifest.json")
	return p, os.WriteFile(p, b, 0o644)
}
