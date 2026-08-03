package act

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"counterspy/internal/model"
)

// rebootstrap re-registers a restored launch item with launchd so a booted-out job
// actually comes back to life, not just its files on disk (ABORT C2). Best-effort:
// launchd also auto-loads user LaunchAgents at next login. Swappable in tests.
var rebootstrap = func(plist string) {
	domain := "gui/" + strconv.Itoa(os.Getuid())
	if strings.Contains(plist, "/LaunchDaemons/") {
		domain = "system"
	}
	ctx, cancel := context.WithTimeout(context.Background(), launchctlTimeout)
	defer cancel()
	_ = exec.CommandContext(ctx, launchctlBin, "bootstrap", domain, plist).Run()
}

// Restore reverses a quarantine from its manifest: every moved artifact goes back
// To → From. It NEVER clobbers: if something already occupies From (e.g. the malware
// respawned there, or the user recreated the file), that item is skipped and reported
// rather than silently overwritten (cp-11 QA F-2). Missing quarantined files are
// likewise skipped-and-reported instead of halting the whole restore (cp-11 QA F-3).
// It restores everything it safely can, then returns an aggregated error if any item
// could not be restored.
func Restore(manifestPath string) error {
	m, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	var problems []error
	for _, item := range m.Items {
		problems = append(problems, restoreItem(item)...)
	}
	if len(problems) > 0 {
		return fmt.Errorf("restore finished with %d issue(s): %w", len(problems), errors.Join(problems...))
	}
	return nil
}

// RestoreItem reverses ONE quarantined item from the manifest, identified by its Subject.Key(), and
// drops it from the manifest on full success — so the TUI can undo a single finding rather than the
// whole session (#8). A partial restore keeps the item recorded so its remaining artifacts stay
// recoverable (no orphaned quarantine).
func RestoreItem(manifestPath, subjectKey string) error {
	m, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	idx := -1
	for i := range m.Items {
		if m.Items[i].Subject.Key() == subjectKey {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("no quarantined item for %s in this session's manifest", subjectKey)
	}
	problems := restoreItem(m.Items[idx])
	if len(problems) == 0 {
		m.Items = append(m.Items[:idx], m.Items[idx+1:]...)
		if err := saveManifest(manifestPath, m); err != nil {
			problems = append(problems, err)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("restore of %s finished with %d issue(s): %w", subjectKey, len(problems), errors.Join(problems...))
	}
	return nil
}

// restoreItem reverses one item's actions (moves back To→From, then re-enables any booted-out launch
// item) and returns any per-artifact problems. It NEVER clobbers: if something already occupies From
// (malware respawned, user recreated it) that artifact is skipped-and-reported, not overwritten
// (cp-11 QA F-2); a missing quarantined file is likewise skipped-and-reported (cp-11 QA F-3).
func restoreItem(item model.ManifestItem) []error {
	var problems []error
	hadBootout := false
	var restoredPlists []string
	for _, a := range item.Actions {
		if a.Kind == model.ActionBootout {
			hadBootout = true
			continue
		}
		if a.Kind != model.ActionMove || a.To == "" {
			continue
		}
		from := filepath.Clean(a.From)
		if err := safeDest(from); err != nil {
			problems = append(problems, err)
			continue
		}
		if _, err := os.Stat(a.To); err != nil {
			problems = append(problems, fmt.Errorf("quarantined file missing, cannot restore %s", from))
			continue
		}
		if _, err := os.Stat(from); err == nil {
			problems = append(problems, fmt.Errorf("refusing to overwrite existing file at %s", from))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(from), 0o755); err != nil {
			problems = append(problems, err)
			continue
		}
		if err := os.Rename(a.To, from); err != nil {
			problems = append(problems, err)
			continue
		}
		if strings.HasSuffix(from, ".plist") {
			restoredPlists = append(restoredPlists, from)
		}
	}
	// Re-enable a disabled launch item so restore is a true reversal, not just
	// files-back-on-disk (ABORT C2).
	if hadBootout {
		for _, pl := range restoredPlists {
			rebootstrap(pl)
		}
	}
	return problems
}

func loadManifest(manifestPath string) (model.Manifest, error) {
	var m model.Manifest
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

func saveManifest(manifestPath string, m model.Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath, b, 0o600)
}
