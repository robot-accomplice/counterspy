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
	_ = exec.CommandContext(ctx, "launchctl", "bootstrap", domain, plist).Run()
}

// Restore reverses a quarantine from its manifest: every moved artifact goes back
// To → From. It NEVER clobbers: if something already occupies From (e.g. the malware
// respawned there, or the user recreated the file), that item is skipped and reported
// rather than silently overwritten (cp-11 QA F-2). Missing quarantined files are
// likewise skipped-and-reported instead of halting the whole restore (cp-11 QA F-3).
// It restores everything it safely can, then returns an aggregated error if any item
// could not be restored.
func Restore(manifestPath string) error {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m model.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	var problems []error
	for _, item := range m.Items {
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
	}
	if len(problems) > 0 {
		return fmt.Errorf("restore finished with %d issue(s): %w", len(problems), errors.Join(problems...))
	}
	return nil
}
