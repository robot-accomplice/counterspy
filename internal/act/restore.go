package act

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"counterspy/internal/model"
)

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
		for _, a := range item.Actions {
			if a.Kind != model.ActionMove || a.To == "" {
				continue
			}
			from := filepath.Clean(a.From)
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
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("restore finished with %d issue(s): %w", len(problems), errors.Join(problems...))
	}
	return nil
}
