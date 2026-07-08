package act

import (
	"encoding/json"
	"os"

	"counterspy/internal/model"
)

// Restore reverses a quarantine from its manifest: every moved artifact goes back
// To → From. (The launch item reloads on next login; we do not re-bootstrap it here.)
func Restore(manifestPath string) error {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m model.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for _, item := range m.Items {
		for _, a := range item.Actions {
			if a.Kind == model.ActionMove && a.To != "" {
				if err := os.Rename(a.To, a.From); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
