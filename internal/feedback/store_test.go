package feedback

import (
	"os"
	"path/filepath"
	"testing"

	"counterspy/internal/model"
)

// save() writes atomically (temp + rename): the store round-trips, no .tmp files are left behind,
// and the file keeps 0600, so a crash mid-write can't corrupt or expose the store.
func TestStore_SaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "feedback.json"))
	if err := s.Add(rec(model.LabelTruePositive, "backdoor", "10-14")); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(rec(model.LabelFalsePositive, "keylogger", "15+")); err != nil {
		t.Fatal(err)
	}
	// Round-trips through a fresh Store.
	if p, err := NewStore(filepath.Join(dir, "feedback.json")).Pending(); err != nil || len(p) != 2 {
		t.Fatalf("store must round-trip 2 records, got %d (%v)", len(p), err)
	}
	// No temp files left behind, and the store is 0600.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" || len(e.Name()) > 4 && e.Name()[:6] == ".store" {
			t.Fatalf("atomic save left a temp file behind: %s", e.Name())
		}
	}
	fi, err := os.Stat(filepath.Join(dir, "feedback.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("store must be 0600, got %o", fi.Mode().Perm())
	}
}

func rec(label, cat, band string) model.FeedbackRecord {
	return model.FeedbackRecord{Schema: "1", Label: label, Category: cat, ScoreBand: band,
		Signals: []string{"persistence"}, Codesign: "unsigned", PathClass: "hidden", Nonce: "x"}
}

func TestStore_AddDedupesByFingerprint(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "feedback.json"))
	if err := s.Add(rec(model.LabelTruePositive, "backdoor", "10-14")); err != nil {
		t.Fatal(err)
	}
	// Same fingerprint, relabeled → updates in place, does not duplicate.
	if err := s.Add(rec(model.LabelFalsePositive, "backdoor", "10-14")); err != nil {
		t.Fatal(err)
	}
	p, err := s.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 {
		t.Fatalf("expected 1 deduped record, got %d", len(p))
	}
	if p[0].Label != model.LabelFalsePositive {
		t.Fatalf("relabel should win, got %q", p[0].Label)
	}
	// A different fingerprint is a separate record.
	if err := s.Add(rec(model.LabelTruePositive, "keylogger", "15+")); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Pending(); len(p) != 2 {
		t.Fatalf("expected 2 records, got %d", len(p))
	}
}

func TestStore_MarkSentClearsPending(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "feedback.json"))
	r := rec(model.LabelFalsePositive, "backdoor", "10-14")
	_ = s.Add(r)
	if err := s.MarkSent([]model.FeedbackRecord{r}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Pending(); len(p) != 0 {
		t.Fatalf("expected 0 pending after MarkSent, got %d", len(p))
	}
}
