// Package ack is the LOCAL, revisitable triage-decision store: a record that the user has
// reviewed a finding and chosen to "leave it" (issue #4). It is deliberately separate from
// internal/feedback — feedback is an opt-in, shareable, anonymous field report; an ack is a
// private, never-transmitted note that only affects how the Findings view flags a row. Acks are
// never hidden: a decided finding stays visible, flagged with its decision, and is re-flagged
// "reviewed · changed" when the finding's state no longer matches what was reviewed.
package ack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"counterspy/internal/model"
)

// Record is one local decision: the finding's fingerprint at the moment it was acked (so a later
// change is detectable) and when it was recorded.
type Record struct {
	Fingerprint string `json:"fp"`
	At          string `json:"at"`
}

// Store holds the acks keyed by Subject.Key(), backed by a JSON file under the invoking user's home.
type Store struct {
	path string
	recs map[string]Record
}

func NewStore(path string) *Store { return &Store{path: path, recs: map[string]Record{}} }

// Fingerprint is a stable digest of a finding's MATERIAL state: its score plus the sorted set of
// evidence "kind|summary" lines. A change to either — a new signal, a higher score — changes the
// digest, which is what lets the view re-flag a prior ack as "reviewed · changed" instead of
// silently masking newly-surfaced concern. Facts are intentionally excluded: they carry volatile
// detail (PIDs, timestamps) that would make every rescan look "changed".
func Fingerprint(a model.Assessment) string {
	lines := make([]string, 0, len(a.Evidence))
	for _, e := range a.Evidence {
		lines = append(lines, string(e.Kind)+"|"+e.Summary)
	}
	sort.Strings(lines)
	h := sha256.New()
	h.Write([]byte(strconv.Itoa(a.Score)))
	for _, l := range lines {
		h.Write([]byte{0})
		h.Write([]byte(l))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Load reads the store into memory. A missing or empty file is not an error — it is an empty store.
func (s *Store) Load() error {
	s.recs = map[string]Record{}
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, &s.recs)
}

// Get returns the ack record for a subject key, if any.
func (s *Store) Get(key string) (Record, bool) {
	r, ok := s.recs[key]
	return r, ok
}

// Ack upserts a decision for a subject key and persists.
func (s *Store) Ack(key, fingerprint, at string) error {
	s.recs[key] = Record{Fingerprint: fingerprint, At: at}
	return s.save()
}

// Unack removes a decision (revisitable toggle-off) and persists. Absent key is a no-op.
func (s *Store) Unack(key string) error {
	if _, ok := s.recs[key]; !ok {
		return nil
	}
	delete(s.recs, key)
	return s.save()
}

// save atomically rewrites the store: temp file in the same dir, fsync, rename. Mirrors
// internal/feedback's store save (kept local rather than shared to avoid coupling the two stores;
// a small, deliberate duplication of ~15 lines).
func (s *Store) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.recs, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ack-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
