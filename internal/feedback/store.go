package feedback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"counterspy/internal/model"
)

// Store persists labeled records locally (under the invoking user's home) so ask-mode
// review, offline retry, and manual export all work. Records dedupe by fingerprint.
type Store struct{ path string }

type entry struct {
	Record model.FeedbackRecord `json:"record"`
	Sent   bool                 `json:"sent"`
}

func NewStore(path string) *Store { return &Store{path: path} }

// Fingerprint is the stable identity of a finding's anonymous shape (nonce/label excluded)
// so relabeling the same finding updates rather than duplicates.
func Fingerprint(r model.FeedbackRecord) string {
	key := strings.Join([]string{
		r.Recommendation, r.Category, r.ScoreBand,
		strings.Join(r.Signals, ","), r.Codesign, r.PathClass, r.Identity,
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (s *Store) load() ([]entry, error) {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []entry
	if len(b) == 0 {
		return nil, nil
	}
	return es, json.Unmarshal(b, &es)
}

func (s *Store) save(es []entry) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(es, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write: a crash mid-write must not corrupt the store. Write a temp file in the SAME
	// directory (so the rename is atomic, same filesystem), fsync it, then rename over the target.
	// os.CreateTemp already opens the temp at 0600, matching the store's permissions.
	tmp, err := os.CreateTemp(dir, ".store-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename; cleans up every error path
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

// Add upserts a record by fingerprint (relabel wins; a re-added sent record re-opens).
func (s *Store) Add(r model.FeedbackRecord) error {
	es, err := s.load()
	if err != nil {
		return err
	}
	fp := Fingerprint(r)
	for i := range es {
		if Fingerprint(es[i].Record) == fp {
			es[i].Record = r
			es[i].Sent = false
			return s.save(es)
		}
	}
	return s.save(append(es, entry{Record: r}))
}

// Pending returns records not yet marked sent.
func (s *Store) Pending() ([]model.FeedbackRecord, error) {
	es, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []model.FeedbackRecord
	for _, e := range es {
		if !e.Sent {
			out = append(out, e.Record)
		}
	}
	return out, nil
}

// MarkSent flags the given records (by fingerprint) as submitted.
func (s *Store) MarkSent(sent []model.FeedbackRecord) error {
	es, err := s.load()
	if err != nil {
		return err
	}
	mark := map[string]bool{}
	for _, r := range sent {
		mark[Fingerprint(r)] = true
	}
	for i := range es {
		if mark[Fingerprint(es[i].Record)] {
			es[i].Sent = true
		}
	}
	return s.save(es)
}
