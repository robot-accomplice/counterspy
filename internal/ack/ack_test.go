package ack

import (
	"os"
	"path/filepath"
	"testing"

	"counterspy/internal/model"
)

func mk(score int, ev ...model.Evidence) model.Assessment {
	return model.Assessment{Finding: model.Finding{Subject: model.Subject{Path: "/x"}, Score: score, Evidence: ev}}
}

func e(kind model.SignalKind, summary string) model.Evidence {
	return model.Evidence{Kind: kind, Summary: summary, Facts: map[string]string{"pid": "42"}}
}

// Fingerprint is stable across identical material state and across volatile Facts (a rescan with a
// new PID must NOT read as "changed"), but changes when the score or an evidence line changes — that
// is what drives the "reviewed · changed" re-flag.
func TestFingerprint_StableAndChangeSensitive(t *testing.T) {
	a := mk(10, e(model.KindPersistence, "user LaunchAgent"), e(model.KindCodesign, "unsigned"))
	b := mk(10, e(model.KindCodesign, "unsigned"), e(model.KindPersistence, "user LaunchAgent")) // reordered + new pid fact
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("fingerprint must be order- and Facts-independent")
	}
	if Fingerprint(a) == Fingerprint(mk(11, e(model.KindPersistence, "user LaunchAgent"), e(model.KindCodesign, "unsigned"))) {
		t.Fatal("a score change must change the fingerprint")
	}
	if Fingerprint(a) == Fingerprint(mk(10, e(model.KindPersistence, "user LaunchAgent"), e(model.KindCodesign, "unsigned"), e(model.KindProcess, "listener"))) {
		t.Fatal("a new evidence line must change the fingerprint")
	}
}

// Ack/Unack round-trip through the file, and a reloaded store sees the same decision.
func TestStore_AckUnackRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "ack.json") // sub dir must be created by save
	s := NewStore(path)
	if err := s.Load(); err != nil {
		t.Fatalf("load of missing file must be clean: %v", err)
	}
	if _, ok := s.Get("path:/x"); ok {
		t.Fatal("empty store should have no records")
	}
	if err := s.Ack("path:/x", "abc123", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	reload := NewStore(path)
	if err := reload.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	r, ok := reload.Get("path:/x")
	if !ok || r.Fingerprint != "abc123" {
		t.Fatalf("ack did not persist: %+v ok=%v", r, ok)
	}

	if err := reload.Unack("path:/x"); err != nil {
		t.Fatalf("unack: %v", err)
	}
	final := NewStore(path)
	_ = final.Load()
	if _, ok := final.Get("path:/x"); ok {
		t.Fatal("unack must remove the record and persist the removal")
	}
	if err := final.Unack("path:/x"); err != nil {
		t.Fatalf("unack of absent key must be a no-op, got %v", err)
	}
}

// Load tolerates an empty file (empty store) and reports a corrupt one (Rule 13 — a garbled local
// note file surfaces as an error to the caller, which degrades to "no acks", never a silent panic).
func TestStore_LoadEmptyAndCorrupt(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(empty).Load(); err != nil {
		t.Fatalf("empty file must load as an empty store, got %v", err)
	}

	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(corrupt)
	if err := s.Load(); err == nil {
		t.Fatal("a corrupt store must report an error")
	}
	if _, ok := s.Get("anything"); ok {
		t.Fatal("a failed load must leave an empty store, not stale data")
	}
}
