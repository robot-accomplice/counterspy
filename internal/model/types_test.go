package model

import "testing"

func TestSubjectKey_PrefersPath(t *testing.T) {
	s := Subject{Path: "/tmp/evil", PID: 42}
	if got := s.Key(); got != "path:/tmp/evil" {
		t.Fatalf("want path key, got %q", got)
	}
}

func TestSubjectKey_FallsBackToPID(t *testing.T) {
	s := Subject{PID: 42}
	if got := s.Key(); got != "pid:42" {
		t.Fatalf("want pid key, got %q", got)
	}
}

// Regression for cp-1 QA F-1 / Audit F-1: a path literally equal to a PID-formatted
// string must not alias the corresponding PID subject in the scorer's group-by-Key.
func TestSubjectKey_NoCollisionPathVsPID(t *testing.T) {
	pathLike := Subject{Path: "pid:42"}
	pidOnly := Subject{PID: 42}
	if pathLike.Key() == pidOnly.Key() {
		t.Fatalf("path %q must not collide with pid 42 (both %q)", pathLike.Path, pidOnly.Key())
	}
}
