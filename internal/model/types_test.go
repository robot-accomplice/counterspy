package model

import "testing"

func TestSubjectKey_PrefersPath(t *testing.T) {
	s := Subject{Path: "/tmp/evil", PID: 42}
	if got := s.Key(); got != "/tmp/evil" {
		t.Fatalf("want path key, got %q", got)
	}
}

func TestSubjectKey_FallsBackToPID(t *testing.T) {
	s := Subject{PID: 42}
	if got := s.Key(); got != "pid:42" {
		t.Fatalf("want pid key, got %q", got)
	}
}
