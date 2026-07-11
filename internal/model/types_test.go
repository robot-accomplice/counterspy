package model

import (
	"strings"
	"testing"
)

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

func TestClean(t *testing.T) {
	const (
		rtlo      = rune(0x202e) // right-to-left override (bidi spoofing)
		zeroWidth = rune(0x200b) // zero-width space
		bom       = rune(0xfeff) // byte order mark / zero-width no-break space
	)
	cases := []struct {
		name     string
		in       string
		want     string
		stripped []rune
	}{
		{"esc_and_control", "\x1b[31mred", "[31mred", []rune{0x1b}},
		{"bidi_rtlo", "a" + string(rtlo) + "b", "ab", []rune{rtlo}},
		{"zero_width", "a" + string(zeroWidth) + "b", "ab", []rune{zeroWidth}},
		{"bom", "a" + string(bom) + "b", "ab", []rune{bom}},
		{"tab_to_space", "a\tb", "a b", nil},
		{"normal_passthrough", "normal text 123", "normal text 123", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Clean(c.in)
			if got != c.want {
				t.Fatalf("Clean(%q) = %q, want %q", c.in, got, c.want)
			}
			for _, r := range c.stripped {
				if strings.ContainsRune(got, r) {
					t.Fatalf("Clean(%q) = %q still contains stripped rune %U", c.in, got, r)
				}
			}
		})
	}
}

func TestSubjectDisplay(t *testing.T) {
	cases := []struct {
		name string
		s    Subject
		want string
	}{
		{"label_wins", Subject{Label: "Chrome", Path: "/Applications/Chrome.app", PID: 5}, "Chrome"},
		{"path_wins_no_label", Subject{Path: "/usr/bin/foo", PID: 5}, "/usr/bin/foo"},
		{"falls_back_to_key", Subject{PID: 42}, "pid:42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.s.Display(); got != c.want {
				t.Fatalf("Display() = %q, want %q", got, c.want)
			}
		})
	}
}
