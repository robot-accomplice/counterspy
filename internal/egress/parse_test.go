package egress

import (
	"os"
	"testing"
)

func TestParseNettop(t *testing.T) {
	b, _ := os.ReadFile("testdata/nettop.csv")
	m := ParseNettop(b)
	if got := m[12345]; got.Out != 5242880 || got.In != 1048576 {
		t.Fatalf("pid 12345 = %+v, want Out 5242880 In 1048576", got)
	}
	if m[4821].Out != 860160 {
		t.Fatalf("pid 4821 Out = %d, want 860160", m[4821].Out)
	}
}

func TestParseLsofConns_EstablishedOnly(t *testing.T) {
	b, _ := os.ReadFile("testdata/lsof.txt")
	m := ParseLsofConns(b)
	if len(m[12345]) != 1 || m[12345][0].Endpoint.IP != "17.253.144.10" || m[12345][0].Endpoint.Port != 443 || m[12345][0].Proto != "tcp" {
		t.Fatalf("pid 12345 conns wrong: %+v", m[12345])
	}
	if len(m[4821]) != 2 {
		t.Fatalf("pid 4821 should have 2 conns (tcp+udp), got %d", len(m[4821]))
	}
	if _, ok := m[1]; ok {
		t.Fatal("a LISTEN socket (no ->remote) must be skipped, not counted as egress")
	}
}

func TestParsePidPaths_SpacedPathsIntact(t *testing.T) {
	in := []byte("  5210 /Users/analyst/Library/Application Support/Claude/claude.app/Contents/MacOS/claude\n" +
		"  100 /usr/sbin/cupsd\n" +
		"garbage-no-space\n")
	m := ParsePidPaths(in)
	if m[5210] != "/Users/analyst/Library/Application Support/Claude/claude.app/Contents/MacOS/claude" {
		t.Fatalf("spaced path must stay whole, got %q", m[5210])
	}
	if m[100] != "/usr/sbin/cupsd" {
		t.Fatalf("plain path wrong, got %q", m[100])
	}
	if len(m) != 2 {
		t.Fatalf("malformed line must be skipped; got %d entries: %v", len(m), m)
	}
}
