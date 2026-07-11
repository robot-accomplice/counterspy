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
