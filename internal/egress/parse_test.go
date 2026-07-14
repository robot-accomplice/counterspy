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

func TestParseNettopConns(t *testing.T) {
	// Hierarchical nettop output (no -P): a process row sets the PID; the connection
	// sub-rows under it carry per-connection bytes. Remote *:* rows and pre-process rows
	// are skipped.
	out := []byte("" +
		",bytes_in,bytes_out,\n" +
		"tcp4 1.2.3.4:5<->6.7.8.9:443,10,20,\n" + // before any process row → skipped
		"syslogd.366,0,33186,\n" +
		"udp4 *:52103<->*:*,0,33186,\n" + // remote *:* → no real endpoint → skipped
		"apsd.372,147092,177383,\n" +
		"tcp4 172.20.10.13:59117<->17.57.146.57:5223,147092,177383,\n" +
		"mDNSResponder.476,148745,115279,\n" +
		"quic4 172.20.10.13:51829<->172.224.55.5:443,84199,55590,\n")

	got := ParseNettopConns(out)

	if b := got[connKey(372, "17.57.146.57", 5223)]; b.Out != 177383 {
		t.Errorf("apsd conn out: got %d want 177383 (%v)", b.Out, got)
	}
	if b := got[connKey(476, "172.224.55.5", 443)]; b.Out != 55590 {
		t.Errorf("mDNSResponder conn out: got %d want 55590", b.Out)
	}
	if _, ok := got[connKey(0, "6.7.8.9", 443)]; ok {
		t.Error("a connection row before any process row must be skipped")
	}
	if len(got) != 2 {
		t.Errorf("want 2 real connections, got %d: %v", len(got), got)
	}
}

func TestParseNettopEndpoint_V4andV6(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"17.57.146.57:5223", "17.57.146.57", 5223},                                 // IPv4
		{"fe80::80b9:89ff:fec1:3064%en0.61275", "fe80::80b9:89ff:fec1:3064", 61275}, // IPv6 + zone, dot-port
		{"::1.8021", "::1", 8021},                                                   // IPv6 loopback, no zone
		{"*:*", "", 0},                                                              // listener → no endpoint
	}
	for _, c := range cases {
		ip, port := parseNettopEndpoint(c.in)
		if ip != c.ip || port != c.port {
			t.Errorf("parseNettopEndpoint(%q) = (%q,%d), want (%q,%d)", c.in, ip, port, c.ip, c.port)
		}
	}
}

// The Audit-confirmed bug: nettop's zoned IPv6 and lsof's bracketed IPv6 must produce the SAME
// connKey so per-connection rates correlate (were silently 0 before net/netip canonicalization).
func TestConnKey_IPv6NettopMatchesLsof(t *testing.T) {
	nettopIP, _ := parseNettopEndpoint("fe80::80b9:89ff:fec1:3064%en0.61275")
	lsofKey := connKey(632, "[fe80::80b9:89ff:fec1:3064]", 61275) // lsof spells it bracketed
	nettopKey := connKey(632, nettopIP, 61275)
	if lsofKey != nettopKey {
		t.Fatalf("IPv6 keys must match: lsof=%q nettop=%q", lsofKey, nettopKey)
	}
}

// Multiple FDs from one process to the SAME remote endpoint collapse to a single connection
// (per-destination), so the tree shows one row, not duplicates sharing one aggregated rate.
func TestParseLsofConns_DedupsSameRemote(t *testing.T) {
	lsof := []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" +
		"app 500 u 10u IPv4 0x1 0t0 TCP 10.0.0.2:5->9.9.9.9:443 (ESTABLISHED)\n" +
		"app 500 u 11u IPv4 0x2 0t0 TCP 10.0.0.3:6->9.9.9.9:443 (ESTABLISHED)\n" + // same remote, diff local
		"app 500 u 12u IPv4 0x3 0t0 TCP 10.0.0.4:7->8.8.8.8:53 (ESTABLISHED)\n") // different remote
	got := ParseLsofConns(lsof)
	if len(got[500]) != 2 {
		t.Fatalf("expected 2 distinct destinations (9.9.9.9:443, 8.8.8.8:53), got %d: %+v", len(got[500]), got[500])
	}
}

func TestCanonIP_Forms(t *testing.T) {
	cases := map[string]string{
		"172.20.10.13":     "172.20.10.13",    // IPv4 unchanged
		"[fe80::1]":        "fe80::1",         // lsof brackets stripped
		"fe80::80b9%en0":   "fe80::80b9",      // nettop %zone stripped
		"[fe80::80b9%en0]": "fe80::80b9",      // both
		"api.example.com":  "api.example.com", // non-IP (hostname) passes through
		"":                 "",
	}
	for in, want := range cases {
		if got := canonIP(in); got != want {
			t.Errorf("canonIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNettopEndpoint_Malformed(t *testing.T) {
	for _, in := range []string{
		"*:*",            // listener (handled)
		"noendpointhere", // no dot, not addr:port
		"1.2.3",          // dot but "1.2" isn't a valid addr
		"host.notaport",  // dot, non-numeric port
	} {
		if ip, port := parseNettopEndpoint(in); ip != "" || port != 0 {
			t.Errorf("parseNettopEndpoint(%q) = (%q,%d), want empty", in, ip, port)
		}
	}
}
