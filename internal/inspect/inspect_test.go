package inspect

import (
	"net/netip"
	"strings"
	"testing"
)

func flowTo(remote string) (Flow, netip.AddrPort) {
	r := netip.MustParseAddrPort(remote)
	return Flow{PID: 1, Remote: r}, netip.MustParseAddrPort("10.0.0.2:50000")
}

// A TLS flow: the interceptor reports SNI + an honest ENCRYPTED/metadata-only verdict.
func TestInspect_TLSFlowMetadataAndSNI(t *testing.T) {
	flow, local := flowTo("93.184.216.34:443")
	src := &fixtureSource{packets: [][]byte{
		ipv4TCP(local, flow.Remote, buildClientHello("api.evil.example.com")),
	}}
	r := Inspect(src, flow, 20)
	if r.Coverage != CoverageMetadata || r.SNI != "api.evil.example.com" {
		t.Fatalf("want metadata+SNI, got coverage=%d sni=%q", r.Coverage, r.SNI)
	}
	if !strings.Contains(r.Verdict, "ENCRYPTED") || !strings.Contains(r.Verdict, "api.evil.example.com") {
		t.Fatalf("verdict should name the encryption + SNI: %q", r.Verdict)
	}
	if len(r.Payload) != 0 {
		t.Fatal("metadata tier must not expose payload for an encrypted flow")
	}
}

// A plaintext (HTTP) flow: the interceptor surfaces the readable payload.
func TestInspect_PlaintextFlowShowsPayload(t *testing.T) {
	flow, local := flowTo("1.2.3.4:80")
	body := []byte("POST /upload HTTP/1.1\r\nHost: drop.example\r\n\r\nsecret=hunter2")
	src := &fixtureSource{packets: [][]byte{ipv4TCP(local, flow.Remote, body)}}
	r := Inspect(src, flow, 20)
	if r.Coverage != CoveragePlaintext || !strings.Contains(string(r.Payload), "secret=hunter2") {
		t.Fatalf("want plaintext payload, got coverage=%d payload=%q", r.Coverage, r.Payload)
	}
	if !strings.Contains(r.Verdict, "plaintext") {
		t.Fatalf("verdict should say plaintext: %q", r.Verdict)
	}
}

// Packets to a different remote (or none) → nothing captured for this flow.
func TestInspect_NoMatchingTraffic(t *testing.T) {
	flow, local := flowTo("9.9.9.9:443")
	other := netip.MustParseAddrPort("8.8.8.8:443")
	src := &fixtureSource{packets: [][]byte{ipv4TCP(local, other, []byte("GET / HTTP/1.1\r\n"))}}
	r := Inspect(src, flow, 20)
	if r.Coverage != CoverageNone || r.Verdict != "no application data captured" {
		t.Fatalf("want none/no-data, got coverage=%d verdict=%q", r.Coverage, r.Verdict)
	}
}
