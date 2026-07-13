package inspect

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func flowTo(remote string) (Flow, netip.AddrPort) {
	r := netip.MustParseAddrPort(remote)
	return Flow{PID: 1, Remote: r}, netip.MustParseAddrPort("10.0.0.2:50000")
}

// errSource yields the given packets, then a non-EOF error (a real capture failure, not clean end).
type errSource struct {
	packets [][]byte
	err     error
	i       int
}

func (s *errSource) Next() ([]byte, error) {
	if s.i < len(s.packets) {
		p := s.packets[s.i]
		s.i++
		return p, nil
	}
	return nil, s.err
}
func (s *errSource) Close() error { return nil }

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

// F-3 (§9 fail-loud): a real BPF read failure must be surfaced, not silently degraded to the
// "no application data" verdict, so the view can tell the user capture broke (e.g. lost privilege).
func TestInspect_CaptureFailureSurfaced(t *testing.T) {
	flow, _ := flowTo("9.9.9.9:443")
	readErr := errors.New("read /dev/bpf0: operation not permitted")
	r := Inspect(&errSource{err: readErr}, flow, 20)
	if r.Err == nil || !errors.Is(r.Err, readErr) {
		t.Fatalf("capture error must be surfaced on Result.Err, got %v", r.Err)
	}
	if !strings.Contains(r.Verdict, "capture failed") {
		t.Fatalf("verdict must name the capture failure, got %q", r.Verdict)
	}
	if r.Verdict == "no application data captured" {
		t.Fatal("a read failure must not masquerade as a clean no-data result")
	}
}

// F-4: a ClientHello split across two TCP segments (large/extension-heavy hello) must still yield
// SNI — tier-0's "always" promise. Best-effort in-order concat of same-remote outbound bytes.
func TestInspect_SNIAcrossSplitSegments(t *testing.T) {
	flow, local := flowTo("93.184.216.34:443")
	ch := buildClientHello("split.example.com")
	half := len(ch) / 2
	src := &fixtureSource{packets: [][]byte{
		ipv4TCP(local, flow.Remote, ch[:half]),
		ipv4TCP(local, flow.Remote, ch[half:]),
	}}
	r := Inspect(src, flow, 20)
	if r.SNI != "split.example.com" {
		t.Fatalf("SNI should reassemble across segments, got %q", r.SNI)
	}
	if r.Coverage != CoverageMetadata {
		t.Fatalf("a split TLS hello is still an encrypted flow, got coverage=%d", r.Coverage)
	}
}

// F-7: TLS control record types (ChangeCipherSpec/Alert/Heartbeat), not just handshake/app-data,
// must not be misjudged as readable plaintext.
func TestLooksPlaintext_ExcludesTLSControlRecords(t *testing.T) {
	for _, ct := range []byte{0x14, 0x15, 0x16, 0x17, 0x18} {
		rec := append([]byte{ct, 0x03, 0x03, 0x00, 0x10}, []byte("plausible-ascii!")...)
		if looksPlaintext(rec) {
			t.Errorf("TLS record type 0x%02x must not read as plaintext", ct)
		}
	}
	if !looksPlaintext([]byte("GET /x HTTP/1.1\r\n")) {
		t.Fatal("a real HTTP request must still read as plaintext")
	}
}

// Packets to a different remote (or none) → nothing captured for this flow.
func TestInspect_NoMatchingTraffic(t *testing.T) {
	flow, local := flowTo("9.9.9.9:443")
	other := netip.MustParseAddrPort("8.8.8.8:443")
	src := &fixtureSource{packets: [][]byte{ipv4TCP(local, other, []byte("GET / HTTP/1.1\r\n"))}}
	r := Inspect(src, flow, 20)
	if r.Coverage != CoverageNone || !strings.Contains(r.Verdict, "no application data captured") {
		t.Fatalf("want none/no-data, got coverage=%d verdict=%q", r.Coverage, r.Verdict)
	}
}
