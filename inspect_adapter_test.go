package main

import (
	"errors"
	"strings"
	"syscall"
	"testing"

	"counterspy/internal/inspect"
	"counterspy/internal/model"
)

// The coverage mapping is pinned so a future tier added to inspect.Coverage forces a deliberate
// decision in toInspectView rather than silently defaulting (cp-insC Audit F-3), and SNI + byte
// volumes pass through for any tier.
func TestToInspectView_CoverageMapping(t *testing.T) {
	cases := []struct {
		in   inspect.Coverage
		want model.InspectCoverage
	}{
		{inspect.CoverageNone, model.InspectNone},
		{inspect.CoverageMetadata, model.InspectMetadata},
		{inspect.CoveragePlaintext, model.InspectPlaintext},
	}
	for _, c := range cases {
		r := inspect.Result{Coverage: c.in, SNI: "api.example.com", Verdict: "v",
			Outbound: []byte("GET / HTTP/1.1\r\n"), Inbound: []byte("HTTP/1.1 200 OK\r\n")}
		v := toInspectView(r)
		if v.Coverage != c.want {
			t.Errorf("coverage %d → %d, want %d", c.in, v.Coverage, c.want)
		}
		if v.SentBytes != len(r.Outbound) || v.RecvBytes != len(r.Inbound) {
			t.Errorf("coverage %d: byte volumes must equal len(Outbound)/len(Inbound)", c.in)
		}
		if v.SNI != "api.example.com" {
			t.Errorf("SNI must pass through, got %q", v.SNI)
		}
	}
}

// A TLS-ciphertext direction is NOT surfaced (random noise) — even when the OTHER direction is
// readable plaintext (§6: never dump ciphertext; the readable side still shows).
func TestToInspectView_TLSCiphertextNotDumped(t *testing.T) {
	r := inspect.Result{
		Coverage: inspect.CoveragePlaintext, Encrypted: true, // a TLS flow (SNI/record/port evidence)
		Outbound: []byte{0x16, 0x03, 0x01, 0xde, 0xad, 0xbe, 0xef}, OutboundPlaintext: false,
		Inbound: []byte("HTTP/1.1 200 OK\r\n\r\nreadable body"), InboundPlaintext: true,
	}
	v := toInspectView(r)
	if v.Sent != "" {
		t.Fatalf("TLS ciphertext must not be dumped, got %q", v.Sent)
	}
	if v.Received == "" {
		t.Fatal("the plaintext inbound direction must still be shown")
	}
	if v.SentBytes == 0 || v.RecvBytes == 0 {
		t.Fatal("byte volumes for both directions must still be reported")
	}
}

// A CLEARTEXT binary payload (not TLS) must still be SHOWN — as a hexdump — not hidden. This is the
// :80 case: the wire bytes are the real payload; the user needs to see them.
func TestToInspectView_CleartextBinaryShownAsHex(t *testing.T) {
	body := []byte{0x50, 0x4b, 0x03, 0x04, 0x00, 0xff, 0xfe, 0x01} // zip-ish binary, not text, not TLS
	r := inspect.Result{Coverage: inspect.CoverageMetadata, Encrypted: false,
		Inbound: body, InboundPlaintext: false}
	v := toInspectView(r)
	if v.Received == "" {
		t.Fatal("a cleartext binary payload must be shown as a hexdump, not hidden")
	}
	if !strings.Contains(v.Received, "50 4b 03 04") {
		t.Fatalf("expected a hexdump of the bytes, got %q", v.Received)
	}
	if v.Encrypted {
		t.Fatal("a non-TLS flow must not be marked Encrypted")
	}
}

// The hexdump surfaces embedded text in its ASCII gutter (so HTTP headers are readable even when
// the direction is classified binary).
func TestHexDump_ASCIIGutterSurfacesText(t *testing.T) {
	got := hexDump([]byte("Host: hi\x00\x01")) // ≤16 bytes → one line
	if !strings.Contains(got, "|Host: hi..|") {
		t.Fatalf("hexdump gutter must show embedded text (non-printable as '.'), got:\n%s", got)
	}
}

// A capture failure on the engine result is surfaced on the view (§9 fail-loud), not swallowed.
func TestToInspectView_SurfacesError(t *testing.T) {
	v := toInspectView(inspect.Result{Coverage: inspect.CoverageNone, Verdict: "capture failed: x", Err: errors.New("boom")})
	if v.Err != "boom" {
		t.Fatalf("engine error must reach the view, got %q", v.Err)
	}
}

// sanitizeMultiline keeps line structure (readable protocols are multi-line) but strips terminal
// control/escape chars so a crafted payload can't inject ANSI into the pane.
func TestSanitizeMultiline(t *testing.T) {
	in := "GET /x HTTP/1.1\nHost: e\x1b[31mvil\nX: ok"
	got := sanitizeMultiline(in)
	if strings.Contains(got, "\x1b") {
		t.Fatalf("escape char survived sanitize: %q", got)
	}
	if strings.Count(got, "\n") != 2 {
		t.Fatalf("newlines must be preserved, got %q", got)
	}
}

// A non-root capture failure (the common case — the monitor is unprivileged but /dev/bpf isn't)
// must read as an actionable "relaunch with sudo", not a raw errno; other failures pass through.
func TestCaptureFailVerdict(t *testing.T) {
	perm := captureFailVerdict(syscall.EACCES)
	if !strings.Contains(perm, "sudo") || strings.Contains(perm, "permission denied") {
		t.Fatalf("permission error should give the actionable sudo message, got %q", perm)
	}
	if got := captureFailVerdict(errors.New("device gone")); got != "capture failed: device gone" {
		t.Fatalf("a non-permission error should surface verbatim, got %q", got)
	}
}

func TestRemoteAddrPort(t *testing.T) {
	if _, ok := remoteAddrPort(model.Conn{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}}); !ok {
		t.Error("valid IPv4 endpoint must parse")
	}
	if _, ok := remoteAddrPort(model.Conn{Endpoint: model.Endpoint{IP: "not-an-ip", Port: 443}}); ok {
		t.Error("garbage endpoint must not parse")
	}
}

// --no-inspect yields a nil Inspector (disabled); the default is a live inspector.
func TestNewInspector(t *testing.T) {
	if newInspector(true) != nil {
		t.Error("--no-inspect must disable inspection (nil Inspector)")
	}
	if newInspector(false) == nil {
		t.Error("default must provide a live inspector")
	}
}
