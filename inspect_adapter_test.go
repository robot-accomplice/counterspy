package main

import (
	"errors"
	"strings"
	"testing"

	"counterspy/internal/inspect"
	"counterspy/internal/model"
)

// The coverage mapping is pinned so a future tier added to inspect.Coverage forces a deliberate
// decision in toInspectView rather than silently defaulting (cp-insC Audit F-3). Payload becomes
// content ONLY for the plaintext tier; an encrypted/metadata flow never exposes bytes.
func TestToInspectView_CoverageMapping(t *testing.T) {
	cases := []struct {
		in         inspect.Coverage
		payload    string
		want       model.InspectCoverage
		wantContnt bool
	}{
		{inspect.CoverageNone, "", model.InspectNone, false},
		{inspect.CoverageMetadata, "", model.InspectMetadata, false},
		{inspect.CoveragePlaintext, "GET / HTTP/1.1\r\n", model.InspectPlaintext, true},
	}
	for _, c := range cases {
		r := inspect.Result{Coverage: c.in, SNI: "api.example.com", Verdict: "v", Payload: []byte(c.payload)}
		v := toInspectView(r)
		if v.Coverage != c.want {
			t.Errorf("coverage %d → %d, want %d", c.in, v.Coverage, c.want)
		}
		if (v.Content != "") != c.wantContnt {
			t.Errorf("coverage %d: content present=%v, want %v", c.in, v.Content != "", c.wantContnt)
		}
		if v.SNI != "api.example.com" {
			t.Errorf("SNI must pass through, got %q", v.SNI)
		}
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
