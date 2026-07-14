package mark

import (
	"testing"

	"counterspy/internal/model"
)

func codesign(facts map[string]string) model.Finding {
	return model.Finding{Evidence: []model.Evidence{{Kind: model.KindCodesign, Facts: facts}}}
}

func TestConcern(t *testing.T) {
	if g := Concern(model.RecQuarantine); g != GlyphQuarantine {
		t.Errorf("quarantine: got %q want %q", g, GlyphQuarantine)
	}
	if g := Concern(model.RecInvestigate); g != GlyphInvestigate {
		t.Errorf("investigate: got %q want %q", g, GlyphInvestigate)
	}
	if g := Concern(model.RecMonitor); g != GlyphMonitor {
		t.Errorf("monitor: got %q want %q", g, GlyphMonitor)
	}
}

func TestTrust(t *testing.T) {
	cases := []struct {
		name  string
		facts map[string]string
		want  rune
	}{
		{"apple", map[string]string{"signed": "true", "authority": "Software Signing"}, GlyphApple},
		{"apple-named", map[string]string{"signed": "true", "authority": "Apple Mac OS Application Signing"}, GlyphApple},
		// ◆ notarized requires the explicit notarized fact (PR #25: native backend sets
		// authority for ANY valid signature, so ◆ must not be inferred from authority alone).
		{"notarized-devid", map[string]string{"signed": "true", "authority": "Developer ID Application: Acme (TEAM1)", "notarized": "true"}, GlyphNotarized},
		// A valid Developer-ID signature that is NOT notarized reads ◇, not ◆.
		{"signed-not-notarized", map[string]string{"signed": "true", "authority": "Developer ID Application: Acme (TEAM1)"}, GlyphSigned},
		// SECURITY (cp T1 review F-1): a Developer-ID cert whose company name contains
		// "Apple" must NOT forge ● Apple-system — it stays ◆ (notarized) / ◇ (not).
		{"devid-apple-spoof", map[string]string{"signed": "true", "authority": "Developer ID Application: Apple Fan LLC (TEAM9)", "notarized": "true"}, GlyphNotarized},
		{"devid-installer-apple-spoof", map[string]string{"signed": "true", "authority": "Developer ID Installer: Apple Lovers Inc (TEAM8)"}, GlyphSigned},
		{"signed-not-accepted", map[string]string{"signed": "true"}, GlyphSigned},
		{"unsigned", map[string]string{"signed": "false"}, GlyphUnsigned},
		{"revoked", map[string]string{"signed": "revoked"}, GlyphRevoked},
	}
	for _, c := range cases {
		if g := Trust(codesign(c.facts)); g != c.want {
			t.Errorf("%s: got %q want %q", c.name, g, c.want)
		}
	}
	if g := Trust(model.Finding{Evidence: []model.Evidence{{Kind: model.KindTCC}}}); g != 0 {
		t.Errorf("no codesign signal: got %q want blank(0)", g)
	}
}

func TestTrustLabel(t *testing.T) {
	cases := map[string]rune{
		"apple": GlyphApple, "notarized": GlyphNotarized, "signed": GlyphSigned,
		"unsigned": GlyphUnsigned, "revoked": GlyphRevoked,
		"unknown": 0, "": 0, "bogus": 0,
	}
	for in, want := range cases {
		if got := TrustLabel(in); got != want {
			t.Errorf("TrustLabel(%q): got %q want %q", in, got, want)
		}
	}
}

func TestPortEnc(t *testing.T) {
	cases := []struct {
		port int
		want EncKind
	}{
		{443, EncTLS}, {993, EncTLS}, {8443, EncTLS}, {5228, EncTLS},
		{80, EncClear}, {21, EncClear}, {143, EncClear},
		{587, EncUnknown}, {5222, EncUnknown}, // STARTTLS: begins clear, honestly unknown
		{27123, EncUnknown}, {0, EncUnknown},
	}
	for _, c := range cases {
		if got := PortEnc(c.port); got != c.want {
			t.Errorf("PortEnc(%d) = %d, want %d", c.port, got, c.want)
		}
	}
	// The TLS glyph is a bare key; cleartext is the same key with a combining overlay.
	if r, comb := EncGlyph(EncTLS); r != GlyphEncrypted || len(comb) != 0 {
		t.Errorf("EncTLS glyph should be a bare key, got %q %v", r, comb)
	}
	if r, comb := EncGlyph(EncClear); r != GlyphCleartext || len(comb) != 0 {
		t.Errorf("EncClear glyph should be the cleartext box, got %q %v", r, comb)
	}
	if r, comb := EncGlyph(EncUnknown); r != 0 || comb != nil {
		t.Errorf("EncUnknown must render nothing, got %q %v", r, comb)
	}
}
