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
		{"notarized-devid", map[string]string{"signed": "true", "authority": "Developer ID Application: Acme (TEAM1)"}, GlyphNotarized},
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
