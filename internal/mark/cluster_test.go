package mark

import (
	"strings"
	"testing"

	"github.com/rivo/uniseg"
)

// TestVocabularyGlyphsAreSingleWidth checks in code the assumption Cluster's
// uniform cadence rests on: every vocabulary glyph occupies exactly markField
// display cells. Without this, a future wide/zero-width/emoji glyph would break
// alignment while the rune-count cadence test still passed (cp-T3 review F-1).
// uniseg is test-only here — the runtime cadence is structural, not measured.
func TestVocabularyGlyphsAreSingleWidth(t *testing.T) {
	for _, r := range Legend() {
		if w := uniseg.StringWidth(string(r.Glyph)); w != markField {
			t.Errorf("glyph %q (%s) display width %d, want %d — would break uniform cadence", r.Glyph, r.Meaning, w, markField)
		}
	}
}

func TestClusterUniformCadence(t *testing.T) {
	rows := []string{
		Cluster(GlyphQuarantine, GlyphUnsigned, Liveness{RunState: GlyphActive, Socket: GlyphSocket}),
		Cluster(GlyphInvestigate, GlyphSigned, Liveness{RunState: GlyphVestigial}),
		Cluster(GlyphMonitor, GlyphApple, Liveness{}),
		Cluster(GlyphQuarantine, 0, Liveness{}), // no trust signal
	}
	width := len([]rune(rows[0]))
	for i, r := range rows {
		if got := len([]rune(r)); got != width {
			t.Errorf("row %d width %d != %d (%q)", i, got, width, r)
		}
		// cadence: slot,gap,slot,gap,slot,gap,slot -> gaps at fixed rune offsets 1,3,5
		rs := []rune(r)
		for _, off := range []int{1, 3, 5} {
			if rs[off] != ' ' {
				t.Errorf("row %d: expected gap at %d, got %q in %q", i, off, rs[off], r)
			}
		}
	}
	if got := Cluster(GlyphQuarantine, GlyphUnsigned, Liveness{RunState: GlyphActive, Socket: GlyphSocket}); got != "⚑ ○ ▸ ↔" {
		t.Errorf("cluster: got %q want %q", got, "⚑ ○ ▸ ↔")
	}
	if got := Cluster(GlyphMonitor, GlyphApple, Liveness{}); got != "· ●    " {
		t.Errorf("blank-slots cluster: got %q want %q", got, "· ●    ")
	}
}

func TestLegendCoversEveryGlyph(t *testing.T) {
	all := []rune{
		GlyphQuarantine, GlyphInvestigate, GlyphMonitor,
		GlyphApple, GlyphNotarized, GlyphSigned, GlyphUnsigned, GlyphRevoked,
		GlyphActive, GlyphVestigial, GlyphSocket,
	}
	have := map[rune]bool{}
	for _, r := range Legend() {
		have[r.Glyph] = true
	}
	for _, g := range all {
		if !have[g] {
			t.Errorf("glyph %q has no Legend row", g)
		}
	}
	if !strings.Contains(LegendLine(), string(GlyphUnsigned)) {
		t.Errorf("LegendLine missing %q: %q", GlyphUnsigned, LegendLine())
	}
}
