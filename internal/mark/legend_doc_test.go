package mark

import (
	"os"
	"strings"
	"testing"
)

// TestReadmeKeyMatchesLegend enforces that the README "Reading the marks" key is
// byte-identical to mark.LegendMarkdown() — so a glyph can never exist in the app
// without a documented meaning, nor the docs describe a mark the app doesn't emit.
func TestReadmeKeyMatchesLegend(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin = "<!-- BEGIN LEGEND (generated) -->"
	const end = "<!-- END LEGEND -->"
	s := strings.ReplaceAll(string(b), "\r\n", "\n") // normalize CRLF (cp-T9 review F-3)
	i := strings.Index(s, begin)
	j := strings.Index(s, end)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("README.md missing legend markers %q ... %q", begin, end)
	}
	got := strings.TrimSpace(s[i+len(begin) : j])
	want := strings.TrimSpace(LegendMarkdown())
	if got != want {
		t.Errorf("README key drifted from mark.Legend().\n--- README has ---\n%s\n--- want (paste this) ---\n%s", got, want)
	}
}
