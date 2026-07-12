package tui

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecouplingInvariant enforces the §12 rule in CI, not by memory: internal/tui may
// import ONLY the project's pure, no-I/O vocabulary leaves — internal/model (domain) and
// internal/mark (presentation symbology) — plus tcell + stdlib. The invariant's intent is
// that the TUI never depends on the I/O / business-logic layers (score, interpret, collect,
// act); those are reached only through the Actor seam. A future dev adding any of those to
// a tui file fails this test (ABORT-TUI Future-Me #4). mark was admitted (cp-T7) as a pure
// leaf analogous to model — it does no I/O and is the single source of the glyph vocabulary.
func TestDecouplingInvariant(t *testing.T) {
	allowed := map[string]bool{
		"counterspy/internal/model": true,
		"counterspy/internal/mark":  true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(p, "counterspy/internal/") && !allowed[p] {
				t.Errorf("%s imports %q — internal/tui may import only model + mark (pure vocabulary leaves); I/O/business-logic layers are reached via the Actor seam", f, p)
			}
		}
	}
}
