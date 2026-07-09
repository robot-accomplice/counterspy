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
// import ONLY internal/model from the project (plus tcell + stdlib). A future dev adding
// internal/score / interpret / collect / act to a tui file fails this test (ABORT-TUI
// Future-Me #4).
func TestDecouplingInvariant(t *testing.T) {
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
			if strings.HasPrefix(p, "counterspy/internal/") && p != "counterspy/internal/model" {
				t.Errorf("%s imports %q — internal/tui must import only internal/model (decoupling invariant)", f, p)
			}
		}
	}
}
