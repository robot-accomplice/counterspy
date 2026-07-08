package score

import (
	"testing"

	"counterspy/internal/model"
)

func ev(path string, k model.SignalKind, w int) model.Evidence {
	return model.Evidence{Subject: model.Subject{Path: path}, Kind: k, Weight: w}
}

func TestScore_SumsSameSubject(t *testing.T) {
	in := []model.Evidence{
		ev("/a", model.KindCodesign, 3),
		ev("/a", model.KindCodesign, 2), // same kind → no correlation bonus
	}
	out := Score(in)
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	if out[0].Score != 5 {
		t.Fatalf("want score 5, got %d", out[0].Score)
	}
}

func TestScore_SortsDescending(t *testing.T) {
	in := []model.Evidence{
		ev("/low", model.KindCodesign, 2),
		ev("/high", model.KindCodesign, 9),
	}
	out := Score(in)
	if out[0].Subject.Path != "/high" {
		t.Fatalf("want /high first, got %q", out[0].Subject.Path)
	}
}

func TestScore_CorrelationBonusForDistinctKinds(t *testing.T) {
	// Same total raw weight (6), but subject B has two distinct kinds.
	in := []model.Evidence{
		ev("/A", model.KindCodesign, 6),
		ev("/B", model.KindCodesign, 3),
		ev("/B", model.KindTCC, 3),
	}
	out := Score(in)
	byPath := map[string]int{}
	for _, f := range out {
		byPath[f.Subject.Path] = f.Score
	}
	if byPath["/A"] != 6 {
		t.Fatalf("A: want 6, got %d", byPath["/A"])
	}
	if byPath["/B"] != 9 { // 6 * 1.5
		t.Fatalf("B: want 9 (correlation bonus), got %d", byPath["/B"])
	}
}
