package score

import (
	"slices"

	"counterspy/internal/model"
)

// Score folds raw evidence into ranked findings. Pure: no I/O.
func Score(ev []model.Evidence) []model.Finding {
	groups := map[string]*model.Finding{}
	order := []string{}
	for _, e := range ev {
		k := e.Subject.Key()
		f, ok := groups[k]
		if !ok {
			f = &model.Finding{Subject: e.Subject}
			groups[k] = f
			order = append(order, k)
		}
		f.Evidence = append(f.Evidence, e)
		f.Score += e.Weight
		if !slices.Contains(f.Kinds, e.Kind) {
			f.Kinds = append(f.Kinds, e.Kind)
		}
	}

	out := make([]model.Finding, 0, len(order))
	for _, k := range order {
		f := groups[k]
		f.Score = applyCorrelation(f.Score, len(f.Kinds))
		f.Tripwire = tripwire(*f) // computed BEFORE suppression. A tripwire always surfaces
		if f.Tripwire == "" && subjectTrusted(*f) {
			continue // genuinely known-good and nothing contradicting → suppress noise
		}
		out = append(out, *f)
	}
	slices.SortFunc(out, func(a, b model.Finding) int {
		if a.Score != b.Score {
			return b.Score - a.Score // desc
		}
		return cmpStr(a.Subject.Key(), b.Subject.Key())
	})
	return out
}

func applyCorrelation(sum, distinctKinds int) int {
	if distinctKinds >= CorrelationMinKinds {
		return sum * CorrelationFactorX100 / 100
	}
	return sum
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
