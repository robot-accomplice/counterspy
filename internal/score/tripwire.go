package score

import "counterspy/internal/model"

// tripwire returns a non-empty label when a finding matches a hard
// "always surface" combination, regardless of numeric score.
func tripwire(f model.Finding) string {
	var unsigned, persistence, listener bool
	for _, e := range f.Evidence {
		switch e.Kind {
		case model.KindCodesign:
			if e.Facts["signed"] == "false" {
				unsigned = true
			}
		case model.KindPersistence:
			persistence = true
		case model.KindProcess:
			if e.Facts["listener"] == "true" {
				listener = true
			}
		}
	}
	if unsigned && persistence && listener {
		return "unsigned binary with persistence and a live network listener"
	}
	return ""
}

// subjectAllowlisted reports whether any evidence carries a trusted authority.
func subjectAllowlisted(f model.Finding) bool {
	for _, e := range f.Evidence {
		if IsAllowlisted(e.Facts["authority"]) {
			return true
		}
	}
	return false
}
