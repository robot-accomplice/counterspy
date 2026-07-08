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

// subjectTrusted reports whether a subject is genuinely known-good and therefore
// safe to suppress: it carries an Apple-allowlisted signing authority AND shows no
// contradicting signal. Any unsigned codesign evidence makes it untrusted, so a
// malicious payload can never hide behind one co-located allowlisted authority
// (cp-3 QA/Audit F-1). The caller additionally refuses to suppress any tripwired
// subject, preserving the "tripwire surfaces regardless" invariant.
func subjectTrusted(f model.Finding) bool {
	allow := false
	for _, e := range f.Evidence {
		if e.Facts["signed"] == "false" {
			return false // an unsigned signal is disqualifying
		}
		if IsAllowlisted(e.Facts["authority"]) {
			allow = true
		}
	}
	return allow
}
