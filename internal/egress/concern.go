// internal/egress/concern.go
package egress

import "counterspy/internal/model"

const sustainedBytesPerSec = 100_000 // ~100 KB/s = a real, sustained upload

// Concern scores an aggregated group: trust + destination + volume-by-nature. Volume is
// gated on BACKGROUND-ness, not trust — a quiet background daemon uploading is the exfil
// case; a foreground app you're using sending data is expected. Trust is one signal among
// several, never a kill switch that silences the others.
func Concern(g model.EgressGroup) model.ConcernLevel {
	return band(concernScore(g))
}

// concernScore is the raw (pre-band) score, shared by Concern and Exfil so both work on one
// scale rather than mixing a banded level with a raw bonus.
func concernScore(g model.EgressGroup) int {
	score := 0
	untrusted := false
	switch g.Trust {
	case "unsigned", "unknown", "revoked":
		score += 2
		untrusted = true
	case "signed":
		score++
	}
	// A sustained uploader that is a background daemon is the quiet-exfiltrator case.
	uploading := g.OutRate >= sustainedBytesPerSec && g.Background
	if uploading {
		score += 2
	}
	// Raw-IP destination concern (#3): a group ALL of whose destinations have no resolved name — the
	// app dialed bare IPs, a mild exfil tell. LIGHT TOUCH + CORROBORATED: it nudges only when the app
	// is ALREADY suspicious on another axis (untrusted trust, or a sustained background upload), never
	// on its own and never for a trusted/quiet app. Nothing about contacting an IP is inherently
	// threatening, so a notarized, idle app talking to an unnamed IP gets no nudge.
	if (untrusted || uploading) && len(g.Destinations) > 0 && allRawIP(g.Destinations) {
		score++
	}
	return score
}

// Exfil infers exfiltration risk and candidate data categories from capability × egress. It
// NEVER reads payloads — candidates are what the capabilities COULD leak. Risk builds on the
// same concernScore, plus a bump for holding a sensitive capability while actively uploading
// in the background (the capability could be the source of what is leaving).
func Exfil(g model.EgressGroup) (model.ConcernLevel, []string) {
	candidates := append([]string(nil), g.Capabilities...)
	if len(candidates) == 0 {
		return model.Minimal, nil
	}
	score := concernScore(g)
	if g.OutRate >= sustainedBytesPerSec && g.Background {
		score++
	}
	return band(score), candidates
}

// allRawIP reports whether EVERY destination is a bare IP with no passively-resolved name. Now that
// the DNS observer attaches names (#3), this is a real signal (it was a neutral stub in v1).
func allRawIP(dests []model.Endpoint) bool {
	for _, d := range dests {
		if d.Name != "" {
			return false
		}
	}
	return true
}

func band(score int) model.ConcernLevel {
	switch {
	case score >= 4:
		return model.Elevated
	case score >= 3:
		return model.Notable
	case score >= 1:
		return model.Low
	default:
		return model.Minimal
	}
}
