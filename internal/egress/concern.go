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
	switch g.Trust {
	case "unsigned", "unknown", "revoked":
		score += 2
	case "signed":
		score++
	}
	// Raw-IP destination concern: inert in v1 because isRawIP is a neutral stub (no
	// destination has a resolved name yet). Kept as a seam for the v0.4.1 name/pcap path.
	if len(g.Destinations) > 0 && allRawIP(g.Destinations) {
		score += 2
	}
	// A sustained uploader that is a background daemon is the quiet-exfiltrator case.
	if g.OutRate >= sustainedBytesPerSec && g.Background {
		score += 2
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

func allRawIP(dests []model.Endpoint) bool {
	for _, d := range dests {
		if !isRawIP(d.IP) {
			return false
		}
	}
	return true
}

// isRawIP reports a destination with no resolved name. In v1 no destination has a name, so
// this is a neutral stub (false) — it does NOT penalize every v1 destination. It becomes
// meaningful when the v0.4.1 packet-capture/reverse-DNS path attaches names.
func isRawIP(host string) bool { return false }

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
