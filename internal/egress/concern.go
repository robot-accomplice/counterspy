package egress

import "counterspy/internal/model"

const sustainedBytesPerSec = 100_000 // ~100 KB/s = a real, sustained upload

// Concern scores an aggregated group: trust × destination × volume × background-nature.
func Concern(g model.EgressGroup) model.ConcernLevel {
	score := 0
	isTrusted := g.Trust == "notarized" || g.Trust == "apple" || g.Trust == ""

	switch g.Trust {
	case "unsigned", "unknown", "revoked":
		score += 2
	case "signed":
		score += 1
	case "notarized", "apple", "":
		// trusted — no add
	}
	// Only untrusted apps trigger concern for raw IPs
	if !isTrusted && allRawIP(g.Destinations) && len(g.Destinations) > 0 {
		score += 2
	}
	// Only untrusted apps trigger concern for sustained volume
	if !isTrusted && g.OutRate >= sustainedBytesPerSec {
		score++
		if g.Background {
			score++ // a quiet daemon uploading is worse than a foreground app you're using
		}
	}
	return band(score)
}

// Exfil infers exfiltration risk and candidate data categories from capability × egress.
// It NEVER reads payloads — candidates are what the capabilities COULD leak.
func Exfil(g model.EgressGroup) (model.ConcernLevel, []string) {
	candidates := append([]string(nil), g.Capabilities...)
	if len(candidates) == 0 {
		return model.Minimal, nil
	}
	// Base risk tracks concern (trust/destination/volume/nature), then capability presence
	// with real outbound volume raises it.
	score := int(Concern(g))
	if g.OutRate >= sustainedBytesPerSec {
		score++
		if g.Background {
			score++
		}
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

// isRawIP is a placeholder for "no resolved name" — in v1 every lsof destination is an IP,
// so this is true unless a future reverse-DNS/pcap step attaches a name. Kept as a seam.
func isRawIP(host string) bool { return host != "" }

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
