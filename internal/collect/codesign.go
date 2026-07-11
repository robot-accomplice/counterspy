package collect

import (
	"strings"

	"counterspy/internal/model"
)

const (
	wUnsigned = 3
	wRevoked  = 5
)

// ParseCodesign turns captured codesign output + the Gatekeeper verdict into evidence.
//
// Ticket T-3 / cp-5 F-1: the signing `authority` is recorded as an allowlist-trustable
// Fact ONLY when Gatekeeper accepted the binary (`accepted` is derived from spctl's
// EXIT CODE by the caller — unspoofable, unlike matching free text). A valid-but-
// unaccepted signature (e.g. a self-signed cert with a spoofed CN) is not accepted, so
// its authority is dropped and cannot suppress the subject downstream.
// "revoked" is checked before "not signed" so the more severe verdict wins when the
// tool output mentions both (cp-5 F-2).
func ParseCodesign(path, verifyErr string, accepted bool, authority string) []model.Evidence {
	sub := model.Subject{Path: path}

	switch {
	case strings.Contains(verifyErr, "revoked"):
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "signing certificate revoked", Weight: wRevoked,
			Facts: map[string]string{"signed": "revoked"}}}
	case strings.Contains(verifyErr, "not signed"):
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "binary is unsigned", Weight: wUnsigned,
			Facts: map[string]string{"signed": "false"}}}
	default:
		facts := map[string]string{"signed": "true"}
		if accepted {
			facts["authority"] = authority // trusted only when Gatekeeper accepts (T-3)
		}
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "signed by " + authority, Weight: 0, Facts: facts}}
	}
}

// CollectCodesign runs codesign/spctl for a path (I/O edge).
func CollectCodesign(path string) []model.Evidence {
	verify, _ := execCombined("codesign", "--verify", "--deep", path)
	v := string(verify)
	// A revoked/unsigned binary needs no Gatekeeper assessment or authority extraction —
	// ParseCodesign discards both for those verdicts. Skipping them avoids two subprocesses
	// (spctl --assess is the slow one, ~0.5s) per unsigned/revoked binary.
	if strings.Contains(v, "revoked") || strings.Contains(v, "not signed") {
		return ParseCodesign(path, v, false, "")
	}
	// spctl's EXIT CODE is the unspoofable acceptance signal (T-3, cp-5 F-1/F-3) —
	// exit 0 == accepted. We never parse its free-text output for the verdict.
	accepted := execAccepts("spctl", "--assess", "--type", "execute", path)
	authOut, _ := execCombined("codesign", "-dv", "--verbose=2", path)
	return ParseCodesign(path, v, accepted, extractAuthority(string(authOut)))
}

// extractAuthority returns the first Authority= line — the leaf/signer cert; later
// lines are the CA chain. The allowlist matches the leaf CN, so first-match is correct.
func extractAuthority(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Authority=") {
			return strings.TrimPrefix(line, "Authority=")
		}
	}
	return ""
}
