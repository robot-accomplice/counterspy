package collect

import (
	"os/exec"
	"strings"

	"counterspy/internal/model"
)

const (
	wUnsigned = 3
	wRevoked  = 5
)

// ParseCodesign turns captured codesign/spctl output into evidence.
//
// Ticket T-3: the signing `authority` is only recorded as an allowlist-trustable
// Fact when Gatekeeper (`spctl --assess`) ACCEPTS the binary. A valid-but-unaccepted
// signature (e.g. a self-signed cert with a spoofed CN) verifies but is not accepted,
// so its authority is dropped and cannot suppress the subject downstream.
func ParseCodesign(path, verifyErr, assessOut, authority string) []model.Evidence {
	sub := model.Subject{Path: path}

	switch {
	case strings.Contains(verifyErr, "not signed"):
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "binary is unsigned", Weight: wUnsigned,
			Facts: map[string]string{"signed": "false"}}}
	case strings.Contains(verifyErr, "revoked"):
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "signing certificate revoked", Weight: wRevoked,
			Facts: map[string]string{"signed": "revoked"}}}
	default:
		facts := map[string]string{"signed": "true"}
		if strings.Contains(assessOut, "accepted") {
			facts["authority"] = authority // trusted only when Gatekeeper accepts (T-3)
		}
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "signed by " + authority, Weight: 0, Facts: facts}}
	}
}

// CollectCodesign runs codesign/spctl for a path (I/O edge).
func CollectCodesign(path string) []model.Evidence {
	verify, _ := exec.Command("codesign", "--verify", "--deep", path).CombinedOutput()
	assess, _ := exec.Command("spctl", "--assess", "--type", "execute", path).CombinedOutput()
	authOut, _ := exec.Command("codesign", "-dv", "--verbose=2", path).CombinedOutput()
	return ParseCodesign(path, string(verify), string(assess), extractAuthority(string(authOut)))
}

func extractAuthority(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Authority=") {
			return strings.TrimPrefix(line, "Authority=")
		}
	}
	return ""
}
