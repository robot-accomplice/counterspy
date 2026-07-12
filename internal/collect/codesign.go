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
func ParseCodesign(path, verifyErr string, accepted bool, authority string, notarized bool) []model.Evidence {
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
			facts["authority"] = authority // trusted only for a valid signature (T-3)
			if notarized {
				// Offline stapled-ticket notarization (PR #25): distinguishes ◆ notarized
				// from ◇ signed-not-notarized now that `accepted` means valid-signature,
				// not Gatekeeper-notarized.
				facts["notarized"] = "true"
			}
		}
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "signed by " + authority, Weight: 0, Facts: facts}}
	}
}

// sigProbe returns a code-signature verdict for a path, in the same shape ParseCodesign
// consumes: a verify-error string ("" = signed, "...not signed..." = unsigned, "...revoked..."
// = revoked), whether the signature is valid/accepted, and the leaf-certificate authority. The
// darwin build wires this to an in-process Security.framework implementation (native.go); it's
// a package var so tests can inject a fake and stay hermetic. Nil on platforms without a
// backend, where CollectCodesign yields no evidence.
var sigProbe func(path string) (verifyErr string, accepted bool, authority string, notarized bool)

// CollectCodesign returns code-signature evidence for a path (I/O edge, via sigProbe).
func CollectCodesign(path string) []model.Evidence {
	if sigProbe == nil {
		return nil
	}
	verifyErr, accepted, authority, notarized := sigProbe(path)
	return ParseCodesign(path, verifyErr, accepted, authority, notarized)
}
