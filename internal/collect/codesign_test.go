package collect

import (
	"testing"

	"counterspy/internal/model"
)

func TestParseCodesign_UnsignedFlagged(t *testing.T) {
	ev := ParseCodesign("/tmp/x", "code object is not signed at all", false, "")
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if ev[0].Facts["signed"] != "false" {
		t.Errorf("expected signed=false fact, got %v", ev[0].Facts)
	}
	if ev[0].Kind != model.KindCodesign {
		t.Errorf("wrong kind %q", ev[0].Kind)
	}
}

func TestParseCodesign_SignedAcceptedCarriesAuthority(t *testing.T) {
	ev := ParseCodesign("/Applications/Safari.app", "", true, "Software Signing")
	if len(ev) != 1 || ev[0].Weight != 0 {
		t.Fatalf("want one zero-weight authority marker, got %+v", ev)
	}
	if ev[0].Facts["authority"] != "Software Signing" {
		t.Errorf("authority fact missing: %v", ev[0].Facts)
	}
}

// Ticket T-3 / cp-5 F-1: a binary whose signature verifies but that Gatekeeper does
// NOT accept must not carry an allowlist-trustable authority.
func TestParseCodesign_SignedButRejectedDropsAuthority(t *testing.T) {
	ev := ParseCodesign("/tmp/selfsigned", "", false, "Software Signing")
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if ev[0].Facts["authority"] != "" {
		t.Errorf("authority must be dropped when Gatekeeper rejects; got %q", ev[0].Facts["authority"])
	}
}

// cp-5 F-2: when verifyErr mentions both, the more severe "revoked" must win.
func TestParseCodesign_RevokedBeatsUnsigned(t *testing.T) {
	ev := ParseCodesign("/tmp/x", "certificate revoked, code object is not signed", false, "")
	if ev[0].Facts["signed"] != "revoked" {
		t.Fatalf("want revoked to win, got %v", ev[0].Facts)
	}
}
