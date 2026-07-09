// internal/feedback/capture_test.go
package feedback

import (
	"testing"

	"counterspy/internal/model"
)

func TestCapture_PublicDropsPrivate(t *testing.T) {
	a := asmt("/Users/jon/.tools/x", "com.private.tool", 8, model.RecInvestigate)
	r := Capture(a, model.LabelFalsePositive, DetailPublic, "nonce-1")
	if r.Nonce != "nonce-1" {
		t.Fatalf("nonce not set: %q", r.Nonce)
	}
	if r.Identity != "" {
		t.Fatalf("public detail must drop private identity, got %q", r.Identity)
	}
	if r.Extra != nil {
		t.Fatalf("public detail must carry no extra, got %+v", r.Extra)
	}
}

func TestCapture_FullIncludesPrivateIdentityAndPath(t *testing.T) {
	a := asmt("/Users/jon/.tools/x", "com.private.tool", 8, model.RecInvestigate)
	r := Capture(a, model.LabelFalsePositive, DetailFull, "nonce-2")
	if r.Identity != "com.private.tool" {
		t.Fatalf("full detail should include the private identity, got %q", r.Identity)
	}
	if r.Extra["path"] != "/Users/jon/.tools/x" {
		t.Fatalf("full detail should include raw path in extra, got %+v", r.Extra)
	}
}

func TestNewNonce_NonEmptyAndVaries(t *testing.T) {
	if a, b := NewNonce(), NewNonce(); a == "" || a == b {
		t.Fatalf("nonce should be non-empty and vary: %q %q", a, b)
	}
}
