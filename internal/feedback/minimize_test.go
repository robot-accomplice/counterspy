// internal/feedback/minimize_test.go
package feedback

import (
	"strings"
	"testing"

	"counterspy/internal/model"
)

func asmt(path, label string, score int, rec model.Recommendation, ev ...model.Evidence) model.Assessment {
	return model.Assessment{
		Finding:        model.Finding{Subject: model.Subject{Path: path, Label: label}, Score: score, Evidence: ev, Tripwire: ""},
		Recommendation: rec, Category: "surveillance-capable",
	}
}

func TestMinimize_DropsRawIdentifiers(t *testing.T) {
	a := asmt("/Users/jon/secret-project/beacon", "com.private.beacon", 12, model.RecQuarantine,
		model.Evidence{Kind: model.KindPersistence, Subject: model.Subject{Path: "/Users/jon/secret-project/beacon"}},
		model.Evidence{Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}})
	r := Minimize(a, model.LabelFalsePositive)
	blob := r.Schema + r.Tool + r.Label + r.Recommendation + r.Category + r.ScoreBand +
		strings.Join(r.Signals, ",") + r.Codesign + r.PathClass + r.Identity
	for _, secret := range []string{"jon", "secret-project", "beacon", "com.private"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("record leaked %q: %+v", secret, r)
		}
	}
	if r.Identity != "" {
		t.Fatalf("private identity must be dropped, got %q", r.Identity)
	}
	if r.PathClass != "user-library" && r.PathClass != "other" {
		// /Users/... without /Library/ classes as "other"
		if r.PathClass != "other" {
			t.Fatalf("unexpected path_class %q", r.PathClass)
		}
	}
	if r.Recommendation != "quarantine" || r.ScoreBand != "10-14" || r.Codesign != "unsigned" {
		t.Fatalf("bad fingerprint: %+v", r)
	}
	if want := []string{"codesign", "persistence"}; strings.Join(r.Signals, ",") != strings.Join(want, ",") {
		t.Fatalf("signals = %v, want sorted %v", r.Signals, want)
	}
}

func TestMinimize_PublicIdentityKept(t *testing.T) {
	apple := asmt("/Applications/Safari.app", "com.apple.Safari", 6, model.RecInvestigate)
	if got := Minimize(apple, model.LabelFalsePositive).Identity; got != "com.apple.Safari" {
		t.Fatalf("apple-namespace identity should be kept, got %q", got)
	}
	notarized := asmt("/Applications/Docker.app/x", "com.docker.docker", 6, model.RecInvestigate,
		model.Evidence{Kind: model.KindCodesign, Facts: map[string]string{"signed": "true", "authority": "Developer ID Application: Docker Inc"}})
	got := Minimize(notarized, model.LabelFalsePositive)
	if got.Identity != "com.docker.docker" {
		t.Fatalf("Gatekeeper-accepted identity should be kept, got %q", got.Identity)
	}
	if got.Codesign != "notarized" {
		t.Fatalf("codesign = %q, want notarized", got.Codesign)
	}
}

func TestScoreBandBoundaries(t *testing.T) {
	for _, c := range []struct {
		s    int
		want string
	}{{0, "0-4"}, {4, "0-4"}, {5, "5-9"}, {9, "5-9"}, {14, "10-14"}, {15, "15+"}, {99, "15+"}} {
		if got := scoreBand(c.s); got != c.want {
			t.Fatalf("scoreBand(%d) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestPathClass(t *testing.T) {
	for _, c := range []struct{ p, want string }{
		{"/System/Library/x", "system"},
		{"/usr/local/bin/x", "system"},
		{"/Users/jon/Library/LaunchAgents/x.plist", "user-library"},
		{"/Users/jon/.hidden/beacon", "hidden"},
		{"/private/var/folders/xx/T/x", "tmp"},
		{"/tmp/x", "tmp"},
		{"/opt/weird/x", "system"},
		{"/Users/jon/Downloads/x", "other"},
		{"", "other"},
	} {
		if got := pathClass(c.p); got != c.want {
			t.Fatalf("pathClass(%q) = %q, want %q", c.p, got, c.want)
		}
	}
}
