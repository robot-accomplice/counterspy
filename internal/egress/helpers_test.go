package egress

import (
	"testing"

	"counterspy/internal/collect"
	"counterspy/internal/model"
)

func ev(facts map[string]string) model.Evidence {
	return model.Evidence{Facts: facts}
}

func TestTrustFromCodesign(t *testing.T) {
	cases := []struct {
		name string
		ev   []model.Evidence
		want string
	}{
		{"unsigned", []model.Evidence{ev(map[string]string{"signed": "false"})}, "unsigned"},
		{"revoked", []model.Evidence{ev(map[string]string{"signed": "revoked"})}, "revoked"},
		{"signed_no_authority", []model.Evidence{ev(map[string]string{"signed": "true"})}, "signed"},
		{"notarized", []model.Evidence{ev(map[string]string{"signed": "true", "authority": "Developer ID Application: Acme"})}, "notarized"},
		{"apple", []model.Evidence{ev(map[string]string{"signed": "true", "authority": "Software Signing"})}, "apple"},
		{"unknown_empty", nil, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := trustFromCodesign(c.ev); got != c.want {
				t.Fatalf("trustFromCodesign(%v) = %q, want %q", c.ev, got, c.want)
			}
		})
	}
}

func TestCapsFromTCC(t *testing.T) {
	grants := []model.Evidence{
		{Facts: map[string]string{"service": "kTCCServiceScreenCapture"}, Subject: model.Subject{Path: "/Applications/Foo.app/Contents/MacOS/Foo"}},
		{Facts: map[string]string{"service": "kTCCServiceAccessibility"}, Subject: model.Subject{Path: "/Applications/Bar.app"}},
		{Facts: map[string]string{"service": "kTCCServiceUnknown"}, Subject: model.Subject{Path: "/Applications/Foo.app/Contents/MacOS/Foo"}},
	}

	t.Run("prefix_match", func(t *testing.T) {
		got := capsFromTCC(grants, "/Applications/Foo.app/Contents/MacOS/Foo")
		if len(got) != 1 || got[0] != "screen" {
			t.Fatalf("want [screen], got %v", got)
		}
	})

	t.Run("basename_match", func(t *testing.T) {
		got := capsFromTCC(grants, "/Applications/Bar.app")
		if len(got) != 1 || got[0] != "keystrokes" {
			t.Fatalf("want [keystrokes], got %v", got)
		}
	})

	t.Run("non_matching_service", func(t *testing.T) {
		got := capsFromTCC([]model.Evidence{{Facts: map[string]string{"service": "kTCCServiceUnknown"}, Subject: model.Subject{Path: "/x"}}}, "/x")
		if got != nil {
			t.Fatalf("want nil, got %v", got)
		}
	})

	t.Run("empty_path_nil", func(t *testing.T) {
		if got := capsFromTCC(grants, ""); got != nil {
			t.Fatalf("want nil, got %v", got)
		}
	})
}

func TestIsAppleAuthority(t *testing.T) {
	cases := []struct {
		authority string
		want      bool
	}{
		{"Software Signing", true},
		{"Apple Mac OS Application Signing", true},
		{"Developer ID Application: Some Corp", false},
	}
	for _, c := range cases {
		if got := isAppleAuthority(c.authority); got != c.want {
			t.Fatalf("isAppleAuthority(%q) = %v, want %v", c.authority, got, c.want)
		}
	}
}

func TestPathMatchesClient(t *testing.T) {
	cases := []struct {
		name   string
		binary string
		client string
		want   bool
	}{
		{"inside_bundle_prefix", "/Applications/Foo.app/Contents/MacOS/Foo", "/Applications/Foo.app", true},
		{"same_basename", "/opt/homebrew/bin/foo", "/usr/local/bin/foo", true},
		{"no_match", "/opt/a/bar", "/opt/b/baz", false},
		{"empty_client", "/opt/a/bar", "", false},
		{"empty_binary", "", "/opt/b/baz", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pathMatchesClient(c.binary, c.client); got != c.want {
				t.Fatalf("pathMatchesClient(%q, %q) = %v, want %v", c.binary, c.client, got, c.want)
			}
		})
	}
}

func TestWorseTrust(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"unsigned", "notarized", "unsigned"},
		{"apple", "signed", "signed"},
		{"signed", "signed", "signed"},
		{"notarized", "notarized", "notarized"},
	}
	for _, c := range cases {
		if got := worseTrust(c.a, c.b); got != c.want {
			t.Fatalf("worseTrust(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestBand(t *testing.T) {
	cases := []struct {
		score int
		want  model.ConcernLevel
	}{
		{0, model.Minimal},
		{1, model.Low},
		{2, model.Low},
		{3, model.Notable},
		{4, model.Elevated},
		{10, model.Elevated},
	}
	for _, c := range cases {
		if got := band(c.score); got != c.want {
			t.Fatalf("band(%d) = %v, want %v", c.score, got, c.want)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"::1:8080", "::1", 8080},
		{"noport", "", 0},
	}
	for _, c := range cases {
		host, port := splitHostPort(c.in)
		if host != c.wantHost || port != c.wantPort {
			t.Fatalf("splitHostPort(%q) = (%q, %d), want (%q, %d)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

func TestBinaryPathAppNameFirstToken(t *testing.T) {
	if got := binaryPath(nil); got != "" {
		t.Fatalf("binaryPath(nil) = %q, want empty", got)
	}
	if got := appName("", 42); got != "pid:42" {
		t.Fatalf("appName(\"\", 42) = %q, want pid:42", got)
	}
	p := &collect.Proc{Cmd: "/usr/bin/foo --flag arg"}
	if got := binaryPath(p); got != "/usr/bin/foo" {
		t.Fatalf("binaryPath(cmd with args) = %q, want /usr/bin/foo", got)
	}
	// appName resolves from the real executable path, so a spaced path keeps its true base.
	if got := appName("/Users/analyst/Library/Application Support/Claude/claude.app/Contents/MacOS/claude", 1); got != "claude" {
		t.Fatalf("appName(spaced path) = %q, want claude", got)
	}
	if got := firstToken("/usr/bin/nospace"); got != "/usr/bin/nospace" {
		t.Fatalf("firstToken(no space) = %q, want unchanged", got)
	}
}

func TestAllRawIP(t *testing.T) {
	if got := allRawIP(nil); !got {
		t.Fatalf("allRawIP(empty) = %v, want true (vacuously)", got)
	}
	dests := []model.Endpoint{{IP: "1.2.3.4"}, {IP: "5.6.7.8"}}
	if got := allRawIP(dests); got {
		t.Fatalf("allRawIP(non-empty) = %v, want false (isRawIP stub)", got)
	}
}

func TestConcernScore(t *testing.T) {
	unsignedBackgroundUploader := model.EgressGroup{
		Trust:      "unsigned",
		Background: true,
		OutRate:    200_000,
	}
	trustedForeground := model.EgressGroup{
		Trust:      "apple",
		Background: false,
		OutRate:    200_000,
	}
	hi := concernScore(unsignedBackgroundUploader)
	lo := concernScore(trustedForeground)
	if hi <= lo {
		t.Fatalf("expected unsigned background uploader score (%d) > trusted foreground score (%d)", hi, lo)
	}
	if lo != 0 {
		t.Fatalf("trusted foreground score = %d, want 0", lo)
	}
}
