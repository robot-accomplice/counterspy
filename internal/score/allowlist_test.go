package score

import "testing"

func TestIsAllowlisted(t *testing.T) {
	cases := map[string]bool{
		"Software Signing":                          true, // Apple system
		"Apple Mac OS Application Signing":          true,
		"Developer ID Application: Some Sketchy Co": false,
		"": false,
	}
	for authority, want := range cases {
		if got := IsAllowlisted(authority); got != want {
			t.Errorf("IsAllowlisted(%q)=%v want %v", authority, got, want)
		}
	}
}

// cp-3 Audit F-4: a spoofed CN that merely contains an Apple authority substring
// must NOT be allowlisted (exact-match only).
func TestIsAllowlisted_RejectsSpoofSubstring(t *testing.T) {
	for _, spoof := range []string{
		"Not Software Signing At All But Fake",
		"Software Signing Evil Edition",
		"x Apple Mac OS Application Signing x",
	} {
		if IsAllowlisted(spoof) {
			t.Errorf("spoof %q must not be allowlisted", spoof)
		}
	}
}
