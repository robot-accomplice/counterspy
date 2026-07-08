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
