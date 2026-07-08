package score

import "strings"

// knownGood are signing-authority substrings we treat as trusted, suppressing
// noise from Apple's own components. Extend deliberately.
var knownGood = []string{
	"Software Signing",                 // Apple system binaries
	"Apple Mac OS Application Signing", // Apple-notarized Mac App Store
	"Apple Code Signing Certification", // Apple intermediate
}

// IsAllowlisted reports whether a code-signing authority is known-good.
func IsAllowlisted(authority string) bool {
	if authority == "" {
		return false
	}
	for _, g := range knownGood {
		if strings.Contains(authority, g) {
			return true
		}
	}
	return false
}
