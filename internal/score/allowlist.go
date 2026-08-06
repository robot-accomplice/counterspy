package score

// knownGood are exact signing-authority strings we treat as trusted, suppressing
// noise from Apple's own components. Extend deliberately.
//
// SECURITY: `authority` passed to IsAllowlisted MUST originate only from a
// codesign-verified AND Gatekeeper-accepted (spctl) chain, never a raw/unverified
// certificate CN, which an attacker can set to anything. Matching is EXACT (not
// substring) so a spoofed CN like "Software Signing Evil Edition" cannot alias a
// real Apple authority. (cp-3 Audit F-4; collector-side enforcement is ticket T-3.)
var knownGood = map[string]bool{
	"Software Signing":                 true, // Apple system binaries
	"Apple Mac OS Application Signing": true, // Apple-notarized Mac App Store
	"Apple Code Signing Certification": true, // Apple intermediate
}

// IsAllowlisted reports whether a code-signing authority is exactly a known-good one.
func IsAllowlisted(authority string) bool {
	return authority != "" && knownGood[authority]
}
