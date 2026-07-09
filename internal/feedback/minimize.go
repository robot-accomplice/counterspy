// Package feedback turns labeled findings into intrinsically-anonymous field reports
// and pushes them to a write-only sink. Anonymity lives in the data: no raw path,
// username, hostname, or (by default) private identifier ever leaves the machine.
package feedback

import (
	"sort"
	"strings"

	"counterspy/internal/model"
)

// Minimize scrubs an Assessment into an anonymous fingerprint + label. It leaves Nonce
// empty and Extra nil — Capture fills those. Deterministic; no I/O.
func Minimize(a model.Assessment, label string) model.FeedbackRecord {
	return model.FeedbackRecord{
		Schema:         model.FeedbackSchema,
		Tool:           model.Version,
		Label:          label,
		Recommendation: strings.ToLower(string(a.Recommendation)),
		Category:       a.Category,
		ScoreBand:      scoreBand(a.Score),
		Signals:        signalsOf(a),
		Codesign:       codesignClass(a),
		PathClass:      pathClass(a.Subject.Path),
		Tripwire:       a.Tripwire != "",
		Identity:       publicIdentity(a),
	}
}

func scoreBand(s int) string {
	switch {
	case s <= 4:
		return "0-4"
	case s <= 9:
		return "5-9"
	case s <= 14:
		return "10-14"
	default:
		return "15+"
	}
}

// pathClass maps a path to a coarse class, never revealing the path itself.
// Precedence: tmp → user-library → system → hidden → other.
func pathClass(p string) string {
	switch {
	case p == "":
		return "other"
	case hasAnyPrefix(p, "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"):
		return "tmp"
	case strings.Contains(p, "/Users/") && strings.Contains(p, "/Library/"):
		return "user-library"
	case hasAnyPrefix(p, "/System", "/usr", "/bin", "/sbin", "/Library/", "/opt"):
		return "system"
	case strings.Contains(p, "/."):
		return "hidden"
	default:
		return "other"
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// signalsOf returns the distinct collector kinds that contributed, sorted for stability.
func signalsOf(a model.Assessment) []string {
	set := map[string]bool{}
	for _, e := range a.Evidence {
		set[string(e.Kind)] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// codesignClass derives the signature state from codesign evidence facts.
// notarized = signed AND Gatekeeper-accepted (an authority fact was recorded).
func codesignClass(a model.Assessment) string {
	for _, e := range a.Evidence {
		if e.Kind != model.KindCodesign {
			continue
		}
		switch e.Facts["signed"] {
		case "false":
			return "unsigned"
		case "revoked":
			return "revoked"
		case "true":
			if e.Facts["authority"] != "" {
				return "notarized"
			}
			return "signed"
		}
	}
	return "unknown"
}

// publicIdentity returns the app identity ONLY when it is recognizably public:
// an Apple-namespace bundle ID, or a Gatekeeper-accepted binary (authority fact present).
// Everything else returns "" — a private identifier is never published without consent.
func publicIdentity(a model.Assessment) string {
	label := a.Subject.Label
	if label == "" {
		return ""
	}
	if strings.HasPrefix(label, "com.apple.") {
		return label
	}
	for _, e := range a.Evidence {
		if e.Kind == model.KindCodesign && e.Facts["authority"] != "" {
			return label
		}
	}
	return ""
}
