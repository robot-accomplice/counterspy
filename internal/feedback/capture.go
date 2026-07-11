// internal/feedback/capture.go
package feedback

import (
	"crypto/rand"
	"encoding/hex"

	"counterspy/internal/model"
)

// Detail is the user-chosen richness of shared data.
type Detail string

const (
	DetailPublic Detail = "public" // default: fingerprint + public identity only
	DetailFull   Detail = "full"   // opt-in: also private identity + raw context
)

// Capture builds the final record: the anonymous fingerprint from Minimize, plus a
// per-submission nonce, plus (only under DetailFull) the private identity and raw context.
func Capture(a model.Assessment, label string, detail Detail, nonce string) model.FeedbackRecord {
	r := Minimize(a, label)
	r.Nonce = nonce
	if detail == DetailFull {
		if a.Subject.Label != "" {
			r.Identity = a.Subject.Label // consented: include the private identifier too
		}
		extra := map[string]string{}
		if a.Subject.Path != "" {
			extra["path"] = a.Subject.Path
		}
		if len(extra) > 0 {
			r.Extra = extra
		}
	}
	return r
}

// NewNonce returns a random, non-correlatable submission nonce. Not used for identity —
// it deduplicates a single submission's records, not a user across submissions.
func NewNonce() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
