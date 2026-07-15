package publish

import (
	"os"

	"counterspy/internal/model"
)

// removeIfSocket removes path only if it is a stale unix socket — never a regular file (so we don't
// clobber something at a mistyped path).
func removeIfSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	return os.Remove(path)
}

// sanitizeFlow validates a flow read from an UNTRUSTED source (the socket / log — anyone who can write
// there). An unknown Status is coerced to FlowError so a malformed record can't imply a state (e.g.
// "decrypted") it doesn't actually represent (the deferred cp-p2a Status-validation, at the consumer).
// Text fields are left as-is; the TUI applies model.Clean at render time.
func sanitizeFlow(fl model.InterceptedFlow) model.InterceptedFlow {
	switch fl.Status {
	case model.FlowDecrypted, model.FlowPinned, model.FlowOpaque, model.FlowError:
	default:
		fl.Status = model.FlowError
	}
	return fl
}
