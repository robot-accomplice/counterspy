package publish

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"counterspy/internal/model"
)

const (
	maxFlowLine = 4 << 20  // cap one JSONL record so a giant/garbage line can't OOM a reader
	maxFieldLen = 64 << 10 // cap decrypted text fields from an untrusted source before display/re-publish
)

// removeIfSocket removes path only if it is a stale unix socket, never a regular file (so we don't
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

// scanMessages reads newline-delimited JSON messages from r, size-bounding each line (no OOM on a
// giant record) and skipping a malformed one, calling fn with each sanitized message. Shared by the
// socket and log readers; both consume untrusted input (anyone who can write the socket/log).
func scanMessages(r io.Reader, fn func(model.InterceptedMessage)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxFlowLine)
	var mismatches int
	var mismatchNoticed bool
	for sc.Scan() {
		line := sc.Bytes()
		var msg model.InterceptedMessage
		if json.Unmarshal(line, &msg) != nil {
			mismatches++
			if !mismatchNoticed {
				mismatchNoticed = true
				fn(synthesizeVersionError("malformed JSON"))
			}
			continue
		}
		if msg.SchemaVersion != model.InterceptMessageSchemaVersion {
			mismatches++
			if !mismatchNoticed {
				mismatchNoticed = true
				fn(synthesizeVersionError(fmt.Sprintf("unsupported record version (got %d, want %d): is the daemon the same build?", msg.SchemaVersion, model.InterceptMessageSchemaVersion)))
			}
			continue
		}
		fn(sanitizeMessage(msg))
	}
	return sc.Err() // bufio.ErrTooLong if a line exceeded the cap, bounded, not an OOM
}

// synthesizeVersionError creates a single stream-level error event for the first malformed or
// version-mismatched record. It carries the current schema version so it passes the sanitize gate
// and is rendered in the inspector chrome with its reason.
func synthesizeVersionError(reason string) model.InterceptedMessage {
	return model.InterceptedMessage{
		SchemaVersion: model.InterceptMessageSchemaVersion,
		Status:        model.FlowError,
		Reason:        reason,
	}
}

// sanitizeMessage validates a message read from an UNTRUSTED source. Unknown Status is coerced per
// event class (message vs Seq-0 connection event) so a malformed record can't imply a state it does
// not represent; text fields are length-capped so an oversized record can't blow up the viewer's
// memory. The TUI still applies model.Clean at render time.
func sanitizeMessage(msg model.InterceptedMessage) model.InterceptedMessage {
	if msg.Seq == 0 {
		// Connection-level event: State must be empty; Status is one of the closed set.
		switch msg.Status {
		case model.FlowPinned, model.FlowOpaque, model.FlowError:
		default:
			msg.Status = model.FlowError
		}
		msg.State = ""
	} else {
		// Message event: Status is decrypted; State is one of the closed set.
		msg.Status = model.FlowDecrypted
		switch msg.State {
		case model.StateComplete, model.StatePartial, model.StateStreaming:
		default:
			msg.State = model.StatePartial
		}
	}

	msg.App = capStr(msg.App, 256)
	msg.Path = capStr(msg.Path, 4096)
	msg.Text = capStr(msg.Text, maxFieldLen)
	msg.Reason = capStr(msg.Reason, 512)
	msg.DestName = capStr(msg.DestName, 512)
	msg.SNI = capStr(msg.SNI, 512)
	msg.At = capStr(msg.At, 64)
	msg.DestIP = capStr(msg.DestIP, 64)
	msg.ConnID = capStr(msg.ConnID, 128)
	return msg
}

func capStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
