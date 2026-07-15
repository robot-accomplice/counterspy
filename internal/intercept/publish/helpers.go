package publish

import (
	"bufio"
	"encoding/json"
	"io"
	"os"

	"counterspy/internal/model"
)

const (
	maxFlowLine = 4 << 20  // cap one JSONL record so a giant/garbage line can't OOM a reader
	maxFieldLen = 64 << 10 // cap decrypted text fields from an untrusted source before display/re-publish
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

// scanFlows reads newline-delimited JSON flows from r, size-bounding each line (no OOM on a giant
// record) and skipping a malformed one, calling fn with each sanitized flow. Shared by the socket and
// log readers — both consume untrusted input (anyone who can write the socket/log).
func scanFlows(r io.Reader, fn func(model.InterceptedFlow)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxFlowLine)
	for sc.Scan() {
		var fl model.InterceptedFlow
		if json.Unmarshal(sc.Bytes(), &fl) == nil {
			fn(sanitizeFlow(fl))
		}
	}
	return sc.Err() // bufio.ErrTooLong if a line exceeded the cap — bounded, not an OOM
}

// sanitizeFlow validates a flow read from an UNTRUSTED source. An unknown Status is coerced to
// FlowError so a malformed record can't imply a state (e.g. "decrypted") it doesn't represent (the
// deferred cp-p2a consumer-side validation); text fields are length-capped so an oversized record
// can't blow up the viewer's memory. The TUI still applies model.Clean at render time.
func sanitizeFlow(fl model.InterceptedFlow) model.InterceptedFlow {
	switch fl.Status {
	case model.FlowDecrypted, model.FlowPinned, model.FlowOpaque, model.FlowError:
	default:
		fl.Status = model.FlowError
	}
	fl.SentText = capStr(fl.SentText, maxFieldLen)
	fl.RecvText = capStr(fl.RecvText, maxFieldLen)
	fl.DestName = capStr(fl.DestName, 512)
	fl.SNI = capStr(fl.SNI, 512)
	return fl
}

func capStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
