package model

// InterceptedMessage is one event published by the Phase 2.5 per-message
// streaming proxy. It is the wire record (JSONL over the unix socket and/or
// rotating log) AND the type the merged Exfiltration view renders, so it lives
// in model (which tui may import). Content is already decoded and
// Redact-masked by the proxy before it reaches any sink, so no sink or viewer
// sees a raw secret.
type InterceptedMessage struct {
	SchemaVersion int    `json:"schema_version"`      // REQUIRED — see §3.1.7
	ConnID        string `json:"conn_id"`             // <proxy-start-epoch>-<seq>
	Seq           int    `json:"seq"`                 // exchange sequence within the connection; 0 for connection-level events
	Direction     string `json:"direction,omitempty"` // request | response; empty for connection-level events
	At            string `json:"at"`                  // RFC3339Nano, when THIS event completed
	PID           int    `json:"pid,omitempty"`
	App           string `json:"app,omitempty"`  // display name
	Path          string `json:"path,omitempty"` // resolved executable path — the join key for Exfiltration
	DestIP        string `json:"dest_ip"`
	DestName      string `json:"dest_name,omitempty"`
	SNI           string `json:"sni,omitempty"`
	Status        string `json:"status"`           // decrypted | pinned | opaque | error
	Text          string `json:"text,omitempty"`   // decoded + masked; empty for non-decrypted statuses
	Bytes         int    `json:"bytes"`            // wire bytes observed for this message AT PUBLISH TIME; 0 on Seq-0 events
	Total         int    `json:"total"`            // -1 = unknown, 0 = declared zero-length, >0 = Content-Length; 0 on Seq-0 events
	State         string `json:"state,omitempty"`  // message events only: complete | partial | streaming
	Reason        string `json:"reason,omitempty"` // partial / opaque / error / pinned detail
}

// InterceptMessageSchemaVersion is the current wire-format version. Old or
// missing versions are rejected by the reader with a single version-error
// event (§3.1.7).
const InterceptMessageSchemaVersion = 2

// MessageCaptureBytes bounds how many bytes of a single message direction the
// proxy keeps for decode/display. The wire is relayed in full regardless —
// this bounds only what we KEEP. It lives here because the viewer must also
// know it, to say when a message's text is a truncated capture rather than the
// whole thing.
const MessageCaptureBytes = 8 << 10

// Message state — applies to decrypted message events only (Seq > 0).
const (
	StateComplete  = "complete"
	StatePartial   = "partial"
	StateStreaming = "streaming"
)

// Flow status constants (FlowDecrypted, FlowPinned, FlowOpaque, FlowError) live
// in interceptflow.go for now; InterceptedMessage reuses the same closed set.
