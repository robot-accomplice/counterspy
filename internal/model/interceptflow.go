package model

// InterceptedFlow is one decrypted (or honestly-undecryptable) outbound TLS flow captured by the
// `counterspy intercept` proxy and published to the `counterspy console` viewer (Phase 2). It is BOTH
// the wire record (JSONL over the socket / rotating log) and the type the decoupled TUI renders — so
// it lives in model (which the tui may import), mirroring InspectView. Content is already decoded and
// Redact-masked by the proxy before it is ever published, so no sink or viewer sees a raw secret.
type InterceptedFlow struct {
	At        string `json:"at"`             // RFC3339 capture time
	PID       int    `json:"pid,omitempty"`  // the originating process, when it could be attributed
	App       string `json:"app,omitempty"`  // its process name ("Safari"); "" when unattributed
	Path      string `json:"path,omitempty"` // resolved executable path — the Exfiltration join key
	DestIP    string `json:"dest_ip"`
	DestName  string `json:"dest_name,omitempty"` // SNI or passively-resolved name, if known
	SNI       string `json:"sni,omitempty"`
	Status    string `json:"status"`              // one of the FlowStatus* constants below
	SentText  string `json:"sent_text,omitempty"` // decoded + masked request (client→server)
	RecvText  string `json:"recv_text,omitempty"` // decoded + masked response (server→client)
	SentBytes int    `json:"sent_bytes"`
	RecvBytes int    `json:"recv_bytes"`
}

// FlowCaptureBytes is how many bytes PER DIRECTION the proxy keeps for decode/display. The wire is
// relayed in full regardless — this bounds only what we KEEP. It lives here, not in the proxy, because
// the VIEWER needs it too: a flow whose SentBytes/RecvBytes exceed this was truncated AT CAPTURE, and
// showing its text without saying so implies content we never had.
const FlowCaptureBytes = 8 << 10

// Flow status — the closed, honest set. "decrypted" is the only one carrying plaintext; the others say
// exactly why there is none, so the viewer never implies content it doesn't have.
const (
	FlowDecrypted = "decrypted" // TLS terminated + relayed; SentText/RecvText are the real plaintext
	FlowPinned    = "pinned"    // the app rejected our leaf (cert pinning) — bypassed, not decryptable
	FlowOpaque    = "opaque"    // not interceptable (e.g. non-TLS / unexpected protocol) — shown as-is
	FlowError     = "error"     // a capture/relay error; the connection was not tampered with
)
