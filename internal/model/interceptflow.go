package model

// InterceptedFlow is one decrypted (or honestly-undecryptable) outbound TLS flow captured by the
// `counterspy intercept` proxy and published to the `counterspy console` viewer (Phase 2). It is BOTH
// the wire record (JSONL over the socket / rotating log) and the type the decoupled TUI renders — so
// it lives in model (which the tui may import), mirroring InspectView. Content is already decoded and
// Redact-masked by the proxy before it is ever published, so no sink or viewer sees a raw secret.
type InterceptedFlow struct {
	At        string `json:"at"` // RFC3339 capture time
	PID       int    `json:"pid,omitempty"`
	DestIP    string `json:"dest_ip"`
	DestName  string `json:"dest_name,omitempty"` // SNI or passively-resolved name, if known
	SNI       string `json:"sni,omitempty"`
	Status    string `json:"status"`              // one of the FlowStatus* constants below
	SentText  string `json:"sent_text,omitempty"` // decoded + masked request (client→server)
	RecvText  string `json:"recv_text,omitempty"` // decoded + masked response (server→client)
	SentBytes int    `json:"sent_bytes"`
	RecvBytes int    `json:"recv_bytes"`
}

// Flow status — the closed, honest set. "decrypted" is the only one carrying plaintext; the others say
// exactly why there is none, so the viewer never implies content it doesn't have.
const (
	FlowDecrypted = "decrypted" // TLS terminated + relayed; SentText/RecvText are the real plaintext
	FlowPinned    = "pinned"    // the app rejected our leaf (cert pinning) — bypassed, not decryptable
	FlowOpaque    = "opaque"    // not interceptable (e.g. non-TLS / unexpected protocol) — shown as-is
	FlowError     = "error"     // a capture/relay error; the connection was not tampered with
)
