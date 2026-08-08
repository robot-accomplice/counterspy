package model

import (
	"encoding/json"
	"testing"
)

func TestInterceptedFlow_JSONRoundTrip(t *testing.T) {
	f := InterceptedFlow{
		At: "2026-07-15T00:00:00Z", DestIP: "1.2.3.4", DestName: "api.example.com", SNI: "api.example.com",
		Status: FlowDecrypted, SentText: "GET / HTTP/1.1", RecvText: "HTTP/1.1 200 OK", SentBytes: 14, RecvBytes: 15,
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var back InterceptedFlow
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != f {
		t.Fatalf("round-trip lost data:\n%+v\n%+v", f, back)
	}
	// An opaque/pinned flow omits the text fields from the wire (no content to imply).
	pinned, _ := json.Marshal(InterceptedFlow{DestIP: "5.6.7.8", Status: FlowPinned})
	if string(pinned) == "" || contains(string(pinned), "sent_text") {
		t.Fatalf("a pinned flow must omit content fields: %s", pinned)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
