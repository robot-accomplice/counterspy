package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInterceptedMessage_JSONRoundTrip(t *testing.T) {
	m := InterceptedMessage{
		SchemaVersion: InterceptMessageSchemaVersion,
		ConnID:        "1234567890123456789-abc-7",
		Seq:           3,
		Direction:     "request",
		At:            "2026-07-17T12:34:56.123456789Z",
		PID:           1234,
		App:           "Safari",
		Path:          "/Applications/Safari.app/Contents/MacOS/Safari",
		DestIP:        "1.2.3.4",
		DestName:      "api.example.com",
		SNI:           "api.example.com",
		Status:        FlowDecrypted,
		Text:          "GET / HTTP/1.1",
		Bytes:         14,
		Total:         14,
		State:         StateComplete,
		Reason:        "",
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back InterceptedMessage
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != m {
		t.Fatalf("round-trip lost data:\n%+v\n%+v", m, back)
	}
}

func TestInterceptedMessage_Seq0OmitsMessageFields(t *testing.T) {
	m := InterceptedMessage{
		SchemaVersion: InterceptMessageSchemaVersion,
		ConnID:        "1234567890123456789-abc-7",
		Seq:           0,
		At:            "2026-07-17T12:34:56Z",
		Status:        FlowOpaque,
		Reason:        "h2-only client — bypassed",
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "direction") {
		t.Fatalf("Seq-0 event must omit direction: %s", b)
	}
	if strings.Contains(string(b), "state") {
		t.Fatalf("Seq-0 event must omit state: %s", b)
	}
	if strings.Contains(string(b), "text") {
		t.Fatalf("Seq-0 event must omit text: %s", b)
	}
}

func TestInterceptedMessage_UnknownTotal(t *testing.T) {
	m := InterceptedMessage{
		SchemaVersion: InterceptMessageSchemaVersion,
		ConnID:        "x-1",
		Seq:           1,
		Direction:     "response",
		Status:        FlowDecrypted,
		State:         StateStreaming,
		Total:         -1,
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back InterceptedMessage
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Total != -1 {
		t.Fatalf("Total -1 must round-trip, got %d", back.Total)
	}
}
