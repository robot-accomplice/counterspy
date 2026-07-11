package feedback

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"counterspy/internal/model"
)

func TestHTTPTransmitter_PostsAndIgnoresBody(t *testing.T) {
	var got []model.FeedbackRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		// Return a body the client MUST ignore (egress-only): if the client ever decoded
		// this into an allowlist/command, that would violate the invariant.
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"command":"disable-all"}`))
	}))
	defer srv.Close()

	tx := &HTTPTransmitter{URL: srv.URL}
	if err := tx.Send(context.Background(), []model.FeedbackRecord{rec(model.LabelFalsePositive, "backdoor", "10-14")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(got) != 1 || got[0].Category != "backdoor" {
		t.Fatalf("server did not receive the record: %+v", got)
	}
}

func TestHTTPTransmitter_NonNamed2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	tx := &HTTPTransmitter{URL: srv.URL}
	if err := tx.Send(context.Background(), []model.FeedbackRecord{rec(model.LabelFalsePositive, "x", "0-4")}); err == nil {
		t.Fatal("a 500 must return an error so the record is kept for retry")
	}
}
