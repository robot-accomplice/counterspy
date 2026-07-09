package feedback

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"counterspy/internal/model"
)

// HTTPTransmitter POSTs records to the author-owned endpoint. It is strictly egress-only:
// it reads ONLY the HTTP status code to decide keep-for-retry vs. clear, and discards the
// response body without decoding it. No allowlist/command/config can flow back.
type HTTPTransmitter struct {
	URL    string
	Client *http.Client
}

func (h *HTTPTransmitter) Send(ctx context.Context, records []model.FeedbackRecord) error {
	body, err := json.Marshal(records)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	// Egress-only: drain-and-discard. The body is NEVER decoded into program state.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("feedback endpoint returned %d", resp.StatusCode)
	}
	return nil
}
