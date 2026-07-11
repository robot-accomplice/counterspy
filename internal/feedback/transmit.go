package feedback

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"counterspy/internal/model"
)

// Transmitter is the write-only egress seam. It returns ONLY an error — there is no
// method that reads, so the network can never speak back into program state
// (egress-only invariant; enforced by TestEgressOnly).
type Transmitter interface {
	Send(ctx context.Context, records []model.FeedbackRecord) error
}

// FileTransmitter appends records as JSONL — the build/test stub and the manual-export path.
type FileTransmitter struct{ Path string }

func (f *FileTransmitter) Send(_ context.Context, records []model.FeedbackRecord) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(f.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	enc := json.NewEncoder(fh)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
