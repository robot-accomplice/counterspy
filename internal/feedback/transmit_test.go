package feedback

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"counterspy/internal/model"
)

func TestFileTransmitter_WritesJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.jsonl")
	var tx Transmitter = &FileTransmitter{Path: p}
	err := tx.Send(context.Background(), []model.FeedbackRecord{
		rec(model.LabelFalsePositive, "backdoor", "10-14"),
		rec(model.LabelTruePositive, "keylogger", "15+"),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d: %s", len(lines), b)
	}
	if !strings.Contains(lines[0], `"category":"backdoor"`) {
		t.Fatalf("line not a record: %s", lines[0])
	}
}
