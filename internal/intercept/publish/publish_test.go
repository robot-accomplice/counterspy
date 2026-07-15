package publish

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"counterspy/internal/model"
)

func TestSocketSink_StreamsToReader(t *testing.T) {
	sock := shortSock(t)
	s, err := NewSocketSink(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got := make(chan model.InterceptedFlow, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ReadSocket(sock, func(f model.InterceptedFlow) { got <- f }) }()
	time.Sleep(50 * time.Millisecond) // let the reader connect

	s.Publish(model.InterceptedFlow{DestIP: "1.2.3.4", Status: model.FlowDecrypted, SentText: "hi"})
	select {
	case f := <-got:
		if f.DestIP != "1.2.3.4" || f.Status != model.FlowDecrypted || f.SentText != "hi" {
			t.Fatalf("flow not streamed intact: %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not receive the published flow")
	}
}

func TestSocketSink_SlowReaderDoesNotBlock(t *testing.T) {
	sock := shortSock(t)
	s, err := NewSocketSink(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go ReadSocket(sock, func(model.InterceptedFlow) { time.Sleep(time.Hour) }) // never drains
	time.Sleep(50 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			s.Publish(model.InterceptedFlow{Status: model.FlowDecrypted})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Publish blocked on a slow reader — the proxy must never stall")
	}
}

func TestLogSink_RotatesAndKeeps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	s, err := NewLogSink(path, 200 /*bytes*/, 2 /*keep*/, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		s.Publish(model.InterceptedFlow{DestIP: "1.2.3.4", Status: model.FlowDecrypted, SentText: "xxxxxxxxxx"})
	}
	s.Close()
	// active + at most `keep` rotated files, nothing more.
	if _, err := os.Stat(path); err != nil {
		t.Fatal("active log must exist")
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("expected a rotated .1")
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatal("keep=2 must not retain a .3")
	}
	// mode 0600
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("log must be 0600, got %v", fi.Mode().Perm())
	}
}

func TestLogSink_ReadBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	s, _ := NewLogSink(path, 0, 1, 0)
	s.Publish(model.InterceptedFlow{DestIP: "9.9.9.9", Status: model.FlowDecrypted})
	s.Publish(model.InterceptedFlow{DestIP: "8.8.8.8", Status: "BOGUS"}) // untrusted → coerced
	s.Close()
	var flows []model.InterceptedFlow
	if err := ReadLog(path, func(f model.InterceptedFlow) { flows = append(flows, f) }); err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 || flows[0].DestIP != "9.9.9.9" {
		t.Fatalf("read back wrong: %+v", flows)
	}
	if flows[1].Status != model.FlowError {
		t.Fatalf("an unknown Status must be coerced to error at the consumer, got %q", flows[1].Status)
	}
}

func TestFanout_BestEffort(t *testing.T) {
	var a, b countSink
	f := Fanout{&a, nil, &b}
	f.Publish(model.InterceptedFlow{Status: model.FlowDecrypted})
	if a.n != 1 || b.n != 1 {
		t.Fatalf("fanout must publish to all non-nil sinks: a=%d b=%d", a.n, b.n)
	}
	f.Close()
}

type countSink struct{ n int }

func (c *countSink) Publish(model.InterceptedFlow) error { c.n++; return nil }
func (c *countSink) Close() error                        { return nil }

// shortSock returns a socket path short enough for macOS's ~104-char sun_path limit (t.TempDir()
// embeds the long test name and overflows it — a real constraint the intercept command respects).
func shortSock(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "cs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "s.sock")
}
