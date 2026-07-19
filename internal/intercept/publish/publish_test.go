package publish

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"counterspy/internal/model"
)

func sampleMsg(opts ...func(*model.InterceptedMessage)) model.InterceptedMessage {
	m := model.InterceptedMessage{
		SchemaVersion: model.InterceptMessageSchemaVersion,
		ConnID:        "1-1",
		Seq:           1,
		Direction:     "request",
		At:            time.Now().UTC().Format(time.RFC3339Nano),
		PID:           42,
		App:           "Test",
		Path:          "/Applications/Test.app/Contents/MacOS/Test",
		DestIP:        "1.2.3.4",
		DestName:      "example.com",
		Status:        model.FlowDecrypted,
		State:         model.StateComplete,
		Text:          "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		Bytes:         32,
		Total:         32,
	}
	for _, opt := range opts {
		opt(&m)
	}
	return m
}

func TestSocketSink_StreamsToReader(t *testing.T) {
	sock := shortSock(t)
	s, err := NewSocketSink(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got := make(chan model.InterceptedMessage, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); ReadSocket(sock, func(m model.InterceptedMessage) { got <- m }) }()
	time.Sleep(50 * time.Millisecond) // let the reader connect

	want := sampleMsg()
	s.Publish(want)
	select {
	case m := <-got:
		if m.DestIP != want.DestIP || m.Status != want.Status || m.Text != want.Text {
			t.Fatalf("message not streamed intact: %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not receive the published message")
	}
}

func TestSocketSink_SlowReaderDoesNotBlock(t *testing.T) {
	sock := shortSock(t)
	s, err := NewSocketSink(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go ReadSocket(sock, func(model.InterceptedMessage) { time.Sleep(time.Hour) }) // never drains
	time.Sleep(50 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			s.Publish(sampleMsg())
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
	s, err := NewLogSink(path, 500 /*bytes*/, 2 /*keep*/, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		s.Publish(sampleMsg(func(m *model.InterceptedMessage) {
			m.Text = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
		}))
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
	s.Publish(sampleMsg(func(m *model.InterceptedMessage) { m.DestIP = "9.9.9.9" }))
	s.Publish(sampleMsg(func(m *model.InterceptedMessage) {
		m.Seq = 0
		m.Direction = ""
		m.Status = "BOGUS"
		m.State = ""
	})) // untrusted Seq-0 → coerced
	s.Close()
	var msgs []model.InterceptedMessage
	if err := ReadLog(path, func(m model.InterceptedMessage) { msgs = append(msgs, m) }); err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].DestIP != "9.9.9.9" {
		t.Fatalf("read back wrong: %+v", msgs)
	}
	if msgs[1].Status != model.FlowError {
		t.Fatalf("an unknown Status on a Seq-0 event must be coerced to error, got %q", msgs[1].Status)
	}
}

func TestFanout_BestEffort(t *testing.T) {
	var a, b countSink
	f := Fanout{&a, nil, &b}
	f.Publish(sampleMsg())
	if a.n != 1 || b.n != 1 {
		t.Fatalf("fanout must publish to all non-nil sinks: a=%d b=%d", a.n, b.n)
	}
	f.Close()
}

type countSink struct{ n int }

func (c *countSink) Publish(model.InterceptedMessage) error { c.n++; return nil }
func (c *countSink) Close() error                           { return nil }

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

// cp-p2d F-5: a message read from an untrusted source has its text length-capped.
func TestSanitizeMessage_CapsAndCoerces(t *testing.T) {
	big := make([]byte, maxFieldLen+5000)
	msg := sanitizeMessage(model.InterceptedMessage{
		SchemaVersion: model.InterceptMessageSchemaVersion,
		Seq:           1,
		Status:        "weird",
		Text:          string(big),
		State:         "weird",
	})
	if msg.Status != model.FlowDecrypted {
		t.Fatalf("Seq>0 unknown status must coerce to decrypted, got %q", msg.Status)
	}
	if msg.State != model.StatePartial {
		t.Fatalf("Seq>0 unknown state must coerce to partial, got %q", msg.State)
	}
	if len(msg.Text) > maxFieldLen {
		t.Fatalf("Text must be capped to %d, got %d", maxFieldLen, len(msg.Text))
	}
}

func TestSanitizeMessage_Seq0CoercesStatus(t *testing.T) {
	msg := sanitizeMessage(model.InterceptedMessage{
		SchemaVersion: model.InterceptMessageSchemaVersion,
		Seq:           0,
		Status:        "weird",
		State:         "weird",
	})
	if msg.Status != model.FlowError {
		t.Fatalf("Seq-0 unknown status must coerce to error, got %q", msg.Status)
	}
	if msg.State != "" {
		t.Fatalf("Seq-0 state must be empty, got %q", msg.State)
	}
}

// cp-p2d F-4: dropped messages are counted + surfaced (not silent).
func TestSocketSink_DroppedIsSurfaced(t *testing.T) {
	sock := shortSock(t)
	s, err := NewSocketSink(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go ReadSocket(sock, func(model.InterceptedMessage) { time.Sleep(time.Hour) })
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 5000; i++ {
		s.Publish(sampleMsg())
	}
	if ss, ok := s.(interface{ Dropped() int }); ok {
		if ss.Dropped() == 0 {
			t.Fatal("a flooded slow reader must record drops (Rule 14 visibility)")
		}
	} else {
		t.Fatal("socket sink should expose Dropped()")
	}
}

// A record with a missing or mismatched SchemaVersion produces exactly one error event.
func TestScanMessages_VersionGate(t *testing.T) {
	old := model.InterceptedMessage{
		SchemaVersion: 1,
		ConnID:        "old",
		Seq:           1,
		Status:        model.FlowDecrypted,
		State:         model.StateComplete,
	}
	good := sampleMsg()

	var pr, pw = ioPipe()
	enc := json.NewEncoder(pw)
	enc.Encode(old)
	enc.Encode(old)
	enc.Encode(good)
	pw.Close()

	var got []model.InterceptedMessage
	if err := scanMessages(pr, func(m model.InterceptedMessage) { got = append(got, m) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 emitted messages (one error + one good), got %d", len(got))
	}
	if got[0].Status != model.FlowError || got[0].SchemaVersion != model.InterceptMessageSchemaVersion {
		t.Fatalf("first mismatch must be an error event with current schema version, got %+v", got[0])
	}
	if got[1].ConnID != good.ConnID {
		t.Fatalf("good record must follow, got %+v", got[1])
	}
}

func ioPipe() (*os.File, *os.File) {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	return r, w
}
