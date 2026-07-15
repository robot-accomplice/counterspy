package publish

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"counterspy/internal/model"
)

// logSink appends flows as JSONL to a 0600 file, rotating at maxSize (path.1 … path.keep) and pruning
// rotated files older than maxAge — the persisted output for after-the-fact console viewing (the
// --non-interactive logging vision). Content is already masked by the proxy.
type logSink struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	size    int64
	maxSize int64
	keep    int
	maxAge  time.Duration
}

// NewLogSink opens (creating) the log at path. maxSize<=0 disables size rotation; keep<1 → 1; maxAge<=0
// disables age pruning. The directory is created 0700; the file is 0600 (it holds decrypted content).
func NewLogSink(path string, maxSize int64, keep int, maxAge time.Duration) (Sink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if keep < 1 {
		keep = 1
	}
	l := &logSink{path: path, maxSize: maxSize, keep: keep, maxAge: maxAge}
	l.pruneAged()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	fi, _ := f.Stat()
	l.f, l.size = f, fi.Size()
	return l, nil
}

func (l *logSink) Publish(fl model.InterceptedFlow) error {
	b, err := json.Marshal(fl)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.maxSize > 0 && l.size+int64(len(b)) > l.maxSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	return err
}

// rotate closes the active file, shifts path.(keep-1)→path.keep … path→path.1 (dropping the oldest),
// and reopens a fresh path. Caller holds l.mu.
func (l *logSink) rotate() error {
	l.f.Close()
	os.Remove(fmt.Sprintf("%s.%d", l.path, l.keep))
	for i := l.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	os.Rename(l.path, l.path+".1")
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.f, l.size = f, 0
	return nil
}

// pruneAged deletes rotated files (path.1 … path.keep) whose mtime is older than maxAge.
func (l *logSink) pruneAged() {
	if l.maxAge <= 0 {
		return
	}
	cutoff := time.Now().Add(-l.maxAge)
	for i := 1; i <= l.keep; i++ {
		p := fmt.Sprintf("%s.%d", l.path, i)
		if fi, err := os.Stat(p); err == nil && fi.ModTime().Before(cutoff) {
			os.Remove(p)
		}
	}
}

func (l *logSink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// ReadLog streams the current log file's flows to fn (for the console). Best-effort: a malformed line
// is skipped. It reads the existing content once (not a live tail) — the socket is the live path.
func ReadLog(path string, fn func(model.InterceptedFlow)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var fl model.InterceptedFlow
		if json.Unmarshal(sc.Bytes(), &fl) == nil {
			fn(sanitizeFlow(fl))
		}
	}
	return sc.Err()
}
