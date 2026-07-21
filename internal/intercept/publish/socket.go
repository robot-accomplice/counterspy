package publish

import (
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"counterspy/internal/model"
)

// socketWriteTimeout bounds a single write to a reader so a stalled-but-connected console can't hang
// the serve goroutine forever (Audit cp-p2d F-1). A slow reader gets torn down, not tolerated.
const socketWriteTimeout = 10 * time.Second

// reader is one connected console: a bounded buffered channel + its conn (tracked so Close can
// force-close it, unblocking a stalled write).
type reader struct {
	ch   chan model.InterceptedMessage
	conn net.Conn
}

// socketSink serves published messages to connected console readers over a unix socket as JSONL. A slow
// or absent reader NEVER blocks the proxy: each reader has a bounded channel and a full buffer drops
// the message (counted) rather than stalling — the live view is best-effort by design.
type socketSink struct {
	ln      net.Listener
	mu      sync.Mutex
	readers map[*reader]struct{}
	closed  bool
	dropped int
}

// NewSocketSink listens on a unix socket at path (removing a stale one first) and serves readers.
// The socket carries decrypted plaintext, so it is chmod'd 0600 explicitly rather than trusting the
// ambient umask (under a permissive umask net.Listen would leave it group/world-connectable); the
// caller then chowns it to the invoking user. (ABORT Sock1.)
func NewSocketSink(path string) (Sink, error) {
	_ = removeIfSocket(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	s := &socketSink{ln: ln, readers: map[*reader]struct{}{}}
	go s.acceptLoop()
	return s, nil
}

func (s *socketSink) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		r := &reader{ch: make(chan model.InterceptedMessage, 256), conn: conn}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.readers[r] = struct{}{}
		s.mu.Unlock()
		go s.serve(r)
	}
}

func (s *socketSink) serve(r *reader) {
	defer func() {
		s.mu.Lock()
		delete(s.readers, r)
		s.mu.Unlock()
		r.conn.Close()
	}()
	enc := json.NewEncoder(r.conn)
	for msg := range r.ch {
		r.conn.SetWriteDeadline(time.Now().Add(socketWriteTimeout))
		if err := enc.Encode(msg); err != nil {
			return // reader went away or stalled past the deadline
		}
	}
}

func (s *socketSink) Publish(msg model.InterceptedMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for r := range s.readers {
		select {
		case r.ch <- msg:
		default:
			s.dropped++ // reader too slow — drop, don't block the proxy
		}
	}
	return nil
}

// Dropped is how many messages were dropped for slow readers — surfaced so the drop isn't silent
// (Rule 14 / Audit cp-p2d F-4); the daemon/console can report it.
func (s *socketSink) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

func (s *socketSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for r := range s.readers {
		close(r.ch)
		r.conn.Close() // force-close so a serve() stalled in a write unblocks (F-1)
		delete(s.readers, r)
	}
	path := s.ln.Addr().String()
	s.mu.Unlock()
	err := s.ln.Close()
	removeIfSocket(path)
	return err
}

// ReadSocket connects to a socketSink at path and calls fn for each message until the connection ends.
// Bounded + resilient: each JSONL line is size-capped and a malformed line is skipped, so a giant or
// garbage record can't OOM or abort the reader (untrusted-input hardening, Audit cp-p2d F-5).
func ReadSocket(path string, fn func(model.InterceptedMessage)) error {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	return scanMessages(conn, fn)
}
