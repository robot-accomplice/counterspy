package publish

import (
	"bufio"
	"encoding/json"
	"net"
	"sync"

	"counterspy/internal/model"
)

// socketSink serves published flows to connected console readers over a unix socket as JSONL. A slow
// or absent reader NEVER blocks the proxy: each reader has a bounded buffered channel and a full
// buffer drops the flow (counted) rather than stalling — the live view is best-effort by design.
type socketSink struct {
	ln       net.Listener
	mu       sync.Mutex
	readers  map[chan model.InterceptedFlow]struct{}
	closed   bool
	dropped  int
	bufPerRd int
}

// NewSocketSink listens on a unix socket at path (removing a stale one first) and serves readers.
func NewSocketSink(path string) (Sink, error) {
	_ = removeSocket(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	s := &socketSink{ln: ln, readers: map[chan model.InterceptedFlow]struct{}{}, bufPerRd: 256}
	go s.acceptLoop()
	return s, nil
}

func (s *socketSink) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		ch := make(chan model.InterceptedFlow, s.bufPerRd)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.readers[ch] = struct{}{}
		s.mu.Unlock()
		go s.serve(conn, ch)
	}
}

func (s *socketSink) serve(conn net.Conn, ch chan model.InterceptedFlow) {
	defer func() {
		s.mu.Lock()
		delete(s.readers, ch)
		s.mu.Unlock()
		conn.Close()
	}()
	enc := json.NewEncoder(conn)
	for fl := range ch {
		if err := enc.Encode(fl); err != nil {
			return // reader went away
		}
	}
}

func (s *socketSink) Publish(fl model.InterceptedFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.readers {
		select {
		case ch <- fl:
		default:
			s.dropped++ // reader too slow — drop, don't block the proxy
		}
	}
	return nil
}

func (s *socketSink) Close() error {
	s.mu.Lock()
	s.closed = true
	for ch := range s.readers {
		close(ch)
		delete(s.readers, ch)
	}
	s.mu.Unlock()
	err := s.ln.Close()
	removeSocket(s.ln.Addr().String())
	return err
}

func removeSocket(path string) error {
	if path == "" {
		return nil
	}
	return removeIfSocket(path)
}

// ReadSocket connects to a socketSink at path and calls fn for each flow until the connection ends.
func ReadSocket(path string, fn func(model.InterceptedFlow)) error {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	dec := json.NewDecoder(bufio.NewReader(conn))
	for {
		var fl model.InterceptedFlow
		if err := dec.Decode(&fl); err != nil {
			return err // EOF when the proxy stops
		}
		fn(sanitizeFlow(fl))
	}
}
