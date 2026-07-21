package intercept

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"counterspy/internal/inspect"
	"counterspy/internal/intercept/ca"
	"counterspy/internal/model"
)

// Per-message pump bounds. These are intentionally constants: the CLI surface is frozen, and the
// values were chosen to keep memory bounded without materially changing what traffic can be watched.
const (
	maxMessageBytes      = 1 << 20  // 1 MiB per message (header + body)
	maxHeaderBytes       = 64 << 10 // 64 KiB per header block
	maxPipelinedRequests = 64       // request→response correlation queue
	maxLinger            = 30 * time.Second
	// Backlog for the non-blocking tee into each framing parser; one slot per forward chunk (≤32 KiB).
	// When a parser falls this far behind, teeing detaches so it can never back-pressure — let alone
	// deadlock — the relayed connection (cp-p25 ABORT F1).
	maxTeeBacklogChunks = 8
)

// pump is the per-message streaming relay. It terminates the client's TLS, dials the real target,
// forwards bytes verbatim, and parses HTTP/1.1 messages out of a copy of each direction.
type pump struct {
	ca         *ca.CA
	dial       dialFunc
	dialPlain  func(network, addr string, timeout time.Duration) (net.Conn, error)
	publish    func(model.InterceptedMessage)
	connID     string
	pid        int
	app        string
	path       string
	target     string
	targetHost string
	sni        string
	destIP     string

	seq        atomic.Uint64
	opaqueOnce sync.Once

	// queue correlates each request to its response in HTTP/1.1 FIFO order. It is a single-producer
	// (parseRequests) / single-consumer (parseResponses) channel: a blocking receive makes the
	// response side wait for the matching request to be enqueued instead of racing it. The request
	// side closes the channel at EOF, which is the only point at which a still-empty queue means a
	// genuinely unmatched response rather than one the request goroutine has not caught up to yet.
	queue chan queueEntry
}

type queueEntry struct {
	seq    int
	method string
}

// run executes the whole pump lifecycle for one CONNECT tunnel and always closes the client conn.
func (p *Proxy) pump(client net.Conn, target string, pid int, app, path, connID string, dial dialFunc) {
	targetHost, _, err := net.SplitHostPort(target)
	if err != nil {
		targetHost = target
	}

	pu := &pump{
		ca:         p.CA,
		dial:       dial,
		dialPlain:  p.DialPlain,
		publish:    p.publish,
		connID:     connID,
		pid:        pid,
		app:        app,
		path:       path,
		target:     target,
		targetHost: targetHost,
		queue:      make(chan queueEntry, maxPipelinedRequests),
	}

	// C4 ALPN-aware bypass: an h2-only client is blind-relayed so it keeps working; browsers that
	// offer both are still MITM'd and downgraded to HTTP/1.1. Any peek ambiguity fail-opens to MITM.
	if isH2Only(client, time.Now().Add(handshakeTimeout)) {
		pu.publish(connEvent(connID, pid, app, path, model.FlowOpaque, "h2-only client — bypassed"))
		pu.bypass(client, target)
		return
	}

	server, ok := pu.terminateTLS(client)
	if !ok {
		return
	}

	upstream, err := dial("tcp", target, &tls.Config{ServerName: targetHost})
	if err != nil {
		pu.publish(connEvent(connID, pid, app, path, model.FlowError, "upstream dial: "+err.Error()))
		server.Close()
		return
	}
	if ap, perr := netip.ParseAddrPort(upstream.RemoteAddr().String()); perr == nil {
		pu.destIP = ap.Addr().String()
	}

	pu.runRelay(server, upstream)
}

// terminateTLS performs the local TLS termination with a CA leaf. It publishes a Seq-0 event and
// closes the client conn on any failure.
func (pu *pump) terminateTLS(client net.Conn) (net.Conn, bool) {
	var sni string
	var sawClientHello bool
	var mintErr error
	server := tls.Server(client, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sawClientHello = true
			sni = chi.ServerName
			host := chi.ServerName
			if host == "" {
				host = pu.targetHost
			}
			leaf, err := pu.ca.LeafFor(host)
			mintErr = err
			return leaf, err
		},
	})
	client.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := server.Handshake(); err != nil {
		var status, reason string
		switch {
		case mintErr != nil:
			status, reason = model.FlowError, mintErr.Error()
		case !sawClientHello:
			status, reason = model.FlowOpaque, "non-TLS bytes on proxy port"
		default:
			status, reason = model.FlowPinned, "client rejected the intercept leaf"
		}
		pu.publish(connEvent(pu.connID, pu.pid, pu.app, pu.path, status, reason))
		client.Close()
		return nil, false
	}
	client.SetDeadline(time.Time{})
	pu.sni = sni
	return server, true
}

// bypass blind-relays the raw TLS bytes between client and upstream. It is used for the h2-only
// ALPN bypass so those clients keep working while remaining opaque to us.
func (pu *pump) bypass(client net.Conn, target string) {
	dial := pu.dialPlain
	if dial == nil {
		dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		}
	}
	upstream, err := dial("tcp", target, dialTimeout)
	if err != nil {
		client.Close()
		return
	}

	done := make(chan struct{}, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src, other net.Conn) {
		defer wg.Done()
		copyIdle(dst, src, nil)
		done <- struct{}{}
		if other != nil {
			_ = other.SetReadDeadline(time.Now().Add(maxLinger))
		}
	}
	go cp(upstream, client, upstream)
	go cp(client, upstream, client)
	<-done
	<-done
	wg.Wait()
	client.Close()
	upstream.Close()
}

// runRelay copies both directions verbatim while teeing a copy into HTTP/1.1 framing parsers. The
// tee is non-blocking (see teeFeeder): a slow or parked parser can never back-pressure the forward
// path, so parsing cannot stall or deadlock the relayed connection. Each parser goroutine closes its
// read end on exit so a feeder blocked writing to an abandoned pipe is always released.
func (pu *pump) runRelay(client, upstream net.Conn) {
	reqRd, reqWr := io.Pipe()
	respRd, respWr := io.Pipe()

	var feederWg sync.WaitGroup
	reqTee := newTeeFeeder(reqWr, &feederWg)
	respTee := newTeeFeeder(respWr, &feederWg)

	done := make(chan struct{}, 2)
	cp := func(dst, src, other net.Conn, tee *teeFeeder) {
		copyTee(dst, src, tee)
		tee.close() // no more chunks; the feeder flushes buffered bytes then closes the pipe → EOF
		done <- struct{}{}
		if other != nil {
			_ = other.SetReadDeadline(time.Now().Add(maxLinger))
		}
	}
	go cp(upstream, client, upstream, reqTee)
	go cp(client, upstream, client, respTee)

	var parseWg sync.WaitGroup
	parseWg.Add(2)
	go func() {
		defer parseWg.Done()
		defer reqRd.Close() // release the request feeder if the parser abandons the stream
		pu.parseRequests(reqRd)
		pu.closeRequests() // request stream ended → release any response waiting on a missing request
	}()
	go func() {
		defer parseWg.Done()
		defer respRd.Close()
		pu.parseResponses(respRd)
	}()

	<-done
	<-done
	parseWg.Wait()
	feederWg.Wait()
	client.Close()
	upstream.Close()
}

// teeFeeder is a bounded, non-blocking bridge from the relay's forward path to a framing parser.
// submit never blocks: when the parser has fallen maxTeeBacklogChunks behind (it is slow or parked in
// popQueue), the chunk is refused and the caller detaches teeing, so forwarding is never
// back-pressured by parsing — the "never affects traffic" invariant. A feeder goroutine drains the
// buffer into the pipe the parser reads; close ends the stream so the parser sees EOF.
type teeFeeder struct {
	ch chan []byte
}

func newTeeFeeder(pw *io.PipeWriter, wg *sync.WaitGroup) *teeFeeder {
	t := &teeFeeder{ch: make(chan []byte, maxTeeBacklogChunks)}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for chunk := range t.ch {
			if _, err := pw.Write(chunk); err != nil {
				return // the parser closed its read end; stop — forwarding is unaffected
			}
		}
		pw.Close() // producer finished cleanly → signal EOF to the parser
	}()
	return t
}

// submit hands a copy of chunk to the feeder without blocking, returning false when the backlog is
// full so the caller stops teeing this connection. The copy is required because the caller reuses buf.
func (t *teeFeeder) submit(chunk []byte) bool {
	dup := make([]byte, len(chunk))
	copy(dup, chunk)
	select {
	case t.ch <- dup:
		return true
	default:
		return false
	}
}

func (t *teeFeeder) close() { close(t.ch) }

// copyTee forwards src→dst and hands a copy of each chunk to the tee. Teeing is best-effort: if the
// parser falls behind (submit returns false) teeing detaches and forwarding continues, so a slow or
// stuck parser never affects the relayed connection.
func copyTee(dst net.Conn, src net.Conn, tee *teeFeeder) {
	buf := make([]byte, 32*1024)
	teeing := true
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if teeing && !tee.submit(buf[:n]) {
				teeing = false
			}
		}
		if err != nil {
			return
		}
	}
}

// parseRequests consumes the client→server copy and publishes one event per request.
func (pu *pump) parseRequests(r io.Reader) {
	f := newFramingReader(r, model.MessageCaptureBytes, maxMessageBytes, maxHeaderBytes)
	for {
		method, requestURI, proto, header, err := f.readRequestHead()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			pu.markOpaque("framing lost: " + err.Error())
			return
		}

		seq := int(pu.seq.Add(1))
		if !pu.pushQueue(seq, method) {
			pu.markOpaque("request queue overflow")
			return
		}

		body, total, _, truncated, reason, err := f.readBody(header, method, 0)
		state := model.StateComplete
		if err != nil || truncated {
			state = model.StatePartial
			if reason == "" {
				if err != nil {
					reason = "connection closed"
				} else {
					reason = "message size exceeded"
				}
			}
		}

		pu.publishMessage(seq, "request", method+" "+requestURI+" "+proto, header, body, f.consumed, total, state, reason)
	}
}

// parseResponses consumes the server→client copy and publishes one event per final response.
func (pu *pump) parseResponses(r io.Reader) {
	f := newFramingReader(r, model.MessageCaptureBytes, maxMessageBytes, maxHeaderBytes)
	for {
		proto, status, reasonPhrase, header, err := f.readResponseHead()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			pu.markOpaque("framing lost: " + err.Error())
			return
		}

		// Interim 1xx (except 101) have no body and do not consume a queue entry.
		if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
			continue
		}

		method, seq, ok := pu.popQueue()
		if !ok {
			pu.markOpaque("response without matching request")
			return
		}

		body, total, _, truncated, reason, err := f.readBody(header, method, status)
		state := model.StateComplete
		if err != nil || truncated {
			state = model.StatePartial
			if reason == "" {
				if err != nil {
					reason = "connection closed"
				} else {
					reason = "message size exceeded"
				}
			}
		}

		startLine := proto + " " + strconv.Itoa(status)
		if reasonPhrase != "" {
			startLine += " " + reasonPhrase
		}
		pu.publishMessage(seq, "response", startLine, header, body, f.consumed, total, state, reason)
	}
}

// pushQueue enqueues a parsed request for correlation. It never blocks: a full queue means more than
// maxPipelinedRequests requests are outstanding, which we treat as overflow (return false) rather
// than stalling the request parser.
func (pu *pump) pushQueue(seq int, method string) bool {
	select {
	case pu.queue <- queueEntry{seq: seq, method: method}:
		return true
	default:
		return false
	}
}

// popQueue blocks until the matching request is enqueued, then returns it. A closed, drained queue
// (closeRequests ran at request-stream EOF) yields ok=false — the only condition under which a
// response is genuinely unmatched rather than merely ahead of its request goroutine.
func (pu *pump) popQueue() (string, int, bool) {
	e, ok := <-pu.queue
	if !ok {
		return "", 0, false
	}
	return e.method, e.seq, true
}

// closeRequests signals that no further requests will be enqueued. Called exactly once, after
// parseRequests returns on any path (EOF or framing loss), so a response waiting in popQueue for a
// request that will never arrive is released instead of blocking for the connection's lifetime.
func (pu *pump) closeRequests() {
	close(pu.queue)
}

func (pu *pump) markOpaque(reason string) {
	pu.opaqueOnce.Do(func() {
		pu.publish(connEvent(pu.connID, pu.pid, pu.app, pu.path, model.FlowOpaque, reason))
	})
}

func (pu *pump) publishMessage(seq int, direction, startLine string, header http.Header, body []byte, bytes, total int, state, reason string) {
	text := formatMessageText(startLine, header, body)
	pu.publish(model.InterceptedMessage{
		SchemaVersion: model.InterceptMessageSchemaVersion,
		ConnID:        pu.connID,
		Seq:           seq,
		Direction:     direction,
		At:            nowRFC3339(),
		PID:           pu.pid,
		App:           pu.app,
		Path:          pu.path,
		DestIP:        pu.destIP,
		DestName:      pu.targetHost,
		SNI:           pu.sni,
		Status:        model.FlowDecrypted,
		Text:          text,
		Bytes:         bytes,
		Total:         total,
		State:         state,
		Reason:        reason,
	})
}

// formatMessageText renders a captured message as displayable text: HTTP start line + headers +
// decoded body, then Redact-masks it. Binary or unparseable bodies become "" so the viewer never
// implies plaintext it does not have.
func formatMessageText(startLine string, header http.Header, body []byte) string {
	var b bytes.Buffer
	b.WriteString(startLine)
	b.WriteString("\r\n")
	for k, vs := range header {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	raw := b.Bytes()

	if decoded, ok := inspect.DecodeCleartext(raw); ok {
		return model.Redact(decoded)
	}
	if looksText(raw) {
		return model.Redact(string(raw))
	}
	return ""
}

// isH2Only peeks the ClientHello ALPN list. It returns true only when ALPN is non-empty,
// contains "h2", and lacks "http/1.1". Any ambiguity (timeout, parser failure, fragmented
// handshake) returns false so we fail-open to the normal MITM path.
func isH2Only(conn net.Conn, deadline time.Time) bool {
	bc, ok := conn.(*bufConn)
	if !ok {
		return false
	}
	// Wait for at least one TLS record, but no longer than the handshake deadline. A client that
	// waits for the CONNECT response before sending ClientHello will unblock once we send it.
	_ = bc.Conn.SetReadDeadline(deadline)
	defer bc.Conn.SetReadDeadline(time.Time{})

	const tlsRecordHeaderLen = 5
	hdr, err := bc.buf.Peek(tlsRecordHeaderLen)
	_ = bc.Conn.SetReadDeadline(time.Time{}) // clear as soon as we have bytes
	if err != nil || len(hdr) < tlsRecordHeaderLen || hdr[0] != 0x16 {
		return false
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	const maxRecord = 1 << 14 // TLS records are at most 16 KiB; larger → garbage/fail-open.
	if recLen > maxRecord {
		return false
	}
	rec, err := bc.buf.Peek(tlsRecordHeaderLen + recLen)
	if err != nil {
		return false
	}
	protos, ok := inspect.ClientHelloALPN(rec)
	if !ok {
		return false
	}
	hasH2 := false
	hasH1 := false
	for _, p := range protos {
		if p == "h2" {
			hasH2 = true
		}
		if p == "http/1.1" {
			hasH1 = true
		}
	}
	return hasH2 && !hasH1
}
