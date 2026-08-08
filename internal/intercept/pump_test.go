package intercept

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"counterspy/internal/intercept/ca"
	"counterspy/internal/model"
)

// runPumpedProxy stands up a proxy + TLS client pair and returns the live TLS connection, a buffered
// reader for responses, and a channel of published messages. The caller drives the exchange and must
// close cc.
func runPumpedProxy(t *testing.T, upstreamResponse string) (net.Conn, *bufio.Reader, <-chan model.InterceptedMessage) {
	t.Helper()
	dest, upCA := upstreamServer(t, upstreamResponse)
	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { pxLn.Close() })

	got := make(chan model.InterceptedMessage, 16)
	p := &Proxy{CA: proxyCA, Dial: dialTo(dest, upCA), Sink: chanSink(got)}
	go p.Serve(pxLn)

	raw := connectTunnel(t, pxLn.Addr().String(), "example.com:443")
	t.Cleanup(func() { raw.Close() })
	cc := tls.Client(raw, &tls.Config{RootCAs: poolFor(proxyCA), ServerName: "example.com"})
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client handshake with proxy leaf: %v", err)
	}
	return cc, bufio.NewReader(cc), got
}

// readResponse reads one HTTP/1.1 response from br and returns its body. It does NOT close the conn.
func readResponse(t *testing.T, br *bufio.Reader, reqMethod string) string {
	t.Helper()
	resp, err := http.ReadResponse(br, &http.Request{Method: reqMethod})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// drainMessages collects all messages already published, timing out if the expected count is not met.
func drainMessages(t *testing.T, ch <-chan model.InterceptedMessage, want int) []model.InterceptedMessage {
	t.Helper()
	var out []model.InterceptedMessage
	for len(out) < want {
		select {
		case m := <-ch:
			out = append(out, m)
		case <-time.After(2 * time.Second):
			t.Fatalf("expected %d messages, got %d after timeout", want, len(out))
		}
	}
	return out
}

// splitByDirection partitions published messages into requests and responses, each in per-direction
// publish order. Ordering *between* the two directions is deliberately not asserted anywhere: the
// pump parses each direction in its own goroutine (see runRelay), so a response may publish before
// the request it answers. Connection events (no Direction) land in neither slice, so a test that
// checks the returned lengths will catch one arriving unexpectedly instead of silently mistaking it
// for a message.
func splitByDirection(msgs []model.InterceptedMessage) (reqs, resps []model.InterceptedMessage) {
	for _, m := range msgs {
		switch m.Direction {
		case "request":
			reqs = append(reqs, m)
		case "response":
			resps = append(resps, m)
		}
	}
	return reqs, resps
}

func TestPump_PublishesRequestAndResponse(t *testing.T) {
	cc, br, got := runPumpedProxy(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	cc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer TOPSECRET\r\n\r\n"))
	if body := readResponse(t, br, http.MethodGet); body != "hi" {
		t.Fatalf("client body = %q, want hi", body)
	}
	cc.Close()

	msgs := drainMessages(t, got, 2)
	reqs, resps := splitByDirection(msgs)
	if len(reqs) != 1 || len(resps) != 1 {
		t.Fatalf("want exactly 1 request and 1 response, got %d/%d: %+v", len(reqs), len(resps), msgs)
	}
	req, resp := reqs[0], resps[0]
	if req.Seq == 0 || req.Seq != resp.Seq {
		t.Fatalf("request/response Seq mismatch: req=%d resp=%d", req.Seq, resp.Seq)
	}
	if !strings.Contains(req.Text, "GET / HTTP/1.1") {
		t.Fatalf("request text missing start line: %q", req.Text)
	}
	if strings.Contains(req.Text, "TOPSECRET") {
		t.Fatalf("Authorization secret must be masked before publish: %q", req.Text)
	}
	if !strings.Contains(resp.Text, "hi") {
		t.Fatalf("response text missing body: %q", resp.Text)
	}
	if req.State != model.StateComplete || resp.State != model.StateComplete {
		t.Fatalf("complete messages marked %q/%q", req.State, resp.State)
	}
}

func TestPump_HEADResponseHasNoBody(t *testing.T) {
	cc, br, got := runPumpedProxy(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
	cc.Write([]byte("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if body := readResponse(t, br, http.MethodHead); body != "" {
		t.Fatalf("HEAD response must have no body: %q", body)
	}
	cc.Close()

	msgs := drainMessages(t, got, 2)
	for _, m := range msgs {
		if m.Direction == "response" && m.Total != 0 {
			t.Fatalf("HEAD response should have Total 0, got %d", m.Total)
		}
	}
}

func TestPump_100ContinueIgnored(t *testing.T) {
	cc, br, got := runPumpedProxy(t, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
	cc.Write([]byte("POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi"))
	if body := readResponse(t, br, http.MethodPost); body != "" {
		t.Fatalf("100 Continue response must have no body: %q", body)
	}
	if body := readResponse(t, br, http.MethodPost); body != "ok" {
		t.Fatalf("final response body = %q, want ok", body)
	}
	cc.Close()

	msgs := drainMessages(t, got, 2)
	reqs, resps := splitByDirection(msgs)
	if len(reqs) != 1 || len(resps) != 1 {
		t.Fatalf("want exactly 1 request and 1 response, got %d/%d: %+v", len(reqs), len(resps), msgs)
	}
	// The interim 100 Continue must neither publish a message nor consume the queue entry, so the one
	// response we publish is the final 201 and it still correlates to the request's Seq.
	if !strings.Contains(resps[0].Text, "201 Created") {
		t.Fatalf("published response should be the final 201, got %q", resps[0].Text)
	}
	if strings.Contains(resps[0].Text, "100 Continue") {
		t.Fatalf("interim 100 Continue must not be published: %q", resps[0].Text)
	}
	if resps[0].Seq != reqs[0].Seq {
		t.Fatalf("response Seq %d should match request Seq %d", resps[0].Seq, reqs[0].Seq)
	}
}

// clientHelloBytes returns the raw TLS ClientHello a Go client sends for the given ALPN list.
func clientHelloBytes(t *testing.T, protos ...string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	var rec []byte
	go func() {
		defer close(done)
		buf := make([]byte, 8192)
		n, _ := c2.Read(buf)
		rec = append([]byte(nil), buf[:n]...)
	}()
	go func() {
		cfg := &tls.Config{NextProtos: protos, ServerName: "example.com", InsecureSkipVerify: true}
		client := tls.Client(c1, cfg)
		_ = client.Handshake()
		_ = client.Close()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out capturing ClientHello")
	}
	if len(rec) < 5 {
		t.Fatalf("captured ClientHello too short: %d bytes", len(rec))
	}
	return rec
}

func TestPump_isH2Only_DetectsH2Only(t *testing.T) {
	rec := clientHelloBytes(t, "h2")
	bc := &bufConn{Conn: &noopConn{}, buf: bufio.NewReader(bytes.NewReader(rec))}
	if !isH2Only(bc, time.Now().Add(time.Second)) {
		t.Fatal("expected h2-only ClientHello to trigger bypass")
	}
}

func TestPump_isH2Only_FailOpenForH2WithHttp11(t *testing.T) {
	rec := clientHelloBytes(t, "h2", "http/1.1")
	bc := &bufConn{Conn: &noopConn{}, buf: bufio.NewReader(bytes.NewReader(rec))}
	if isH2Only(bc, time.Now().Add(time.Second)) {
		t.Fatal("browser ALPN [h2, http/1.1] must be MITM'd, not bypassed")
	}
}

// noopConn satisfies net.Conn for bufConn tests where the buffered reader already has all bytes.
type noopConn struct{}

func (noopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (noopConn) Write([]byte) (int, error)        { return 0, nil }
func (noopConn) Close() error                     { return nil }
func (noopConn) LocalAddr() net.Addr              { return nil }
func (noopConn) RemoteAddr() net.Addr             { return nil }
func (noopConn) SetDeadline(time.Time) error      { return nil }
func (noopConn) SetReadDeadline(time.Time) error  { return nil }
func (noopConn) SetWriteDeadline(time.Time) error { return nil }

func TestPump_ALPNH2OnlyBypasses(t *testing.T) {
	dest, upCA := upstreamServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pxLn.Close()

	got := make(chan model.InterceptedMessage, 4)
	p := &Proxy{
		CA:   proxyCA,
		Dial: dialTo(dest, upCA),
		Sink: chanSink(got),
		DialPlain: func(network, addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, dest.String(), timeout)
		},
	}
	go p.Serve(pxLn)

	raw := connectTunnel(t, pxLn.Addr().String(), "example.com:443")
	defer raw.Close()
	// h2-only client: the proxy must bypass (blind-relay) so the real upstream cert reaches us.
	cc := tls.Client(raw, &tls.Config{
		RootCAs:            poolFor(upCA),
		ServerName:         "example.com",
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer certificates")
			}
			peer, _ := x509.ParseCertificate(rawCerts[0])
			if peer == nil {
				return fmt.Errorf("could not parse peer cert")
			}
			// Verify manually against the upstream CA so the test surfaces whose cert arrived.
			pool := poolFor(upCA)
			opts := x509.VerifyOptions{Roots: pool, DNSName: "example.com"}
			if _, err := peer.Verify(opts); err != nil {
				return fmt.Errorf("peer cert %q DNS=%v did not verify against upstream CA: %v", peer.Subject.CommonName, peer.DNSNames, err)
			}
			return nil
		},
	})
	if err := cc.Handshake(); err != nil {
		t.Fatalf("h2-only handshake through bypass failed: %v", err)
	}
	cc.Close()

	select {
	case m := <-got:
		if m.Status != model.FlowOpaque || !strings.Contains(m.Reason, "h2-only") {
			t.Fatalf("expected h2-only opaque event, got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bypass did not publish an opaque event")
	}
}

func TestPump_PipelinedKeepAlive(t *testing.T) {
	cc, br, got := runPumpedProxy(t, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nAHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB")
	cc.Write([]byte("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\nGET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if body := readResponse(t, br, http.MethodGet); body != "A" {
		t.Fatalf("first response = %q, want A", body)
	}
	if body := readResponse(t, br, http.MethodGet); body != "B" {
		t.Fatalf("second response = %q, want B", body)
	}
	cc.Close()

	msgs := drainMessages(t, got, 4)
	reqs, resps := splitByDirection(msgs)
	if len(reqs) != 2 || len(resps) != 2 {
		t.Fatalf("want 2 requests and 2 responses, got %d/%d: %+v", len(reqs), len(resps), msgs)
	}
	// What matters for pipelining is correlation, not arrival order: the two in-flight requests must
	// come back matched to the right responses: /a ↔ "A" on Seq 1, /b ↔ "B" on Seq 2. Each direction
	// publishes in order within itself, so Seqs ascend per direction.
	if reqs[0].Seq != 1 || reqs[1].Seq != 2 {
		t.Fatalf("request Seqs should ascend 1,2, got %d,%d", reqs[0].Seq, reqs[1].Seq)
	}
	if resps[0].Seq != 1 || resps[1].Seq != 2 {
		t.Fatalf("response Seqs should ascend 1,2, got %d,%d", resps[0].Seq, resps[1].Seq)
	}
	if !strings.Contains(reqs[0].Text, "GET /a") || !strings.Contains(reqs[1].Text, "GET /b") {
		t.Fatalf("requests mis-sequenced: %q / %q", reqs[0].Text, reqs[1].Text)
	}
	if !strings.HasSuffix(resps[0].Text, "A") || !strings.HasSuffix(resps[1].Text, "B") {
		t.Fatalf("responses not correlated to their requests: %q / %q", resps[0].Text, resps[1].Text)
	}
}

// newQueuePump returns a pump with an initialized correlation queue, matching how Proxy.pump builds
// one. The queue is the only field these unit tests exercise.
func newQueuePump() *pump {
	return &pump{queue: make(chan queueEntry, maxPipelinedRequests)}
}

// TestPump_PopWaitsForPush is the deterministic regression guard for the correlation race: a response
// can reach popQueue before the request goroutine has run pushQueue. popQueue MUST block until the
// request is enqueued and then correlate to it, never report the response as unmatched. Before the
// fix the two ran under a plain mutex and popQueue returned ok=false on the empty queue, which dropped
// the response and aborted the parser. This asserts the happens-before the pump depends on.
func TestPump_PopWaitsForPush(t *testing.T) {
	pu := newQueuePump()

	type popResult struct {
		method string
		seq    int
		ok     bool
	}
	done := make(chan popResult, 1)
	go func() {
		method, seq, ok := pu.popQueue() // called first, on an empty queue
		done <- popResult{method, seq, ok}
	}()

	// The pop is now blocked. Give it a moment to be genuinely waiting, then push its request.
	select {
	case r := <-done:
		t.Fatalf("popQueue returned %+v before any push; it must block on an empty queue", r)
	case <-time.After(50 * time.Millisecond):
	}

	if !pu.pushQueue(7, "GET") {
		t.Fatal("pushQueue reported overflow on an empty queue")
	}
	select {
	case r := <-done:
		if !r.ok || r.method != "GET" || r.seq != 7 {
			t.Fatalf("pop after push = %+v, want {GET 7 true}", r)
		}
	case <-time.After(time.Second):
		t.Fatal("popQueue did not wake after the matching push")
	}
}

// TestPump_PopUnblocksOnClose asserts the other half of the contract: an unmatched response must not
// wait forever. Once the request stream ends (closeRequests) with the queue empty, a blocked popQueue
// returns ok=false so parseResponses can mark the flow opaque instead of hanging the pump.
func TestPump_PopUnblocksOnClose(t *testing.T) {
	pu := newQueuePump()

	done := make(chan bool, 1)
	go func() {
		_, _, ok := pu.popQueue()
		done <- ok
	}()

	pu.closeRequests() // no request will ever arrive
	select {
	case ok := <-done:
		if ok {
			t.Fatal("popQueue on a closed empty queue must return ok=false (unmatched response)")
		}
	case <-time.After(time.Second):
		t.Fatal("popQueue did not unblock after closeRequests")
	}
}

// TestPump_RelayNoDeadlockOnUnmatchedResponse is the regression guard for ABORT review F1. A server
// that emits more responses than requests (adversarial or buggy: this tool inspects untrusted
// traffic) must not wedge the relay. The mutex→channel correlation fix made popQueue block; combined
// with the old synchronous tee that back-pressured the forward path, an unmatched response deadlocked
// runRelay permanently; CONFIRMED earlier via goroutine dump (parseResponses parked in popQueue while
// the response copyTee blocked on the tee pipe, so closeRequests could never run). The tee is now
// non-blocking, so a parked parser can never stall the relay: runRelay must return once the conns close.
func TestPump_RelayNoDeadlockOnUnmatchedResponse(t *testing.T) {
	var mu sync.Mutex
	var published []model.InterceptedMessage
	pu := &pump{
		queue: make(chan queueEntry, maxPipelinedRequests),
		publish: func(m model.InterceptedMessage) {
			mu.Lock()
			published = append(published, m)
			mu.Unlock()
		},
	}
	clientR, clientW := net.Pipe()
	upstreamR, upstreamW := net.Pipe()

	// Drain forwarded bytes so the relay's FORWARD path never blocks on the test side.
	go io.Copy(io.Discard, upstreamW) // forwarded requests (client→upstream)
	go io.Copy(io.Discard, clientW)   // forwarded responses (upstream→client)

	relayDone := make(chan struct{})
	go func() { pu.runRelay(clientR, upstreamR); close(relayDone) }()

	// One request, then a matched response followed by an UNMATCHED response whose body is far larger
	// than any parser read-ahead or the tee backlog. parseResponses parks in popQueue after the second
	// head, before reading its body, so with a synchronous tee the copy goroutine wedges mid-body with
	// bytes the parser will never drain, the confirmed F1 deadlock. With the non-blocking tee, teeing
	// detaches and the body still forwards, so the relay unwinds once the conns close.
	body := strings.Repeat("x", 300*1024)
	go clientW.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	go upstreamW.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA" +
		"HTTP/1.1 200 OK\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body))

	time.Sleep(200 * time.Millisecond) // let the unmatched response park parseResponses in popQueue
	clientW.Close()                    // both ends hang up; a correct relay now unwinds
	upstreamW.Close()

	select {
	case <-relayDone:
	case <-time.After(3 * time.Second):
		t.Fatal("runRelay did not return after the conns closed: F1 deadlock regression (idleTimeout is 5m)")
	}
	// F-A: the 300KB unmatched body overflows the tee backlog and detaches teeing, so capture is
	// incomplete; the relay MUST publish an opaque "tee detached" event, never silently under-report.
	mu.Lock()
	defer mu.Unlock()
	sawDetach := false
	for _, m := range published {
		if m.Status == model.FlowOpaque && strings.Contains(m.Reason, "tee detached") {
			sawDetach = true
		}
	}
	if !sawDetach {
		t.Fatalf("tee detach must publish an opaque 'capture incomplete' event, got %+v", published)
	}
}
