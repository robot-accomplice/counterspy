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

func TestPump_PublishesRequestAndResponse(t *testing.T) {
	cc, br, got := runPumpedProxy(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	cc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer TOPSECRET\r\n\r\n"))
	if body := readResponse(t, br, http.MethodGet); body != "hi" {
		t.Fatalf("client body = %q, want hi", body)
	}
	cc.Close()

	msgs := drainMessages(t, got, 2)
	var req, resp model.InterceptedMessage
	for _, m := range msgs {
		if m.Direction == "request" {
			req = m
		} else {
			resp = m
		}
	}
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
	if msgs[0].Direction != "request" {
		t.Fatalf("first message should be the request, got %q", msgs[0].Direction)
	}
	if msgs[1].Direction != "response" || !strings.Contains(msgs[1].Text, "201 Created") {
		t.Fatalf("second message should be the final response, got %+v", msgs[1])
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

func (noopConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (noopConn) Write([]byte) (int, error) { return 0, nil }
func (noopConn) Close() error              { return nil }
func (noopConn) LocalAddr() net.Addr       { return nil }
func (noopConn) RemoteAddr() net.Addr      { return nil }
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
		CA:    proxyCA,
		Dial:  dialTo(dest, upCA),
		Sink:  chanSink(got),
		DialPlain: func(network, addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, dest.String(), timeout)
		},
	}
	go p.Serve(pxLn)

	raw := connectTunnel(t, pxLn.Addr().String(), "example.com:443")
	defer raw.Close()
	// h2-only client: the proxy must bypass (blind-relay) so the real upstream cert reaches us.
	cc := tls.Client(raw, &tls.Config{
		RootCAs:              poolFor(upCA),
		ServerName:           "example.com",
		NextProtos:           []string{"h2"},
		InsecureSkipVerify:   true,
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
	var seqs []int
	for _, m := range msgs {
		seqs = append(seqs, m.Seq)
	}
	// Per-direction events publish when each direction completes: both requests finish before the
	// first response body arrives, so the order is request-1, request-2, response-1, response-2.
	if seqs[0] != 1 || seqs[1] != 2 || seqs[2] != 1 || seqs[3] != 2 {
		t.Fatalf("pipelined Seq order wrong: %v", seqs)
	}
}
