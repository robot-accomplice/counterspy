package intercept

import (
	"io"
	"strings"
	"testing"
)

const (
	testKeep    = 64
	testMessage = 1024
	testHeader  = 256
)

func TestFramingReader_SimpleRequestResponse(t *testing.T) {
	reqBody := "hello"
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n" + reqBody
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld"
	r := newFramingReader(strings.NewReader(req), testKeep, testMessage, testHeader)

	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if m.startLine != "POST /x HTTP/1.1" {
		t.Fatalf("startLine = %q", m.startLine)
	}
	if got := string(m.body); got != reqBody {
		t.Fatalf("body = %q, want %q", got, reqBody)
	}
	if m.total != 5 {
		t.Fatalf("total = %d", m.total)
	}
	if m.truncated {
		t.Fatal("unexpected truncated")
	}

	respR := newFramingReader(strings.NewReader(resp), testKeep, testMessage, testHeader)
	m2, err := respR.readResponse("POST")
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if got := string(m2.body); got != "world" {
		t.Fatalf("response body = %q", got)
	}
}

func TestFramingReader_PipelinedKeepAlive(t *testing.T) {
	piped := "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" +
		"GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
	r := newFramingReader(strings.NewReader(piped), testKeep, testMessage, testHeader)
	for i, want := range []string{"GET /a HTTP/1.1", "GET /b HTTP/1.1"} {
		m, err := r.readRequest()
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		if m.startLine != want {
			t.Fatalf("req %d startLine = %q", i, m.startLine)
		}
	}
	_, err := r.readRequest()
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestFramingReader_HEADNoBody(t *testing.T) {
	req := "HEAD /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"
	r := newFramingReader(strings.NewReader(req), testKeep, testMessage, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if len(m.body) != 0 {
		t.Fatalf("HEAD body should be empty, got %q", m.body)
	}
	if m.total != 0 {
		t.Fatalf("HEAD total = %d", m.total)
	}
}

func TestFramingReader_204NoBody(t *testing.T) {
	resp := "HTTP/1.1 204 No Content\r\n\r\n"
	r := newFramingReader(strings.NewReader(resp), testKeep, testMessage, testHeader)
	m, err := r.readResponse("GET")
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if len(m.body) != 0 {
		t.Fatalf("204 body should be empty, got %q", m.body)
	}
}

func TestFramingReader_304NoBody(t *testing.T) {
	resp := "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nhello"
	r := newFramingReader(strings.NewReader(resp), testKeep, testMessage, testHeader)
	m, err := r.readResponse("GET")
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if len(m.body) != 0 {
		t.Fatalf("304 body should be empty, got %q", m.body)
	}
}

func TestFramingReader_Chunked(t *testing.T) {
	body := "5\r\nhello\r\n0\r\nX-Trailer: ok\r\n\r\n"
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + body
	r := newFramingReader(strings.NewReader(req), testKeep, testMessage, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if got := string(m.body); got != "hello" {
		t.Fatalf("chunked body = %q", got)
	}
	if !m.chunked {
		t.Fatal("expected chunked")
	}
	if m.total != -1 {
		t.Fatalf("total = %d, want -1", m.total)
	}
}

func TestFramingReader_ChunkedWithTrailer(t *testing.T) {
	body := "5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n"
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + body
	r := newFramingReader(strings.NewReader(req), testKeep, testMessage, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if got := string(m.body); got != "hello" {
		t.Fatalf("body = %q", got)
	}
	// Next parse should hit EOF since the whole message was consumed.
	_, err = r.readRequest()
	if err != io.EOF {
		t.Fatalf("expected EOF after trailers, got %v", err)
	}
}

func TestFramingReader_ChunkExtensionsIgnored(t *testing.T) {
	body := "5;ext=foo\r\nhello\r\n0\r\n\r\n"
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + body
	r := newFramingReader(strings.NewReader(req), testKeep, testMessage, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if got := string(m.body); got != "hello" {
		t.Fatalf("body with chunk ext = %q", got)
	}
}

func TestFramingReader_ContentLengthCapped(t *testing.T) {
	keep := 4
	payload := "1234567890"
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n" + payload
	r := newFramingReader(strings.NewReader(req), keep, testMessage, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if got := string(m.body); got != "1234" {
		t.Fatalf("capped body = %q", got)
	}
	if !m.truncated {
		t.Fatal("expected truncated")
	}
	if m.reason != "capture capped" {
		t.Fatalf("reason = %q", m.reason)
	}
}

func TestFramingReader_MessageTooBig(t *testing.T) {
	keep := 4
	max := 8
	payload := "1234567890"
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n" + payload
	r := newFramingReader(strings.NewReader(req), keep, max, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if !m.truncated {
		t.Fatal("expected truncated")
	}
	if m.reason != "message size exceeded" {
		t.Fatalf("reason = %q", m.reason)
	}
	// The rest of the stream should be consumed so the next read sees EOF.
	_, err = r.readRequest()
	if err != io.EOF {
		t.Fatalf("expected EOF after skipping oversized body, got %v", err)
	}
}

func TestFramingReader_HeaderTooBig(t *testing.T) {
	big := "X-Foo: " + strings.Repeat("a", 512) + "\r\n"
	req := "GET /x HTTP/1.1\r\nHost: example.com\r\n" + big + "\r\n"
	r := newFramingReader(strings.NewReader(req), testKeep, testMessage, 64)
	_, err := r.readRequest()
	if err != errHeaderTooBig {
		t.Fatalf("expected errHeaderTooBig, got %v", err)
	}
}

func TestFramingReader_NoLengthResponseBody(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\nhello"
	r := newFramingReader(strings.NewReader(resp), testKeep, testMessage, testHeader)
	m, err := r.readResponse("GET")
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if got := string(m.body); got != "hello" {
		t.Fatalf("no-length body = %q", got)
	}
	if m.total != -1 {
		t.Fatalf("total = %d", m.total)
	}
}

func TestFramingReader_NoLengthResponseExceedsMaxMessage(t *testing.T) {
	keep := 4
	max := 8
	payload := "12345678901234567890"
	resp := "HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\n" + payload
	r := newFramingReader(strings.NewReader(resp), keep, max, testHeader)
	m, err := r.readResponse("GET")
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if got := string(m.body); got != "1234" {
		t.Fatalf("body = %q", got)
	}
	if !m.truncated || m.reason != "message size exceeded" {
		t.Fatalf("truncated=%v reason=%q", m.truncated, m.reason)
	}
}

func TestFramingReader_ResponseUsesMethod(t *testing.T) {
	// A HEAD response can legally include Content-Length but must not have a body.
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
	r := newFramingReader(strings.NewReader(resp), testKeep, testMessage, testHeader)
	m, err := r.readResponse("HEAD")
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if len(m.body) != 0 {
		t.Fatalf("HEAD response body = %q", m.body)
	}
}

func TestFramingReader_BodyPreservedForNextMessage(t *testing.T) {
	// A request with body followed by another request: the reader must consume exactly the
	// declared body and then parse the next request.
	reqs := "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" +
		"GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
	r := newFramingReader(strings.NewReader(reqs), testKeep, testMessage, testHeader)
	m1, err := r.readRequest()
	if err != nil {
		t.Fatalf("req1: %v", err)
	}
	if got := string(m1.body); got != "hello" {
		t.Fatalf("req1 body = %q", got)
	}
	m2, err := r.readRequest()
	if err != nil {
		t.Fatalf("req2: %v", err)
	}
	if m2.startLine != "GET /b HTTP/1.1" {
		t.Fatalf("req2 startLine = %q", m2.startLine)
	}
}

func TestFramingReader_EmptyBodyContentLengthZero(t *testing.T) {
	req := "GET /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	r := newFramingReader(strings.NewReader(req), testKeep, testMessage, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if len(m.body) != 0 || m.total != 0 {
		t.Fatalf("body=%q total=%d", m.body, m.total)
	}
}

func TestFramingReader_MultipleChunkedMessages(t *testing.T) {
	body1 := "5\r\nhello\r\n0\r\n\r\n"
	body2 := "5\r\nworld\r\n0\r\n\r\n"
	reqs := "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + body1 +
		"POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + body2
	r := newFramingReader(strings.NewReader(reqs), testKeep, testMessage, testHeader)
	m1, err := r.readRequest()
	if err != nil {
		t.Fatalf("req1: %v", err)
	}
	if got := string(m1.body); got != "hello" {
		t.Fatalf("req1 body = %q", got)
	}
	m2, err := r.readRequest()
	if err != nil {
		t.Fatalf("req2: %v", err)
	}
	if got := string(m2.body); got != "world" {
		t.Fatalf("req2 body = %q", got)
	}
}

func TestFramingReader_ChunkedTooBig(t *testing.T) {
	keep := 4
	max := 16
	body := "10\r\n" + strings.Repeat("a", 16) + "\r\n0\r\n\r\n"
	req := "POST /x HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n" + body
	r := newFramingReader(strings.NewReader(req), keep, max, testHeader)
	m, err := r.readRequest()
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if !m.truncated || m.reason != "message size exceeded" {
		t.Fatalf("truncated=%v reason=%q", m.truncated, m.reason)
	}
	// The terminal chunk was consumed, so the next read sees EOF.
	_, err = r.readRequest()
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestFramingReader_ResponseEarlyFinal(t *testing.T) {
	// Server rejects a 100-continue upload with 413; request body is aborted.
	resp := "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"
	r := newFramingReader(strings.NewReader(resp), testKeep, testMessage, testHeader)
	m, err := r.readResponse("POST")
	if err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	if m.startLine != "HTTP/1.1 413 Payload Too Large" {
		t.Fatalf("status = %q", m.startLine)
	}
	if len(m.body) != 0 {
		t.Fatalf("413 response body = %q", m.body)
	}
}

// Ensure the framing reader can be used with a reader that grows over time (like a pipe
// fed by the relay).
func TestFramingReader_PartialInput(t *testing.T) {
	pr, pw := io.Pipe()
	r := newFramingReader(pr, testKeep, testMessage, testHeader)
	done := make(chan struct{})
	var m *message
	var err error
	go func() {
		m, err = r.readRequest()
		close(done)
	}()
	pw.Write([]byte("GET /x HTTP/1.1\r\nHost: ex"))
	pw.Write([]byte("ample.com\r\n\r\n"))
	pw.Close()
	<-done
	if err != nil {
		t.Fatalf("readRequest: %v", err)
	}
	if m.startLine != "GET /x HTTP/1.1" {
		t.Fatalf("startLine = %q", m.startLine)
	}
}
