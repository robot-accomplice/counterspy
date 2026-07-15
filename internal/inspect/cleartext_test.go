package inspect

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

func TestDecodeCleartext_Request(t *testing.T) {
	raw := "POST /api/login HTTP/1.1\r\nHost: x.example\r\nContent-Length: 11\r\n\r\nuser=alice\n"
	got, ok := DecodeCleartext([]byte(raw))
	if !ok {
		t.Fatal("a well-formed HTTP request must decode")
	}
	if !strings.HasPrefix(got, "POST /api/login HTTP/1.1") {
		t.Fatalf("start line missing: %q", got)
	}
	if !strings.Contains(got, "Host: x.example") || !strings.Contains(got, "user=alice") {
		t.Fatalf("headers/body missing: %q", got)
	}
}

func TestDecodeCleartext_GzipResponseDecompressed(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte(`{"secret_report":"the app is exfiltrating your contacts"}`))
	w.Close()
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", gz.Len())
	got, ok := DecodeCleartext(append([]byte(raw), gz.Bytes()...))
	if !ok {
		t.Fatal("gzip response must decode")
	}
	if !strings.Contains(got, "exfiltrating your contacts") {
		t.Fatalf("gzip body was not decompressed to readable text: %q", got)
	}
}

func TestDecodeCleartext_ChunkedResponseDechunked(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
	got, ok := DecodeCleartext([]byte(raw))
	if !ok {
		t.Fatal("chunked response must decode")
	}
	if !strings.Contains(got, "Wikipedia") {
		t.Fatalf("chunked body not reassembled: %q", got)
	}
}

func TestDecodeCleartext_NonHTTPFallsBack(t *testing.T) {
	if _, ok := DecodeCleartext([]byte{0x16, 0x03, 0x01, 0x00, 0x40}); ok {
		t.Fatal("a TLS record (non-HTTP) must NOT decode as cleartext")
	}
	if _, ok := DecodeCleartext([]byte("just some random text, not http\n")); ok {
		t.Fatal("arbitrary text must not parse as HTTP")
	}
	if _, ok := DecodeCleartext(nil); ok {
		t.Fatal("empty input must not decode")
	}
}
