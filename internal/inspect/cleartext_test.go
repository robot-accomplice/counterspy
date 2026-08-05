package inspect

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
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

// Audit cp-p1f F-1/F-2: a body mislabeled with a Content-Encoding it doesn't actually have must NOT
// vanish; the raw bytes must still be shown (a decoder that drained the reader would lose them).
func TestDecodeCleartext_MislabeledEncodingKeepsBody(t *testing.T) {
	for _, enc := range []string{"gzip", "deflate", "br"} {
		raw := "HTTP/1.1 200 OK\r\nContent-Encoding: " + enc + "\r\nContent-Length: 5\r\n\r\nhello"
		got, ok := DecodeCleartext([]byte(raw))
		if !ok {
			t.Fatalf("%s: response must still parse", enc)
		}
		if !strings.Contains(got, "hello") {
			t.Fatalf("%s: a mislabeled encoding must NOT swallow the plaintext body: %q", enc, got)
		}
	}
}

// F-1 bound: a gzip bomb must not blow up memory; the DECOMPRESSED body is capped at maxBodyPreview.
func TestDecodeCleartext_GzipBombBounded(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(bytes.Repeat([]byte("A"), 1<<20)) // 1 MiB → ~1 KiB gzipped
	w.Close()
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", gz.Len())
	got, ok := DecodeCleartext(append([]byte(raw), gz.Bytes()...))
	if !ok {
		t.Fatal("must parse")
	}
	// The BODY portion is capped at maxBodyPreview; total render adds only the start line + headers.
	if len(got) > maxBodyPreview+256 {
		t.Fatalf("gzip bomb output not bounded: %d bytes", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Fatalf("a bomb-sized body should be marked truncated")
	}
}

// F-3: a successfully decoded body annotates its Content-Encoding so it doesn't read as still-compressed.
func TestDecodeCleartext_AnnotatesDecodedEncoding(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write([]byte("plain text"))
	w.Close()
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", gz.Len())
	got, _ := DecodeCleartext(append([]byte(raw), gz.Bytes()...))
	if !strings.Contains(got, "(decoded)") {
		t.Fatalf("decoded body should annotate Content-Encoding: %q", got)
	}
}

func TestDecodeCleartext_BrotliResponseDecompressed(t *testing.T) {
	plain := []byte(`{"report":"brotli body"}`)
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	bw.Write(plain)
	bw.Close()
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: %d\r\n\r\n", br.Len())
	got, ok := DecodeCleartext(append([]byte(raw), br.Bytes()...))
	if !ok {
		t.Fatal("brotli response must decode")
	}
	if !strings.Contains(got, "brotli body") {
		t.Fatalf("brotli body was not decompressed: %q", got)
	}
	if !strings.Contains(got, "br (decoded)") {
		t.Fatalf("brotli Content-Encoding should be annotated as decoded: %q", got)
	}
}
