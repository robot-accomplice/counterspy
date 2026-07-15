package inspect

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"sort"
	"strings"
)

// maxBodyPreview bounds how much decoded body we render for one direction.
const maxBodyPreview = 4 << 10

// DecodeCleartext tries to parse b as an HTTP request or response and render it with its body
// DECODED — net/http dechunks a chunked Transfer-Encoding, and this additionally decompresses a
// gzip/deflate Content-Encoding — so a compressed or chunked cleartext payload reads as text instead
// of a binary hexdump (the "reveal as much as we can" goal, #3). It returns (rendered, true) on a
// successful parse, else ("", false) so the caller keeps the existing text/hexdump rendering. It only
// reveals structure + content; secret masking stays with model.Redact at render time (so the same
// masking + reveal toggle applies uniformly).
func DecodeCleartext(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b))); err == nil {
		h := req.Header
		if req.Host != "" { // net/http hoists Host out of the header map — put it back for display
			h = req.Header.Clone()
			h.Set("Host", req.Host)
		}
		return render(req.Method+" "+req.RequestURI+" "+req.Proto, h, readBody(h, req.Body)), true
	}
	if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil); err == nil {
		return render(resp.Proto+" "+resp.Status, resp.Header, readBody(resp.Header, resp.Body)), true
	}
	return "", false
}

// maxRawBody bounds how many (post-dechunk) body bytes we buffer before attempting decompression.
const maxRawBody = 1 << 20

// readBody reads the (already dechunked) body into a buffer, then decompresses a gzip/deflate
// Content-Encoding OVER A COPY — so a decode failure falls back to the UNTOUCHED raw bytes instead of
// a reader the decompressor already drained (which would make the plaintext vanish — Audit cp-p1f
// F-1). On a successful decode it annotates the shown Content-Encoding so the body doesn't read as
// still-compressed (F-3). Bounded output (maxBodyPreview) caps a decompression bomb.
func readBody(h http.Header, body io.ReadCloser) string {
	if body == nil {
		return ""
	}
	defer body.Close()
	raw, _ := io.ReadAll(io.LimitReader(body, maxRawBody))
	dec, decoded := decodeBody(strings.ToLower(h.Get("Content-Encoding")), raw)
	if decoded {
		h.Set("Content-Encoding", h.Get("Content-Encoding")+" (decoded)")
	}
	if len(dec) > maxBodyPreview {
		return string(dec[:maxBodyPreview]) + "\n… (truncated)"
	}
	return string(dec)
}

// decodeBody attempts gzip/deflate decompression over a FRESH reader on a COPY of raw, capping the
// decompressed output. It returns (raw, false) on any failure or empty result, so the caller always
// shows *something* real and never loses the payload to a mislabeled encoding.
func decodeBody(enc string, raw []byte) (out []byte, decoded bool) {
	var r io.Reader
	switch enc {
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw, false
		}
		defer zr.Close()
		r = zr
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		r = fr
	default:
		return raw, false
	}
	got, _ := io.ReadAll(io.LimitReader(r, maxBodyPreview+1))
	if len(got) == 0 {
		return raw, false // decode produced nothing usable → show the raw bytes, never vanish
	}
	return got, true
}

// render assembles the start line, sorted headers, and body into a readable block. Header values are
// shown verbatim; model.Redact masks the sensitive ones at display time.
func render(start string, h http.Header, body string) string {
	var b strings.Builder
	b.WriteString(start)
	b.WriteByte('\n')
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	if body != "" {
		b.WriteByte('\n')
		b.WriteString(body)
	}
	return b.String()
}
