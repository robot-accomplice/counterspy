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
		return render(req.Method+" "+req.RequestURI+" "+req.Proto, h, readBody(req.Header, req.Body)), true
	}
	if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil); err == nil {
		return render(resp.Proto+" "+resp.Status, resp.Header, readBody(resp.Header, resp.Body)), true
	}
	return "", false
}

// readBody reads the (already dechunked) body, decompressing a gzip/deflate Content-Encoding, capped
// at maxBodyPreview. A decompressor that fails on a mislabeled/partial body falls back to the raw
// bytes rather than erroring — best-effort, never a hang (the source is a finite byte slice).
func readBody(h http.Header, body io.ReadCloser) string {
	if body == nil {
		return ""
	}
	defer body.Close()
	var r io.Reader = body
	switch strings.ToLower(h.Get("Content-Encoding")) {
	case "gzip":
		if zr, err := gzip.NewReader(body); err == nil {
			defer zr.Close()
			r = zr
		}
	case "deflate":
		fr := flate.NewReader(body)
		defer fr.Close()
		r = fr
	}
	buf, _ := io.ReadAll(io.LimitReader(r, maxBodyPreview+1))
	if len(buf) > maxBodyPreview {
		return string(buf[:maxBodyPreview]) + "\n… (truncated)"
	}
	return string(buf)
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
