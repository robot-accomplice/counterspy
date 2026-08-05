package intercept

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// message is one parsed HTTP/1.1 request or response. The body slice is a bounded preview
// (at most maxKeep bytes); the total field carries the peer's declared expectation.
type message struct {
	startLine string
	header    http.Header
	body      []byte // preview, capped at reader's maxKeep
	total     int    // -1 = unknown/chunked/no-length; 0 = declared zero-length; >0 = Content-Length
	chunked   bool
	truncated bool   // true if body preview was capped or maxMessage was exceeded
	reason    string // why truncated (empty when complete)
}

var (
	errHeaderTooBig  = errors.New("header block exceeds limit")
	errMessageTooBig = errors.New("message exceeds limit")
)

// framingReader parses HTTP/1.1 messages from a tee/copy of the relayed byte stream.
// It keeps only a bounded preview of each message for display while consuming the full
// message so the next parse stays framed.
type framingReader struct {
	r          *bufio.Reader
	maxKeep    int // max body bytes to keep for display
	maxMessage int // max header+body bytes for one message
	maxHeader  int // max header-block bytes
	consumed   int // bytes consumed for the current message (header + body)
}

func newFramingReader(r io.Reader, maxKeep, maxMessage, maxHeader int) *framingReader {
	return &framingReader{
		r:          bufio.NewReader(r),
		maxKeep:    maxKeep,
		maxMessage: maxMessage,
		maxHeader:  maxHeader,
	}
}

// readRequestHead reads the request line and headers. It is used by the pump to push
// {method, seq} to the correlation queue at head-completion time, before the body is read.
func (f *framingReader) readRequestHead() (method, requestURI, proto string, header http.Header, err error) {
	f.consumed = 0
	startLine, header, headerBytes, err := f.readHeaderBlock()
	if err != nil {
		return "", "", "", nil, err
	}
	f.consumed += headerBytes
	parts := strings.SplitN(startLine, " ", 3)
	if len(parts) < 3 {
		return "", "", "", nil, errors.New("bad request line")
	}
	return parts[0], parts[1], parts[2], header, nil
}

// readResponseHead reads the status line and headers.
func (f *framingReader) readResponseHead() (proto string, status int, reason string, header http.Header, err error) {
	f.consumed = 0
	startLine, header, headerBytes, err := f.readHeaderBlock()
	if err != nil {
		return "", 0, "", nil, err
	}
	f.consumed += headerBytes
	parts := strings.SplitN(startLine, " ", 3)
	if len(parts) < 2 {
		return "", 0, "", nil, errors.New("bad status line")
	}
	status, _ = strconv.Atoi(parts[1])
	if len(parts) >= 3 {
		reason = parts[2]
	}
	return parts[0], status, reason, header, nil
}

// readRequest consumes one HTTP request from the stream.
func (f *framingReader) readRequest() (*message, error) {
	method, requestURI, proto, header, err := f.readRequestHead()
	if err != nil {
		return nil, err
	}

	body, total, chunked, truncated, reason, err := f.readBody(header, method, 0)
	if err != nil {
		return nil, err
	}

	return &message{
		startLine: method + " " + requestURI + " " + proto,
		header:    header,
		body:      body,
		total:     total,
		chunked:   chunked,
		truncated: truncated,
		reason:    reason,
	}, nil
}

// readResponse consumes one HTTP response from the stream. method is the request method
// paired with this response; HEAD responses never carry a body regardless of headers.
func (f *framingReader) readResponse(method string) (*message, error) {
	proto, status, reasonPhrase, header, err := f.readResponseHead()
	if err != nil {
		return nil, err
	}

	body, total, chunked, truncated, reason, err := f.readBody(header, method, status)
	if err != nil {
		return nil, err
	}

	startLine := proto + " " + strconv.Itoa(status)
	if reasonPhrase != "" {
		startLine += " " + reasonPhrase
	}
	return &message{
		startLine: startLine,
		header:    header,
		body:      body,
		total:     total,
		chunked:   chunked,
		truncated: truncated,
		reason:    reason,
	}, nil
}

// readHeaderBlock reads the start-line + headers up to the blank line, bounded by maxHeader.
// It returns the parsed start-line, headers, and the byte count consumed (including the blank line).
func (f *framingReader) readHeaderBlock() (string, http.Header, int, error) {
	var block bytes.Buffer

	// Start line.
	line, err := f.r.ReadBytes('\n')
	if err != nil {
		return "", nil, block.Len(), err
	}
	block.Write(line)
	if block.Len() > f.maxHeader {
		return "", nil, block.Len(), errHeaderTooBig
	}
	startLine := strings.TrimRight(string(line), "\r\n")

	// Headers until blank line.
	for {
		line, err := f.r.ReadBytes('\n')
		if err != nil {
			return startLine, nil, block.Len(), err
		}
		block.Write(line)
		if block.Len() > f.maxHeader {
			return "", nil, block.Len(), errHeaderTooBig
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}

	// Parse the accumulated block with textproto so we get proper MIME header handling
	// (folded continuation lines, multiple values, etc.). The block includes the start line,
	// which textproto skips before reading MIME headers.
	tr := textproto.NewReader(bufio.NewReader(bytes.NewReader(block.Bytes())))
	if _, err := tr.ReadLine(); err != nil {
		return startLine, nil, block.Len(), err
	}
	h, err := tr.ReadMIMEHeader()
	if err != nil {
		return startLine, nil, block.Len(), err
	}
	return startLine, http.Header(h), block.Len(), nil
}

func (f *framingReader) readLine() (string, error) {
	line, err := f.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (f *framingReader) readBody(h http.Header, method string, status int) (body []byte, total int, chunked, truncated bool, reason string, err error) {
	// HEAD and 204/304 never have a body.
	if method == http.MethodHead || status == http.StatusNoContent || status == http.StatusNotModified {
		return nil, 0, false, false, "", nil
	}

	// Chunked wins over Content-Length per RFC 7230.
	te := strings.ToLower(h.Get("Transfer-Encoding"))
	if strings.Contains(te, "chunked") {
		body, truncated, reason, err = f.readChunkedBody()
		return body, -1, true, truncated, reason, err
	}

	if cl := h.Get("Content-Length"); cl != "" {
		n, parseErr := strconv.Atoi(cl)
		if parseErr != nil || n < 0 {
			return nil, -1, false, false, "", errors.New("invalid Content-Length")
		}
		body, truncated, reason, err = f.readFixedBody(n)
		return body, n, false, truncated, reason, err
	}

	// No declared framing. For requests, RFC 7230 says a message body is present only when
	// indicated by Content-Length or Transfer-Encoding; so a request without either has no body.
	// For responses, the absence of both means close-delimited framing: read until EOF.
	if status == 0 {
		// request
		return nil, 0, false, false, "", nil
	}
	body, truncated, reason, err = f.readUntilEOF()
	return body, -1, false, truncated, reason, err
}

// readFixedBody reads exactly n bytes, keeping at most maxKeep. It returns the preview,
// whether the preview was capped, and any error. The full n bytes are consumed from the
// stream so framing is preserved.
func (f *framingReader) readFixedBody(n int) ([]byte, bool, string, error) {
	if n == 0 {
		return nil, false, "", nil
	}

	// maxMessage applies to the whole message; if the declared body pushes us over, mark it.
	truncated := f.consumed+n > f.maxMessage
	reason := ""
	if truncated {
		reason = "message size exceeded"
	}

	keep := n
	if keep > f.maxKeep {
		keep = f.maxKeep
		truncated = true
		if reason == "" {
			reason = "capture capped"
		}
	}

	body := make([]byte, keep)
	if _, err := io.ReadFull(f.r, body); err != nil {
		f.consumed += keep
		return body, true, "connection closed", err
	}
	f.consumed += keep
	if n > keep {
		skip := n - keep
		if _, err := io.CopyN(io.Discard, f.r, int64(skip)); err != nil {
			return body, true, "connection closed", err
		}
		f.consumed += skip
	}
	return body, truncated, reason, nil
}

// readChunkedBody parses a chunked transfer-coded body, keeping at most maxKeep payload
// bytes and consuming chunk extensions, the terminal chunk, and the trailer-part.
func (f *framingReader) readChunkedBody() ([]byte, bool, string, error) {
	var body []byte
	truncated := false
	reason := ""

	for {
		line, err := f.readLine()
		if err != nil {
			return body, true, "connection closed", err
		}
		// Count the chunk size line bytes (the newline was consumed by readLine; add 1 or 2
		// for the terminator: approximate is fine for maxMessage).
		f.consumed += len(line) + 1

		// Chunk size is before the first ';'. RFC 7230 §4.1.
		if i := strings.Index(line, ";"); i >= 0 {
			line = line[:i]
		}
		size, parseErr := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if parseErr != nil {
			return body, true, "", parseErr
		}
		if size == 0 {
			// Trailer-part: read until blank line.
			for {
				trl, err := f.readLine()
				if err != nil {
					return body, true, "connection closed", err
				}
				f.consumed += len(trl) + 1
				if trl == "" {
					break
				}
			}
			break
		}

		// Enforce maxMessage on cumulative payload.
		if f.consumed+int(size) > f.maxMessage {
			truncated = true
			reason = "message size exceeded"
		}

		// Read the chunk data, keeping only what fits in the preview cap.
		need := int(size)
		room := f.maxKeep - len(body)
		if room < 0 {
			room = 0
		}
		keep := need
		if keep > room {
			keep = room
		}
		if keep > 0 {
			chunk := make([]byte, keep)
			if _, err := io.ReadFull(f.r, chunk); err != nil {
				f.consumed += keep
				return body, true, "connection closed", err
			}
			body = append(body, chunk...)
		}
		f.consumed += need
		if need > keep {
			if _, err := io.CopyN(io.Discard, f.r, int64(need-keep)); err != nil {
				return body, true, "connection closed", err
			}
		}

		// Consume the trailing CRLF after chunk data.
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(f.r, crlf); err != nil {
			return body, true, "connection closed", err
		}
		f.consumed += 2
	}

	if !truncated && len(body) >= f.maxKeep && f.maxKeep > 0 {
		truncated = true
		reason = "capture capped"
	}
	return body, truncated, reason, nil
}

// readUntilEOF reads a body with no declared framing until EOF or maxMessage, whichever
// comes first. Bytes beyond maxKeep are discarded; bytes beyond maxMessage are consumed
// but do not create a second message.
func (f *framingReader) readUntilEOF() ([]byte, bool, string, error) {
	var body []byte
	truncated := false
	reason := ""
	buf := make([]byte, 4096)

	for {
		n, err := f.r.Read(buf)
		if n > 0 {
			f.consumed += n
			room := f.maxKeep - len(body)
			if room > 0 {
				if n > room {
					body = append(body, buf[:room]...)
				} else {
					body = append(body, buf[:n]...)
				}
			}
			if !truncated && f.consumed > f.maxMessage {
				truncated = true
				reason = "message size exceeded"
			}
		}
		if err == io.EOF {
			return body, truncated, reason, nil
		}
		if err != nil {
			return body, true, "connection closed", err
		}
	}
}
