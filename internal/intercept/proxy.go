// Package intercept is the transparent, READ-ONLY TLS-intercepting proxy (Phase 2): it terminates a
// client's TLS with a leaf minted by the local CA, re-dials the real server (verified normally),
// relays both directions BYTE-FOR-BYTE unmodified, and captures the decrypted plaintext — decoded and
// secret-masked — into a model.InterceptedFlow for the console. It never modifies traffic.
package intercept

import (
	"crypto/tls"
	"net"
	"net/netip"
	"time"
	"unicode/utf8"

	"counterspy/internal/inspect"
	"counterspy/internal/intercept/ca"
	"counterspy/internal/intercept/publish"
	"counterspy/internal/model"
)

// Proxy is the running interception service: it accepts redirected connections, recovers each one's
// pre-redirect destination, intercepts (decrypt → relay → capture), and publishes the flow. OrigDest
// and Dial are seams so the accept loop is testable without pf/root.
type Proxy struct {
	CA       *ca.CA
	OrigDest func(net.Conn) (netip.AddrPort, error)
	Dial     dialFunc // nil → defaultDial (verified upstream)
	Sink     publish.Sink
}

// Serve accepts on l until it errors (listener closed), handling each connection in its own goroutine.
func (p *Proxy) Serve(l net.Listener) error {
	dial := p.Dial
	if dial == nil {
		dial = defaultDial
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go p.handle(conn, dial)
	}
}

// handle intercepts one connection and publishes its flow. Panic-recovered so a single malformed flow
// can never kill the whole proxy (which is holding the user's traffic redirected).
func (p *Proxy) handle(conn net.Conn, dial dialFunc) {
	defer func() { _ = recover() }()
	dest, err := p.OrigDest(conn)
	if err != nil {
		conn.Close() // can't recover the destination → can't relay; drop cleanly
		return
	}
	flow := intercept(conn, dest, p.CA, dial) // intercept owns closing conn
	if p.Sink != nil {
		p.Sink.Publish(flow)
	}
}

// maxCapture bounds how many bytes per direction we hold for decode/display (the wire is relayed in
// full regardless — this only bounds what we KEEP).
const maxCapture = 8 << 10

// Timeouts reap a stalled flow so a hung client/upstream can't leak goroutines + fds forever
// (Audit/Antagonist cp-p2c F-1): a bound on the TLS handshake, on dialing the upstream, and an idle
// deadline reset on each relay read so a connection with no traffic for idleTimeout is torn down.
const (
	handshakeTimeout = 10 * time.Second
	dialTimeout      = 10 * time.Second
	idleTimeout      = 5 * time.Minute
)

// dialFunc dials the real upstream. Injected so tests can point it at a loopback server and trust a
// test CA; production verifies the upstream cert against the system roots.
type dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)

func defaultDial(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, network, addr, cfg)
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// intercept handles one redirected connection: terminate the client TLS with a CA leaf for its SNI,
// dial the real dest, relay unmodified, and return the captured Flow. A client that REJECTS our leaf
// (cert pinning) fails the handshake → FlowPinned (bypassed, not decrypted, connection closed). The
// relayed bytes are never altered — this is a read-only mirror.
func intercept(client net.Conn, dest netip.AddrPort, c *ca.CA, dial dialFunc) model.InterceptedFlow {
	flow := model.InterceptedFlow{At: nowRFC3339(), DestIP: dest.Addr().String()}

	var sni string
	var sawClientHello bool
	var mintErr error
	server := tls.Server(client, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sawClientHello = true
			sni = chi.ServerName
			host := chi.ServerName
			if host == "" {
				host = dest.Addr().String()
			}
			leaf, err := c.LeafFor(host)
			mintErr = err
			return leaf, err
		},
	})
	client.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := server.Handshake(); err != nil {
		// Classify honestly (cp-p2c F-2): OUR leaf mint failed → error; no ClientHello at all (non-TLS
		// bytes on the port) → opaque; we presented a valid leaf and the client refused it → pinned.
		switch {
		case mintErr != nil:
			flow.Status = model.FlowError
		case !sawClientHello:
			flow.Status = model.FlowOpaque
		default:
			flow.Status = model.FlowPinned
		}
		client.Close()
		return flow
	}
	client.SetDeadline(time.Time{}) // clear the handshake deadline; relay uses per-read idle deadlines
	host := sni
	if host == "" {
		host = dest.Addr().String()
	}
	flow.SNI, flow.DestName = sni, host

	upstream, err := dial("tcp", dest.String(), &tls.Config{ServerName: host})
	if err != nil {
		flow.Status = model.FlowError
		server.Close()
		return flow
	}
	sent, recv := &capBuf{max: maxCapture}, &capBuf{max: maxCapture}
	relay(server, upstream, sent, recv)

	flow.SentBytes, flow.RecvBytes = sent.n, recv.n
	flow.SentText = decodeMask(sent.b) // masked BEFORE the Flow exists — no sink ever sees a raw secret
	flow.RecvText = decodeMask(recv.b)
	flow.Status = model.FlowDecrypted
	return flow
}

// relay copies both directions concurrently, tee-capturing each into a bounded buffer, then closes
// both ends. Bytes are forwarded to the real peer UNMODIFIED; the capture is a copy, not a filter. An
// idle deadline reaps a stalled flow (F-1).
func relay(client, upstream net.Conn, sent, recv *capBuf) {
	done := make(chan struct{}, 2)
	go func() { copyIdle(upstream, client, sent); done <- struct{}{} }()
	go func() { copyIdle(client, upstream, recv); done <- struct{}{} }()
	<-done
	client.Close()
	upstream.Close()
	<-done
}

// copyIdle forwards src→dst, tee-capturing into cap, resetting src's read deadline each iteration so a
// connection idle for idleTimeout is torn down (no unbounded goroutine/fd leak). The real dst is
// written first and its bytes are never altered; a dst write error ends the copy.
func copyIdle(dst net.Conn, src net.Conn, cap *capBuf) {
	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			cap.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// capBuf keeps up to max bytes for decode/display while counting the true total. It always reports a
// full write so it never truncates the relay it's tee'd into.
type capBuf struct {
	b   []byte
	n   int
	max int
}

func (c *capBuf) Write(p []byte) (int, error) {
	c.n += len(p)
	if room := c.max - len(c.b); room > 0 {
		q := p
		if len(q) > room {
			q = q[:room]
		}
		c.b = append(c.b, q...)
	}
	return len(p), nil
}

// decodeMask turns a captured direction into displayable text: decode HTTP (dechunk/decompress) when
// possible, else show cleartext text as-is; binary non-HTTP yields "". Redact ALWAYS runs so a secret
// (bearer/cookie/api-key/PEM) is masked before the Flow leaves this function (cp-p2a review; #Phase2).
func decodeMask(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if decoded, ok := inspect.DecodeCleartext(b); ok {
		return model.Redact(decoded)
	}
	if looksText(b) {
		return model.Redact(string(b))
	}
	return ""
}

func looksText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	nonPrint := 0
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			nonPrint++
		}
	}
	return nonPrint*10 < len(b) // <10% control bytes → treat as text
}
