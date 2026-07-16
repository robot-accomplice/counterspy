// Package intercept is the READ-ONLY TLS-intercepting HTTPS proxy (Phase 2): a client CONNECTs to it
// (macOS is pointed here by the system secure-web-proxy setting), it terminates the client's TLS with a
// leaf minted by the local CA, re-dials the real server (verified normally), relays both directions
// BYTE-FOR-BYTE unmodified, and captures the decrypted plaintext — decoded and secret-masked — into a
// model.InterceptedFlow for the console. It never modifies traffic.
//
// ROUTING HISTORY (why CONNECT, not a transparent pf redirect): Phase 2 originally used a pf `rdr`
// rule to steal :443 transparently. A root smoke test proved that CANNOT work for this use case — pf
// translates only INBOUND packets, so a rule as permissive as
// `rdr pass inet proto tcp from any to any port = 443` logged 27828 Evaluations and 0 Packets against
// the machine's own outbound curl. Locally-originated traffic never traverses the rdr path (Linux has
// iptables OUTPUT REDIRECT, FreeBSD has divert-to; macOS pf has neither). So the client now TELLS us
// the destination via CONNECT, which also removes the DIOCNATLOOK ioctl and gives us the real hostname
// without inferring it from SNI. Tradeoff: this is COOPERATIVE — apps honoring the system proxy
// (CFNetwork/NSURLSession) are seen; evasive software bypasses it and must be caught by a
// NetworkExtension transparent proxy (a later phase).
package intercept

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"counterspy/internal/inspect"
	"counterspy/internal/intercept/ca"
	"counterspy/internal/intercept/publish"
	"counterspy/internal/model"
)

// Proxy is the running interception service: it accepts CONNECT tunnels, intercepts (decrypt → relay →
// capture), attributes each to the app that opened it, and publishes the flow. Dial and Owner are seams
// so the accept loop is testable without real upstreams or lsof.
type Proxy struct {
	CA   *ca.CA
	Dial dialFunc // nil → defaultDial (verified upstream)
	Sink publish.Sink
	// Owner maps a client's local port to the process that owns it. nil → portOwner (lsof on darwin).
	Owner func(port int) (pid int, name string, ok bool)
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

// connectTimeout bounds reading the client's CONNECT request line, so a client that opens a socket and
// says nothing can't pin a goroutine.
const connectTimeout = 10 * time.Second

// readConnect reads the client's `CONNECT host:port HTTP/1.1` request and returns the target authority.
// The client naming its own destination is what replaces the pf/DIOCNATLOOK lookup. A non-CONNECT
// request is an error: we are configured ONLY as the secure-web (https) proxy, so plain-HTTP requests
// are not ours to serve and must not be silently swallowed.
func readConnect(conn net.Conn) (string, error) {
	conn.SetReadDeadline(time.Now().Add(connectTimeout))
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return "", fmt.Errorf("read CONNECT: %w", err)
	}
	if req.Method != http.MethodConnect {
		return "", fmt.Errorf("expected CONNECT, got %s", req.Method)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host == "" {
		return "", fmt.Errorf("CONNECT with no target")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443") // authority may omit the port
	}
	conn.SetReadDeadline(time.Time{})
	return host, nil
}

// connectEstablished is the tunnel-open response; after it the bytes are raw TLS.
const connectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"

// handle intercepts one CONNECT tunnel and publishes its flow. Panic-recovered so a single malformed
// flow can never kill the whole proxy (which is holding the user's traffic) — and the recover ALWAYS
// closes the conn, so a panic can't leak the fd (cp-p2d F-2).
//
// A connection we cannot resolve publishes a FlowError rather than closing silently: the console must
// SHOW that something arrived and could not be handled, never imply nothing happened (Rule 13 — the
// silent-drop the smoke test surfaced when OrigDest could fail with no trace).
func (p *Proxy) handle(conn net.Conn, dial dialFunc) {
	defer func() {
		if r := recover(); r != nil {
			conn.Close()
		}
	}()
	// Attribute BEFORE the tunnel runs: the lookup needs the client's socket to still be open, and a
	// long-lived flow would otherwise be attributed (or not) minutes later, after the app may have exited.
	pid, app := p.owner(conn)
	target, err := readConnect(conn)
	if err != nil {
		p.publish(model.InterceptedFlow{
			At: nowRFC3339(), Status: model.FlowError, PID: pid, App: app,
			DestName: "(unresolved: " + firstLine(err.Error()) + ")",
		})
		conn.Close()
		return
	}
	if _, werr := conn.Write([]byte(connectEstablished)); werr != nil {
		conn.Close()
		return
	}
	flow := intercept(conn, target, p.CA, dial) // intercept owns closing conn on the normal path
	flow.PID, flow.App = pid, app
	p.publish(flow)
}

// owner attributes a connection to the process that opened it. An unattributable flow is published
// UNATTRIBUTED rather than dropped — a flow we can't name is still one the user needs to see (Rule 13).
func (p *Proxy) owner(conn net.Conn) (int, string) {
	lookup := p.Owner
	if lookup == nil {
		lookup = portOwner
	}
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return 0, ""
	}
	pid, name, ok := lookup(int(ap.Port()))
	if !ok {
		return 0, ""
	}
	return pid, name
}

func (p *Proxy) publish(fl model.InterceptedFlow) {
	if p.Sink != nil {
		p.Sink.Publish(fl)
	}
}

// firstLine keeps an error to one displayable line (it reaches the console's flow list).
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
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

// intercept handles one CONNECT tunnel: terminate the client TLS with a CA leaf, dial the real target,
// relay unmodified, and return the captured Flow. `target` is the authority the client named in its
// CONNECT ("example.com:443") — authoritative, unlike an inferred destination. A client that REJECTS
// our leaf (cert pinning) fails the handshake → FlowPinned (bypassed, not decrypted, connection
// closed). The relayed bytes are never altered — this is a read-only mirror.
func intercept(client net.Conn, target string, c *ca.CA, dial dialFunc) model.InterceptedFlow {
	targetHost, _, err := net.SplitHostPort(target)
	if err != nil {
		targetHost = target
	}
	flow := model.InterceptedFlow{At: nowRFC3339(), DestName: targetHost}

	var sni string
	var sawClientHello bool
	var mintErr error
	server := tls.Server(client, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sawClientHello = true
			sni = chi.ServerName
			host := chi.ServerName
			if host == "" {
				host = targetHost // fall back to the CONNECT authority (an IP-literal target has no SNI)
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
	flow.SNI = sni
	// Verify the upstream against the name the CLIENT asked for (the CONNECT authority), not one the
	// server or a forged SNI could influence — SNI is recorded for display only.
	upstream, err := dial("tcp", target, &tls.Config{ServerName: targetHost})
	if err != nil {
		flow.Status = model.FlowError
		server.Close()
		return flow
	}
	if ap, perr := netip.ParseAddrPort(upstream.RemoteAddr().String()); perr == nil {
		flow.DestIP = ap.Addr().String() // the IP the name actually resolved to
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
	// Each copy recovers its own panic and always signals done — a panic in copyIdle/capBuf while
	// processing attacker-controlled bytes must not crash the whole proxy or deadlock relay (cp-p2d F-3).
	cp := func(dst, src net.Conn, cap *capBuf) {
		defer func() { _ = recover(); done <- struct{}{} }()
		copyIdle(dst, src, cap)
	}
	go cp(upstream, client, sent)
	go cp(client, upstream, recv)
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
