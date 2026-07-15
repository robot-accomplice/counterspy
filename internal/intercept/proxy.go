// Package intercept is the transparent, READ-ONLY TLS-intercepting proxy (Phase 2): it terminates a
// client's TLS with a leaf minted by the local CA, re-dials the real server (verified normally),
// relays both directions BYTE-FOR-BYTE unmodified, and captures the decrypted plaintext — decoded and
// secret-masked — into a model.InterceptedFlow for the console. It never modifies traffic.
package intercept

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"time"
	"unicode/utf8"

	"counterspy/internal/inspect"
	"counterspy/internal/intercept/ca"
	"counterspy/internal/model"
)

// maxCapture bounds how many bytes per direction we hold for decode/display (the wire is relayed in
// full regardless — this only bounds what we KEEP).
const maxCapture = 8 << 10

// dialFunc dials the real upstream. Injected so tests can point it at a loopback server and trust a
// test CA; production verifies the upstream cert against the system roots.
type dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)

func defaultDial(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return tls.Dial(network, addr, cfg)
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// intercept handles one redirected connection: terminate the client TLS with a CA leaf for its SNI,
// dial the real dest, relay unmodified, and return the captured Flow. A client that REJECTS our leaf
// (cert pinning) fails the handshake → FlowPinned (bypassed, not decrypted, connection closed). The
// relayed bytes are never altered — this is a read-only mirror.
func intercept(client net.Conn, dest netip.AddrPort, c *ca.CA, dial dialFunc) model.InterceptedFlow {
	flow := model.InterceptedFlow{At: nowRFC3339(), DestIP: dest.Addr().String()}

	var sni string
	server := tls.Server(client, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = chi.ServerName
			host := chi.ServerName
			if host == "" {
				host = dest.Addr().String()
			}
			return c.LeafFor(host)
		},
	})
	if err := server.Handshake(); err != nil {
		// The client wouldn't accept our leaf — cert pinning. We don't (and can't) decrypt it; report
		// honestly and close. A future bypass list keeps such hosts out of the redirect entirely.
		flow.Status = model.FlowPinned
		client.Close()
		return flow
	}
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
// both ends. Bytes pass through io.MultiWriter unmodified — the capture is a copy, not a filter.
func relay(client, upstream net.Conn, sent, recv *capBuf) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(io.MultiWriter(upstream, sent), client); done <- struct{}{} }()
	go func() { io.Copy(io.MultiWriter(client, recv), upstream); done <- struct{}{} }()
	<-done
	client.Close()
	upstream.Close()
	<-done
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
