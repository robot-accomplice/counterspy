package intercept

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"counterspy/internal/intercept/ca"
	"counterspy/internal/model"
)

func poolFor(c *ca.CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(c.CertPEM())
	return p
}

func addrPort(t *testing.T, a net.Addr) netip.AddrPort {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

// upstreamServer stands up a loopback TLS server (cert for "example.com", signed by upCA) that reads
// a request and returns a fixed response. Returns its addr + the CA a client should trust to reach it.
func upstreamServer(t *testing.T, response string) (netip.AddrPort, *ca.CA) {
	upCA, _ := ca.NewCA()
	leaf, err := upCA.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				c.Read(buf) // consume the request (don't need to parse it)
				c.Write([]byte(response))
				c.Close()
			}(c)
		}
	}()
	return addrPort(t, ln.Addr()), upCA
}

// dialTo returns a dialFunc that connects to the loopback stand-in `at` while preserving the ServerName
// the pump asked for, modelling real DNS: the proxy asks for "example.com:443", the packets land on
// our test server, and the cert must still verify as example.com.
func dialTo(at netip.AddrPort, upCA *ca.CA) dialFunc {
	return func(network, _ string, cfg *tls.Config) (net.Conn, error) {
		cfg.RootCAs = poolFor(upCA)
		return tls.Dial(network, at.String(), cfg)
	}
}

// connectTunnel dials the proxy, performs the CONNECT handshake for `authority`, and returns the raw
// conn positioned at the start of the tunnel (ready for TLS).
func connectTunnel(t *testing.T, proxyAddr, authority string) net.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	if err := expectEstablished(raw); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	return raw
}

func TestIntercept_DecryptsRelaysAndMasks(t *testing.T) {
	dest, upCA := upstreamServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nSECRETBODY")

	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pxLn.Close()

	dial := dialTo(dest, upCA) // the pump verifies the REAL upstream normally, against the CONNECT name
	flowCh := make(chan model.InterceptedFlow, 1)
	go func() {
		c, err := pxLn.Accept()
		if err != nil {
			return
		}
		flowCh <- intercept(c, "example.com:443", proxyCA, dial)
	}()

	// The client trusts the PROXY CA (as if the CA were installed), dials the pump with SNI example.com.
	cc, err := tls.Dial("tcp", pxLn.Addr().String(), &tls.Config{RootCAs: poolFor(proxyCA), ServerName: "example.com"})
	if err != nil {
		t.Fatalf("client handshake with the proxy leaf must succeed: %v", err)
	}
	cc.Write([]byte("GET /p HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer TOPSECRET\r\n\r\n"))
	resp, _ := io.ReadAll(cc)
	if !strings.Contains(string(resp), "SECRETBODY") {
		t.Fatalf("client must receive the real (relayed, unmodified) upstream response: %q", resp)
	}

	flow := <-flowCh
	if flow.Status != model.FlowDecrypted {
		t.Fatalf("status = %q, want decrypted", flow.Status)
	}
	if !strings.Contains(flow.SentText, "GET /p") || !strings.Contains(flow.SentText, "example.com") {
		t.Fatalf("request plaintext not captured: %q", flow.SentText)
	}
	if strings.Contains(flow.SentText, "TOPSECRET") {
		t.Fatalf("the Authorization secret must be MASKED before the flow is built: %q", flow.SentText)
	}
	if !strings.Contains(flow.RecvText, "SECRETBODY") {
		t.Fatalf("response plaintext not captured: %q", flow.RecvText)
	}
	if flow.DestName != "example.com" || flow.SNI != "example.com" {
		t.Fatalf("SNI/dest not recorded: %+v", flow)
	}
}

// A cert-pinned client (does not trust our CA) rejects the leaf; the proxy reports it honestly as
// pinned and closes, never claiming decryption.
func TestIntercept_PinnedClientReportedNotBroken(t *testing.T) {
	dest, upCA := upstreamServer(t, "unused")
	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pxLn.Close()

	flowCh := make(chan model.InterceptedFlow, 1)
	go func() {
		c, err := pxLn.Accept()
		if err != nil {
			return
		}
		flowCh <- intercept(c, "example.com:443", proxyCA, dialTo(dest, upCA))
	}()

	// Client trusts an EMPTY pool → rejects the proxy's leaf (pinning).
	_, err := tls.Dial("tcp", pxLn.Addr().String(), &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com"})
	if err == nil {
		t.Fatal("a pinned client must reject the intercept leaf")
	}
	if flow := <-flowCh; flow.Status != model.FlowPinned {
		t.Fatalf("a rejected handshake must be reported as pinned, got %q", flow.Status)
	}
}

// cp-p2c F-2: non-TLS bytes to the proxy port → opaque (no ClientHello), NOT mislabeled pinned.
func TestIntercept_NonTLSIsOpaqueNotPinned(t *testing.T) {
	proxyCA, _ := ca.NewCA() // no upstream needed: the handshake fails before any dial

	c1, c2 := net.Pipe()
	flowCh := make(chan model.InterceptedFlow, 1)
	go func() { flowCh <- intercept(c2, "example.com:443", proxyCA, defaultDial) }()
	// speak plain HTTP (not TLS) then close; no ClientHello ever arrives.
	go func() { c1.Write([]byte("GET / HTTP/1.1\r\n\r\n")); c1.Close() }()
	if flow := <-flowCh; flow.Status != model.FlowOpaque {
		t.Fatalf("non-TLS input must be opaque, got %q", flow.Status)
	}
}

// Proxy.Serve wires accept → CONNECT → intercept → publish end-to-end, speaking the SAME protocol a
// real client does: an HTTP CONNECT tunnel, then TLS inside it. This is the path the system proxy
// setting drives: no pf, no root, no ioctl.
func TestProxy_ServePublishesDecryptedFlow(t *testing.T) {
	dest, upCA := upstreamServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pxLn.Close()

	got := make(chan model.InterceptedMessage, 4)
	p := &Proxy{CA: proxyCA, Dial: dialTo(dest, upCA), Sink: chanSink(got)}
	go p.Serve(pxLn)

	// Speak CONNECT, naming the destination; this is what replaces the pf origdest lookup.
	raw := connectTunnel(t, pxLn.Addr().String(), "example.com:443")
	defer raw.Close()
	cc := tls.Client(raw, &tls.Config{RootCAs: poolFor(proxyCA), ServerName: "example.com"})
	if err := cc.Handshake(); err != nil {
		t.Fatal(err)
	}
	cc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	br := bufio.NewReader(cc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal("client read response:", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hi" {
		t.Fatalf("client received wrong body: %q", body)
	}
	cc.Close()

	select {
	case m := <-got:
		if m.Status != model.FlowDecrypted {
			t.Fatalf("served message wrong: %+v", m)
		}
		// The destination now comes from the CONNECT authority, not an inferred lookup.
		if m.DestName != "example.com" {
			t.Fatalf("DestName should be the CONNECT authority host, got %q", m.DestName)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not publish the message")
	}
}

// expectEstablished reads the proxy's CONNECT response and requires a 200.
func expectEstablished(c net.Conn) error {
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("CONNECT not established: %s", resp.Status)
	}
	if br.Buffered() != 0 {
		return fmt.Errorf("proxy sent %d bytes past the CONNECT response", br.Buffered())
	}
	return nil
}

type chanSink chan model.InterceptedMessage

func (c chanSink) Publish(m model.InterceptedMessage) error { c <- m; return nil }
func (c chanSink) Close() error                             { return nil }

// A connection we cannot resolve must publish a FlowError, never vanish. The pf-era code closed the
// conn and returned silently when the destination lookup failed, which is indistinguishable from
// "nothing arrived" in the console, the exact silent-drop the smoke test surfaced (Rule 13).
func TestProxy_UnresolvableConnPublishesError(t *testing.T) {
	proxyCA, _ := ca.NewCA()
	got := make(chan model.InterceptedMessage, 1)
	p := &Proxy{CA: proxyCA, Sink: chanSink(got)}
	c1, c2 := net.Pipe()
	go p.handle(c2, defaultDial)
	// Speak something that is NOT a CONNECT.
	go func() { fmt.Fprint(c1, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); c1.Close() }()
	select {
	case m := <-got:
		if m.Status != model.FlowError {
			t.Fatalf("a non-CONNECT must publish FlowError, got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a non-CONNECT was dropped SILENTLY; the console would show nothing")
	}
}

// cp-p2d F-2: a panic inside handle must not leak the conn; the recover closes it. The panic is driven
// through `dial`, which is only reached AFTER a real client TLS handshake, so the test must complete
// the CONNECT *and* the handshake to get there (an earlier version stalled in Handshake() and "passed"
// on a timeout instead of exercising the recover).
func TestProxy_HandlePanicClosesConn(t *testing.T) {
	proxyCA, _ := ca.NewCA()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	panicDial := func(string, string, *tls.Config) (net.Conn, error) { panic("boom") }
	done := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		(&Proxy{CA: proxyCA}).handle(c, panicDial)
		close(done)
	}()

	raw := connectTunnel(t, ln.Addr().String(), "example.com:443")
	defer raw.Close()
	cc := tls.Client(raw, &tls.Config{RootCAs: poolFor(proxyCA), ServerName: "example.com"})
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client handshake with the proxy leaf must succeed: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle hung on a panicking dial")
	}
	// The conn must be CLOSED: a read returns EOF/error promptly. io.ReadAll reports EOF as a nil error,
	// so the thing that actually distinguishes a leak is a read that TIMES OUT (still open, nothing coming).
	raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, err := io.ReadAll(cc)
	if len(b) != 0 {
		t.Fatalf("no data should follow a panic, got %q", b)
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		t.Fatal("conn still open after a handle panic; the fd leaked")
	}
}
