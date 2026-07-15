package intercept

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
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

func TestIntercept_DecryptsRelaysAndMasks(t *testing.T) {
	dest, upCA := upstreamServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nSECRETBODY")

	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pxLn.Close()

	dial := func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		cfg.RootCAs = poolFor(upCA) // the pump verifies the REAL upstream normally
		return tls.Dial(network, addr, cfg)
	}
	flowCh := make(chan model.InterceptedFlow, 1)
	go func() {
		c, err := pxLn.Accept()
		if err != nil {
			return
		}
		flowCh <- intercept(c, dest, proxyCA, dial)
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
	dest, _ := upstreamServer(t, "unused")
	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pxLn.Close()

	flowCh := make(chan model.InterceptedFlow, 1)
	go func() {
		c, err := pxLn.Accept()
		if err != nil {
			return
		}
		flowCh <- intercept(c, dest, proxyCA, defaultDial)
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
	dest, _ := upstreamServer(t, "unused")
	proxyCA, _ := ca.NewCA()
	c1, c2 := net.Pipe()
	flowCh := make(chan model.InterceptedFlow, 1)
	go func() { flowCh <- intercept(c2, dest, proxyCA, defaultDial) }()
	// speak plain HTTP (not TLS) then close — no ClientHello ever arrives.
	go func() { c1.Write([]byte("GET / HTTP/1.1\r\n\r\n")); c1.Close() }()
	if flow := <-flowCh; flow.Status != model.FlowOpaque {
		t.Fatalf("non-TLS input must be opaque, got %q", flow.Status)
	}
}

// Proxy.Serve wires accept → origDest → intercept → publish end-to-end (injected origDest/dial/sink,
// no pf/root).
func TestProxy_ServePublishesDecryptedFlow(t *testing.T) {
	dest, upCA := upstreamServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
	proxyCA, _ := ca.NewCA()
	pxLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pxLn.Close()

	got := make(chan model.InterceptedFlow, 1)
	p := &Proxy{
		CA:       proxyCA,
		OrigDest: func(net.Conn) (netip.AddrPort, error) { return dest, nil },
		Dial: func(n, a string, cfg *tls.Config) (net.Conn, error) {
			cfg.RootCAs = poolFor(upCA)
			return tls.Dial(n, a, cfg)
		},
		Sink: chanSink(got),
	}
	go p.Serve(pxLn)

	cc, err := tls.Dial("tcp", pxLn.Addr().String(), &tls.Config{RootCAs: poolFor(proxyCA), ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	cc.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	io.ReadAll(cc)
	select {
	case f := <-got:
		if f.Status != model.FlowDecrypted || f.DestName != "example.com" {
			t.Fatalf("served flow wrong: %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not publish the flow")
	}
}

type chanSink chan model.InterceptedFlow

func (c chanSink) Publish(f model.InterceptedFlow) error { c <- f; return nil }
func (c chanSink) Close() error                          { return nil }
