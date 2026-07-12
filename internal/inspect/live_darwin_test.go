//go:build darwin

package inspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

// liveSNI is the hostname the smoke test's client puts in its ClientHello and the capture must
// recover — proving the whole native path end to end.
const liveSNI = "counterspy.smoke.test"

// TestLiveCapture_LoopbackTLS_SNI is the ROOT smoke test for the /dev/bpf capture path that CI
// cannot run. It stands up a local TLS server on lo0, opens a real BPF capture scoped to it,
// drives ClientHellos across the loopback, and asserts inspect.Inspect recovers the SNI. That one
// assertion exercises every root-only link in the chain: opening /dev/bpf, BIOCSETIF binding, the
// BIOCSETF scoped filter, the non-blocking bounded read, the DLT_NULL link strip, IP/TCP framing,
// the TLS ClientHello parse, and the flow correlation. No external network; fully deterministic.
//
// It is gated behind COUNTERSPY_LIVE_CAPTURE=1 so `go test ./...` stays green without root. Run:
//
//	sudo COUNTERSPY_LIVE_CAPTURE=1 go test -run LiveCapture -v ./internal/inspect/
func TestLiveCapture_LoopbackTLS_SNI(t *testing.T) {
	if os.Getenv("COUNTERSPY_LIVE_CAPTURE") != "1" {
		t.Skip("root live-capture smoke: run `sudo COUNTERSPY_LIVE_CAPTURE=1 go test -run LiveCapture -v ./internal/inspect/`")
	}

	ln := newLoopbackTLSServer(t)
	defer ln.Close()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	remote := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))

	src, err := OpenLiveCapture("lo0", remote, 6*time.Second)
	if err != nil {
		t.Fatalf("OpenLiveCapture on lo0 failed (are you root?): %v", err)
	}
	defer src.Close()

	// Keep new ClientHellos flowing so one is on the wire while the capture reads (defeats the
	// capture-setup-vs-first-packet race deterministically).
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		// Test-only: the client connects to a self-signed cert generated inline above, purely to
		// emit a ClientHello carrying liveSNI for the capture to parse — no identity is being
		// trusted here, so skipping verification is correct and scoped to this smoke harness.
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: liveSNI, MinVersion: tls.VersionTLS12} //nolint:gosec // self-signed loopback smoke server
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), cfg); err == nil {
				c.Close()
			}
			time.Sleep(120 * time.Millisecond)
		}
	}()

	res := Inspect(src, Flow{Remote: remote}, 1024)
	if res.SNI != liveSNI {
		t.Fatalf("live capture did NOT recover the SNI — coverage=%d tier=%q sni=%q verdict=%q err=%v",
			res.Coverage, res.Tier, res.SNI, res.Verdict, res.Err)
	}
	t.Logf("LIVE CAPTURE OK — recovered SNI=%q via the real /dev/bpf path (coverage=%d verdict=%q)",
		res.SNI, res.Coverage, res.Verdict)
}

// newLoopbackTLSServer starts a TLS listener on 127.0.0.1 with a fresh self-signed cert and an
// accept loop that completes handshakes and closes. Its address is the flow the smoke test inspects.
func newLoopbackTLSServer(t *testing.T) net.Listener {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: liveSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{liveSNI},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(conn net.Conn) {
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				conn.Close()
			}(c)
		}
	}()
	return ln
}
