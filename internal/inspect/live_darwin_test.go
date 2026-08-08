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
	"sync"
	"testing"
	"time"
)

// liveSNI is the hostname the smoke test's client puts in its ClientHello and the capture must
// recover, proving the whole native path end to end.
const liveSNI = "counterspy.smoke.test"

// requireLiveEnv skips unless the root smoke gate is set, so `go test ./...` stays green without root.
func requireLiveEnv(t *testing.T) {
	t.Helper()
	if os.Getenv("COUNTERSPY_LIVE_CAPTURE") != "1" {
		t.Skip("root live-capture smoke: run `sudo COUNTERSPY_LIVE_CAPTURE=1 go test -run LiveCapture -v ./internal/inspect/`")
	}
}

// TestLiveCapture_LoopbackTLS_SNI is the ROOT smoke test for the /dev/bpf capture path that CI
// cannot run. It stands up a local TLS server on lo0, opens a real BPF capture scoped to it,
// drives ClientHellos across the loopback, and asserts inspect.Inspect recovers the SNI. That one
// assertion exercises the root-only read chain end to end: opening /dev/bpf, BIOCSETIF binding, the
// non-blocking bounded read, the DLT_NULL link strip, IP/TCP framing, the TLS ClientHello parse,
// and the flow correlation. The companion test below proves the BIOCSETF filter separately. No
// external network; fully deterministic.
//
//	sudo COUNTERSPY_LIVE_CAPTURE=1 go test -run LiveCapture -v ./internal/inspect/
func TestLiveCapture_LoopbackTLS_SNI(t *testing.T) {
	requireLiveEnv(t)

	ln := newLoopbackTLSServer(t)
	defer ln.Close()

	remote := loopbackRemote(t, ln)
	src, err := OpenLiveCapture("lo0", remote, 6*time.Second)
	if err != nil {
		t.Fatalf("OpenLiveCapture on lo0 failed (are you root?): %v", err)
	}
	defer src.Close()

	// Keep new ClientHellos flowing so one is on the wire while the capture reads (defeats the
	// capture-setup-vs-first-packet race deterministically). Joined before the test returns.
	stop, wait := driveLoopbackTLS(ln.Addr().String())
	defer wait()
	defer close(stop)

	res := Inspect(src, Flow{Remote: remote}, 1024)
	if res.SNI != liveSNI {
		t.Fatalf("live capture did NOT recover the SNI: coverage=%d tier=%q sni=%q verdict=%q err=%v",
			res.Coverage, res.Tier, res.SNI, res.Verdict, res.Err)
	}
	t.Logf("LIVE CAPTURE OK: recovered SNI=%q via the real /dev/bpf path (coverage=%d verdict=%q)",
		res.SNI, res.Coverage, res.Verdict)
}

// TestLiveCapture_FilterDropsUnscopedTraffic proves the BIOCSETF scoped filter actually engaged,
// which the SNI test above cannot, since on loopback both endpoints are 127.0.0.1 and a host filter
// passes everything regardless. Here the capture is scoped to a bogus TEST-NET host (RFC 5737, never
// on the wire) while real loopback TLS traffic flows; a correctly-installed filter drops it all in
// kernel, so the RAW source stays silent. Any packet reaching userspace means the filter no-op'd.
func TestLiveCapture_FilterDropsUnscopedTraffic(t *testing.T) {
	requireLiveEnv(t)

	ln := newLoopbackTLSServer(t)
	defer ln.Close()

	stop, wait := driveLoopbackTLS(ln.Addr().String()) // real 127.0.0.1 loopback traffic
	defer wait()
	defer close(stop)

	// A filter scoped to an address that is provably not on lo0 (203.0.113.0/24 = TEST-NET-3).
	bogus := netip.MustParseAddrPort("203.0.113.7:9")
	src, err := OpenLiveCapture("lo0", bogus, 1500*time.Millisecond)
	if err != nil {
		t.Fatalf("OpenLiveCapture on lo0 failed (are you root?): %v", err)
	}
	defer src.Close()

	// Read the raw source for the bounded window. A working kernel filter yields zero packets (all
	// live traffic is to 127.0.0.1, which the filter drops); Next returns io.EOF at the deadline.
	leaked := 0
	for i := 0; i < 128; i++ {
		if _, err := src.Next(); err != nil {
			break // io.EOF at the deadline: the filter held
		}
		leaked++
	}
	if leaked != 0 {
		t.Fatalf("BIOCSETF filter did NOT engage: %d loopback packets not scoped to the filter leaked to userspace", leaked)
	}
	t.Logf("FILTER OK: kernel dropped all traffic not scoped to the capture (raw source silent)")
}

// loopbackRemote is the listener's address as a netip.AddrPort (the flow the smoke test inspects).
func loopbackRemote(t *testing.T, ln net.Listener) netip.AddrPort {
	t.Helper()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

// driveLoopbackTLS repeatedly opens TLS connections carrying liveSNI until stop is closed. It
// returns the stop channel and a wait func to join the goroutine (close(stop) then wait()).
func driveLoopbackTLS(addr string) (chan struct{}, func()) {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Test-only: the client connects to a self-signed cert generated inline in
		// newLoopbackTLSServer, purely to emit a ClientHello carrying liveSNI for the capture to
		// parse; no identity is trusted here, so skipping verification is correct and scoped to
		// this smoke harness.
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: liveSNI, MinVersion: tls.VersionTLS12} //nolint:gosec // self-signed loopback smoke server
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, cfg); err == nil {
				c.Close()
			}
			time.Sleep(120 * time.Millisecond)
		}
	}()
	return stop, wg.Wait
}

// newLoopbackTLSServer starts a TLS listener on 127.0.0.1 with a fresh self-signed cert and an
// accept loop that completes handshakes and closes; the loop exits when the listener is closed.
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
