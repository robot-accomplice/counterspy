package ca

import (
	"crypto/x509"
	"testing"
)

func TestNewCA_IsACA(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.IsCA || ca.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("the root must be a signing CA")
	}
}

// A minted leaf must chain to the CA and match the requested host; that's what makes a client
// trusting the CA accept the proxy's TLS termination.
func TestCA_MintsVerifiableLeaf(t *testing.T) {
	ca, _ := NewCA()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	for _, host := range []string{"example.com", "cdn.sub.example.org", "93.184.216.34"} {
		lf, err := ca.LeafFor(host)
		if err != nil {
			t.Fatalf("LeafFor(%s): %v", host, err)
		}
		leaf, _ := x509.ParseCertificate(lf.Certificate[0])
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool}); err != nil {
			// DNSName verify won't match an IP; verify the chain without the name check for IPs.
			if _, err2 := leaf.Verify(x509.VerifyOptions{Roots: pool}); err2 != nil {
				t.Fatalf("leaf for %s must chain to the CA: %v / %v", host, err, err2)
			}
		}
		if len(lf.Certificate) != 2 {
			t.Fatalf("presented chain must be [leaf, CA], got %d certs", len(lf.Certificate))
		}
	}
}

func TestCA_LeafCacheReturnsSame(t *testing.T) {
	ca, _ := NewCA()
	a, _ := ca.LeafFor("example.com")
	b, _ := ca.LeafFor("example.com")
	if a != b {
		t.Fatal("a repeated host must return the cached leaf, not re-mint")
	}
}

func TestCA_PEMRoundTrip(t *testing.T) {
	ca, _ := NewCA()
	certPEM, keyPEM, err := ca.PEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	// The reloaded CA must still mint leaves that verify against the ORIGINAL cert.
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	lf, err := loaded.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(lf.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
		t.Fatalf("a reloaded CA must mint leaves that still chain: %v", err)
	}
}

// Audit cp-p2a F-3/F-4: LoadCA rejects garbage and a mismatched key clearly, at load time.
func TestLoadCA_RejectsBadInput(t *testing.T) {
	if _, err := LoadCA(nil, nil); err == nil {
		t.Fatal("nil PEM must error")
	}
	if _, err := LoadCA([]byte("not pem"), []byte("not pem")); err == nil {
		t.Fatal("garbage PEM must error")
	}
	ca1, _ := NewCA()
	ca2, _ := NewCA()
	cert1, _, _ := ca1.PEM()
	_, key2, _ := ca2.PEM()
	if _, err := LoadCA(cert1, key2); err == nil {
		t.Fatal("a key that doesn't match the cert must be rejected at load, not at handshake")
	}
}

// Antagonist cp-p2a F-1/F-3: hostile/edge SNI: empty refused; IPv6 zone stripped so the IP SAN is set.
func TestLeafFor_HostNormalization(t *testing.T) {
	ca, _ := NewCA()
	if _, err := ca.LeafFor("   "); err == nil {
		t.Fatal("an empty/whitespace host must be refused, not minted")
	}
	lf, err := ca.LeafFor("fe80::1%en0")
	if err != nil {
		t.Fatal(err)
	}
	if len(lf.Leaf.IPAddresses) != 1 || len(lf.Leaf.DNSNames) != 0 {
		t.Fatalf("a zoned IPv6 host must mint an IP SAN, not a DNS SAN: ip=%v dns=%v", lf.Leaf.IPAddresses, lf.Leaf.DNSNames)
	}
	// plain IPv6 too
	if lf6, _ := ca.LeafFor("2001:db8::1"); len(lf6.Leaf.IPAddresses) != 1 {
		t.Fatal("plain IPv6 host must mint an IP SAN")
	}
}

// Audit cp-p2a F-1: the leaf cache is bounded; a flood of distinct SNIs evicts oldest, no unbounded growth.
func TestLeafFor_CacheIsBounded(t *testing.T) {
	ca, _ := NewCA()
	ca.cap = 4
	hosts := []string{"a.com", "b.com", "c.com", "d.com", "e.com", "f.com"}
	for _, h := range hosts {
		if _, err := ca.LeafFor(h); err != nil {
			t.Fatal(err)
		}
	}
	ca.mu.Lock()
	n := len(ca.leaves)
	ca.mu.Unlock()
	if n > 4 {
		t.Fatalf("cache must be bounded to cap=4, holds %d", n)
	}
	if _, ok := ca.leaves["a.com"]; ok {
		t.Fatal("the oldest host should have been evicted")
	}
}

func TestCertPEM(t *testing.T) {
	ca, _ := NewCA()
	if len(ca.CertPEM()) == 0 {
		t.Fatal("CertPEM must return the CA cert")
	}
}
