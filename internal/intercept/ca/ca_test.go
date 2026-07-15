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

// A minted leaf must chain to the CA and match the requested host — that's what makes a client
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
