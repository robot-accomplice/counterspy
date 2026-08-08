// Package ca is the local, single-purpose, reversible Certificate Authority the TLS-intercept proxy
// uses to mint per-SNI leaf certs on the fly (Phase 2). It is all stdlib crypto and has no OS
// dependency; installing the CA as trusted (the invasive, consented step) lives in trust_*.go.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// defaultLeafCap bounds the minted-leaf cache. The SNI is attacker/app-controlled, so an unbounded
// cache is a memory-DoS vector for a long-running proxy (a flood of distinct SNIs); evict oldest.
const defaultLeafCap = 1024

// leafRenewBefore re-mints a cached leaf this long before it expires, so a leaf minted early in a
// long daemon lifetime is never served past validity (which would silently break the handshake).
const leafRenewBefore = 24 * time.Hour

// CA is a self-signed root plus a bounded, expiry-aware cache of leaves it has minted. Safe for
// concurrent use: the proxy mints leaves from many connection goroutines.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
	order  []string // insertion order of distinct hosts, for oldest-eviction past cap
	cap    int
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewCA generates a fresh single-purpose intercept CA (P-256, 10-year, clearly named so a human
// inspecting their keychain sees exactly what it is).
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "CounterSpy Local Intercept CA", Organization: []string{"CounterSpy"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves:  map[string]*tls.Certificate{},
		cap:     defaultLeafCap,
	}, nil
}

// LoadCA reconstructs a CA from a previously-saved PEM pair, so the same trusted CA persists across
// runs (install trust once, reuse) instead of re-prompting every launch.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca: bad certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("ca: bad key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	// Fail LOUDLY at load if the key doesn't match the cert, instead of minting leaves that only
	// fail obscurely at a client's handshake later (Audit cp-p2a F-4).
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("ca: private key does not match the certificate")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM, leaves: map[string]*tls.Certificate{}, cap: defaultLeafCap}, nil
}

// CertPEM is the CA certificate (what gets installed as trusted).
func (c *CA) CertPEM() []byte { return c.certPEM }

// PEM returns the cert + key PEM pair for persistence.
func (c *CA) PEM() (certPEM, keyPEM []byte, err error) {
	kd, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return nil, nil, err
	}
	return c.certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

// normalizeHost trims the host and strips an IPv6 zone id (so net.ParseIP recognizes the address;
// otherwise "fe80::1%en0" would fall through to a DNS SAN and never match the real IP). ok is false
// for an empty/whitespace host, which is not something we should mint a (useless) cert for.
func normalizeHost(host string) (string, bool) {
	h := strings.TrimSpace(host)
	if i := strings.IndexByte(h, '%'); i >= 0 {
		if ip := net.ParseIP(h[:i]); ip != nil {
			h = h[:i]
		}
	}
	if h == "" {
		return "", false
	}
	return h, true
}

// LeafFor mints (and caches) a server leaf for host (a DNS name or a bare IP) signed by the CA, so
// the proxy can present it to a client terminating TLS to that destination. The presented chain is
// [leaf, CA] so a client trusting the CA validates it. The cache is bounded (oldest-evicted) and
// expiry-aware (a near-expired leaf is re-minted). Keygen happens OUTSIDE the lock so concurrent
// handshakes to distinct new hosts don't serialize.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	h, ok := normalizeHost(host)
	if !ok {
		return nil, fmt.Errorf("ca: refusing to mint a leaf for an empty host")
	}
	if lf := c.cachedFresh(h); lf != nil {
		return lf, nil
	}
	lf, err := c.mint(h)
	if err != nil {
		return nil, err
	}
	return c.store(h, lf), nil
}

func (c *CA) cachedFresh(h string) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	if lf, ok := c.leaves[h]; ok && lf.Leaf.NotAfter.After(time.Now().Add(leafRenewBefore)) {
		return lf
	}
	return nil
}

// store inserts lf, evicting the oldest host past cap. A concurrent minter may have beaten us; if a
// FRESH leaf already exists for h, prefer it (don't churn the cache with duplicate mints).
func (c *CA) store(h string, lf *tls.Certificate) *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ex, ok := c.leaves[h]; ok && ex.Leaf.NotAfter.After(time.Now().Add(leafRenewBefore)) {
		return ex
	}
	if _, existed := c.leaves[h]; !existed {
		if len(c.order) >= c.cap {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.leaves, oldest)
		}
		c.order = append(c.order, h)
	}
	c.leaves[h] = lf
	return lf
}

func (c *CA) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}
