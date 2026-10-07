package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"sync/atomic"
	"time"
)

// CA is a throwaway in-process CA. Fine for the control plane demo
// and for tests. For anything real, wrap a PKCS#11 / Vault / KMS
// signer and keep this type as the interface.
type CA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
	ser  atomic.Uint64
}

type Bundle struct {
	CertPEM []byte
	KeyPEM  []byte
	CAPEM   []byte
	NotAfter time.Time
	SPIFFE  string
}

func NewCA(now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "postern-ca", Organization: []string{"postern"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{key: key, cert: cert, der: der}, nil
}

func (c *CA) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Mint issues a client cert whose URI SAN is the SPIFFE id.
// TTL is the caller's problem to cap; we just encode it.
func (c *CA) Mint(spiffe string, ttl time.Duration, now time.Time) (Bundle, error) {
	if ttl <= 0 {
		return Bundle{}, fmt.Errorf("certs: ttl must be > 0")
	}
	if ttl > 24*time.Hour {
		// hard ceiling even if policy is misconfigured. I have seen
		// a "temporary" 90-day grant survive three reorgs.
		return Bundle{}, fmt.Errorf("certs: ttl %s exceeds 24h ceiling", ttl)
	}
	uri, err := url.Parse(spiffe)
	if err != nil || uri.Scheme != "spiffe" {
		return Bundle{}, fmt.Errorf("certs: bad spiffe id %q", spiffe)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Bundle{}, err
	}
	serial := c.ser.Add(1) + 1
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(serial)),
		Subject:      pkix.Name{CommonName: spiffe},
		NotBefore:    now.Add(-30 * time.Second), // clock skew. 30s is enough; 1h is how you get replayed certs
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return Bundle{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CAPEM:    c.CAPEM(),
		NotAfter: tmpl.NotAfter,
		SPIFFE:   spiffe,
	}, nil
}
