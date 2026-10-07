package certs

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestMintRoundTrip(t *testing.T) {
	now := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	ca, err := NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.Mint("spiffe://prod/ns/pay/sa/ledger", 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b.CertPEM)
	if block == nil {
		t.Fatal("no pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CAPEM())
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://prod/ns/pay/sa/ledger" {
		t.Fatalf("uri san: %v", cert.URIs)
	}
}

func TestMintRejectsLongTTL(t *testing.T) {
	now := time.Now()
	ca, _ := NewCA(now)
	if _, err := ca.Mint("spiffe://prod/x", 48*time.Hour, now); err == nil {
		t.Fatal("expected 24h ceiling")
	}
	if _, err := ca.Mint("https://not-spiffe", time.Minute, now); err == nil {
		t.Fatal("expected scheme check")
	}
}
