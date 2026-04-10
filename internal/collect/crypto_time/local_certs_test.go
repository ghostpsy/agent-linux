//go:build linux

package crypto_time

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectLocalTlsCertInventoryFromPaths_ParsesNotAfter(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.pem")
	writeTestCertPEM(t, p, time.Now().Add(60*24*time.Hour), x509.SHA256WithRSA)
	inv := collectLocalTlsCertInventoryFromPaths([]string{p})
	if inv == nil || len(inv.Items) != 1 {
		t.Fatalf("items: %+v", inv)
	}
	if inv.Items[0].UsesSha1Signature != nil {
		t.Fatal("expected no SHA-1 flag for SHA256 cert")
	}
	if inv.Sha1SignatureCertCount != 0 {
		t.Fatalf("sha1 count %d", inv.Sha1SignatureCertCount)
	}
}

func TestCollectLocalTlsCertInventoryFromPaths_Sha1Count(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sha1.pem")
	writeTestCertPEM(t, p, time.Now().Add(60*24*time.Hour), x509.SHA1WithRSA)
	inv := collectLocalTlsCertInventoryFromPaths([]string{p})
	if inv == nil || inv.Sha1SignatureCertCount != 1 {
		t.Fatalf("inv %+v", inv)
	}
	if inv.Items[0].UsesSha1Signature == nil || !*inv.Items[0].UsesSha1Signature {
		t.Fatal("expected uses_sha1_signature")
	}
}

func writeTestCertPEM(t *testing.T, path string, notAfter time.Time, sigAlg x509.SignatureAlgorithm) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"ghostpsy-test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
}
