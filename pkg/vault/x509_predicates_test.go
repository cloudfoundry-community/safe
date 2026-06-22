// TV-04 (pure predicates): Expired, ValidFor, Revoke, HasRevoked.
// These helpers operate on an *X509 value and require no HTTP server.
// A fixture certificate is built with fixed time bounds so the tests are
// fully deterministic.
package vault_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// randSerial generates a random 128-bit certificate serial number.
func randSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int for serial: %v", err)
	}
	// Ensure non-zero.
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial
}

// buildX509 creates a minimal self-signed X509 wrapping a cert whose
// NotBefore/NotAfter span the provided window. Each call uses a unique serial.
func buildX509(t *testing.T, notBefore, notAfter time.Time) *vault.X509 {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024) // small key — tests only
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &vault.X509{Certificate: cert, PrivateKey: key}
}

// buildCA creates a CA-flagged X509 with a CRL, used for Revoke/HasRevoked tests.
func buildCA(t *testing.T) *vault.X509 {
	t.Helper()
	ca := buildX509(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	ca.MakeCA()
	return ca
}

// ---------------------------------------------------------------------------
// Expired
// ---------------------------------------------------------------------------

// TestExpiredTrueWhenAfterNotAfter verifies Expired returns true when
// NotAfter is in the past.
func TestExpiredTrueWhenAfterNotAfter(t *testing.T) {
	t.Parallel()
	past := time.Now().Add(-2 * time.Hour)
	x := buildX509(t, past.Add(-time.Hour), past)
	if !x.Expired() {
		t.Error("Expired() = false, want true for cert with past NotAfter")
	}
}

// TestExpiredFalseForActiveCert verifies Expired returns false for a cert
// whose window includes now.
func TestExpiredFalseForActiveCert(t *testing.T) {
	t.Parallel()
	x := buildX509(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if x.Expired() {
		t.Error("Expired() = true, want false for active cert")
	}
}

// TestExpiredTrueWhenBeforeNotBefore verifies Expired returns true when
// now is before NotBefore (not yet valid).
func TestExpiredTrueWhenBeforeNotBefore(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(2 * time.Hour)
	x := buildX509(t, future, future.Add(time.Hour))
	if !x.Expired() {
		t.Error("Expired() = false, want true for cert not yet valid")
	}
}

// ---------------------------------------------------------------------------
// ValidFor — domain
// ---------------------------------------------------------------------------

// TestValidForDomainMatch verifies that ValidFor returns true for a domain
// listed in DNSNames.
func TestValidForDomainMatch(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com", "www.example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	x := &vault.X509{Certificate: cert, PrivateKey: key}

	ok, err := x.ValidFor("example.com")
	if err != nil {
		t.Fatalf("ValidFor: %v", err)
	}
	if !ok {
		t.Error("ValidFor(example.com) = false, want true")
	}
}

// TestValidForDomainMismatch verifies that ValidFor returns an error for a
// domain not listed in DNSNames.
func TestValidForDomainMismatch(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	x := &vault.X509{Certificate: cert, PrivateKey: key}

	ok, err := x.ValidFor("other.com")
	if err == nil {
		t.Fatal("ValidFor(other.com) returned nil error, want error")
	}
	if ok {
		t.Error("ValidFor(other.com) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// ValidFor — IP
// ---------------------------------------------------------------------------

// TestValidForIPMatch verifies that ValidFor returns true for an IP that
// is listed in IPAddresses.
func TestValidForIPMatch(t *testing.T) {
	t.Parallel()
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(t),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	x := &vault.X509{Certificate: cert, PrivateKey: key}

	ok, err := x.ValidFor("10.0.0.1")
	if err != nil {
		t.Fatalf("ValidFor IP: %v", err)
	}
	if !ok {
		t.Error("ValidFor(10.0.0.1) = false, want true")
	}
}

// ---------------------------------------------------------------------------
// Revoke / HasRevoked
// ---------------------------------------------------------------------------

// TestRevokeAndHasRevoked verifies that Revoke adds a cert to the CA's CRL
// and HasRevoked detects it.
func TestRevokeAndHasRevoked(t *testing.T) {
	t.Parallel()
	ca := buildCA(t)
	leaf := buildX509(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	if ca.HasRevoked(leaf) {
		t.Fatal("HasRevoked = true before Revoke, want false")
	}

	ca.Revoke(leaf)

	if !ca.HasRevoked(leaf) {
		t.Error("HasRevoked = false after Revoke, want true")
	}
}

// TestRevokeIdempotent verifies that calling Revoke twice on the same cert
// does not add a duplicate CRL entry.
func TestRevokeIdempotent(t *testing.T) {
	t.Parallel()
	ca := buildCA(t)
	leaf := buildX509(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	ca.Revoke(leaf)
	ca.Revoke(leaf)

	count := 0
	for _, entry := range ca.CRL.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leaf.Certificate.SerialNumber) == 0 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 CRL entry for leaf, got %d", count)
	}
}

// TestHasRevokedDifferentCert verifies that HasRevoked returns false for a
// cert whose serial is not in the CRL.
func TestHasRevokedDifferentCert(t *testing.T) {
	t.Parallel()
	ca := buildCA(t)
	leaf1 := buildX509(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	leaf2 := buildX509(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	ca.Revoke(leaf1)

	if ca.HasRevoked(leaf2) {
		t.Error("HasRevoked(leaf2) = true, want false — wrong serial matched")
	}
}
