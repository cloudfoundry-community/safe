package cli

// Commands that write a certificate back rewrite the whole secret from the
// certificate they read. An intermediate CA is commonly stored with the
// issuers above it in the same attribute, and regenerating its revocation
// list — or issuing anything under it — used to leave only the intermediate
// behind.

import (
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// storeChainedCA writes an intermediate CA to path with the root appended to
// its certificate attribute, the way a chain is usually kept.
func storeChainedCA(t *testing.T, fv *cliFakeVault, path string, root *vault.X509) *vault.X509 {
	t.Helper()

	inter, err := vault.NewCertificate("CN=inter", []string{"inter"},
		[]string{"key_cert_sign", "crl_sign"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	inter.MakeCA()
	if err := root.Sign(inter, 24*time.Hour); err != nil {
		t.Fatalf("sign the intermediate: %v", err)
	}
	storeCert(t, fv, path, inter)

	stored := fv.get(path)
	stored["certificate"] += string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.Certificate.Raw,
	}))
	stored["combined"] = stored["certificate"] + stored["key"]
	fv.set(path, stored)

	return inter
}

// certCount reports how many certificates the attribute at path holds.
func certCount(t *testing.T, fv *cliFakeVault, path, attr string) int {
	t.Helper()
	return strings.Count(fv.get(path)[attr], "-----BEGIN CERTIFICATE-----")
}

// Regenerating a revocation list writes the CA back over itself.
func TestRegeneratingACRLKeepsTheChain(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeChainedCA(t, fv, "secret/inter", newCA(t, "root"))

	c := newX509CLI(t)
	c.opt.X509.CRL.Renew = true
	if err := c.cmdX509Crl("x509 crl", "secret/inter"); err != nil {
		t.Fatalf("crl --renew: %v", err)
	}

	if got := certCount(t, fv, "secret/inter", "certificate"); got != 2 {
		t.Errorf("certificate holds %d certificates, want 2", got)
	}
	if got := certCount(t, fv, "secret/inter", "combined"); got != 2 {
		t.Errorf("combined holds %d certificates, want 2", got)
	}
}

// Issuing a certificate saves the signing CA back, to record the serial
// number it just handed out.
func TestIssuingUnderAChainedCAKeepsItsChain(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeChainedCA(t, fv, "secret/inter", newCA(t, "root"))

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/inter"
	if err := c.cmdX509Issue("x509 issue", "secret/leaf"); err != nil {
		t.Fatalf("issue: %v", err)
	}

	if got := certCount(t, fv, "secret/inter", "certificate"); got != 2 {
		t.Errorf("the CA's certificate holds %d certificates, want 2", got)
	}
}

// Revoking writes the CA back to record the revoked serial number.
func TestRevokingAgainstAChainedCAKeepsItsChain(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	inter := storeChainedCA(t, fv, "secret/inter", newCA(t, "root"))
	storeCert(t, fv, "secret/leaf", newLeaf(t, inter, "leaf"))

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/inter"
	if err := c.cmdX509Revoke("x509 revoke", "secret/leaf"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if got := certCount(t, fv, "secret/inter", "certificate"); got != 2 {
		t.Errorf("the CA's certificate holds %d certificates, want 2", got)
	}
}
