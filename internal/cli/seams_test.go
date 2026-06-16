package cli

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// clearVaultEnv neutralizes every VAULT_* variable connectOrErr inspects so the
// test controls the connection inputs regardless of the developer's shell.
func clearVaultEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_CACERT",
		"VAULT_NAMESPACE", "VAULT_SKIP_VERIFY",
	} {
		t.Setenv(k, "")
	}
}

func TestConnectOrErr_NoTarget(t *testing.T) {
	clearVaultEnv(t)
	for _, auth := range []bool{true, false} {
		v, err := connectOrErr(auth)
		if !errors.Is(err, errNoVaultTarget) {
			t.Fatalf("auth=%v: expected errNoVaultTarget, got %v", auth, err)
		}
		if v != nil {
			t.Fatalf("auth=%v: expected nil vault on error", auth)
		}
	}
}

func TestConnectOrErr_NotAuthenticated(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv("VAULT_ADDR", "https://vault.example.com")

	v, err := connectOrErr(true)
	if !errors.Is(err, errNotAuthenticated) {
		t.Fatalf("expected errNotAuthenticated, got %v", err)
	}
	if v != nil {
		t.Fatal("expected nil vault on error")
	}
}

func TestConnectOrErr_NoAuthSkipsTokenCheck(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv("VAULT_ADDR", "https://vault.example.com")

	// auth=false must not require a token; NewVault makes no network calls.
	v, err := connectOrErr(false)
	if err != nil {
		t.Fatalf("expected success without a token when auth=false, got %v", err)
	}
	if v == nil {
		t.Fatal("expected a vault client")
	}
}

func TestConnectOrErr_Authenticated(t *testing.T) {
	clearVaultEnv(t)
	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "s.exampletoken")

	v, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("expected success with a token, got %v", err)
	}
	if v == nil {
		t.Fatal("expected a vault client")
	}
}

// signedCert builds a signed certificate suitable for rendering. The top-level
// KeyUsage/ExtKeyUsage and Issuer fields are populated only when a cert is
// parsed back from Vault, so callers set them directly to drive printX509.
func signedCert(t *testing.T, subject string, names []string, ca bool) *vault.X509 {
	t.Helper()
	spec, err := vault.ResolveKeySpec("rsa", 2048, "", nil)
	if err != nil {
		t.Fatalf("ResolveKeySpec: %s", err)
	}
	usage := []string{"server_auth", "client_auth"}
	if ca {
		usage = append(usage, "key_cert_sign", "crl_sign")
	}
	cert, err := vault.NewCertificate(subject, names, usage, "", spec)
	if err != nil {
		t.Fatalf("NewCertificate: %s", err)
	}
	if ca {
		cert.MakeCA()
	}
	if err := cert.Sign(cert, 365*24*time.Hour); err != nil {
		t.Fatalf("Sign: %s", err)
	}
	return cert
}

func TestPrintX509_SelfSignedLeaf(t *testing.T) {
	cert := signedCert(t, "CN=leaf.example.com",
		[]string{"leaf.example.com", "10.0.0.1", "admin@example.com"}, false)
	// Self-signed: issuer equals subject. Drive the usage rendering directly.
	cert.Certificate.Issuer = cert.Certificate.Subject
	cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	var buf bytes.Buffer
	printX509(&buf, cert)
	out := buf.String()

	for _, want := range []string{
		"leaf.example.com",
		"self-signed",
		"for the following purposes:",
		"digital-signature",
		"key-encipherment",
		"client-auth",
		"server-auth",
		"for the following names:",
		"leaf.example.com (DNS)",
		"10.0.0.1 (IP)",
		"admin@example.com (email)",
		"signed with the algorithm",
		"is not a CA",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("printX509 output missing %q\n---\n%s", want, out)
		}
	}
}

func TestPrintX509_CA(t *testing.T) {
	cert := signedCert(t, "CN=ca.example.com", []string{"ca.example.com"}, true)
	cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	var buf bytes.Buffer
	printX509(&buf, cert)
	out := buf.String()

	if !strings.Contains(out, "is a CA") || strings.Contains(out, "is not a CA") {
		t.Errorf("expected CA to render as a CA, got:\n%s", out)
	}
	for _, want := range []string{"key-cert-sign", "crl-sign"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q usage, got:\n%s", want, out)
		}
	}
}

// TestMoveCopy_Guards exercises the shared move/copy guard checks, which all
// return before any Vault access (so a nil client is safe). It pins the
// verb-parameterized messages and the copy-only versioned-source guard.
func TestMoveCopy_Guards(t *testing.T) {
	c := &CLI{opt: &Options{}}

	cases := []struct {
		name    string
		args    []string
		p       moveCopyParams
		wantErr string
	}{
		{"deep into key (move)", []string{"a/b:k", "c/d"},
			moveCopyParams{verb: "move", deep: true}, "Cannot deep copy a specific key"},
		{"deep into key (copy)", []string{"a/b", "c/d:k"},
			moveCopyParams{verb: "copy", deep: true}, "Cannot deep copy a specific key"},
		{"entire into key", []string{"a/b", "c/d:k"},
			moveCopyParams{verb: "move"}, "Cannot move from entire secret into specific key"},
		{"dest version (move)", []string{"a/b", "c/d^2"},
			moveCopyParams{verb: "move"}, "Cannot move to a specific destination version"},
		{"dest version (copy)", []string{"a/b", "c/d^2"},
			moveCopyParams{verb: "copy"}, "Cannot copy to a specific destination version"},
		{"recurse versioned source (copy)", []string{"a/b^2", "c/d"},
			moveCopyParams{verb: "copy", recurse: true, guardRecurseVersion: true},
			"Cannot recursively copy a path with specific version"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.moveCopy(nil, tc.args, tc.p)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("args=%v: want error containing %q, got %v", tc.args, tc.wantErr, err)
			}
		})
	}
}
