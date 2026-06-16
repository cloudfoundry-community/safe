package vault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"
)

// ---- ResolveKeySpec ---------------------------------------------------------

func TestResolveKeySpec(t *testing.T) {
	rsa2048, err := GenerateKey(KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("seed rsa key: %v", err)
	}
	ecP384, err := GenerateKey(KeySpec{Algorithm: "ec", Curve: elliptic.P384()})
	if err != nil {
		t.Fatalf("seed ec key: %v", err)
	}
	edKey, err := GenerateKey(KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("seed ed key: %v", err)
	}

	cases := []struct {
		name     string
		keyType  string
		bits     int
		curve    string
		wantAlgo string
		wantBits int
		wantCurv elliptic.Curve
		wantErr  bool
	}{
		{name: "default rsa 4096", keyType: "", bits: 0, wantAlgo: "rsa", wantBits: 4096},
		{name: "explicit rsa bits", keyType: "rsa", bits: 2048, wantAlgo: "rsa", wantBits: 2048},
		{name: "rsa bad bits", keyType: "rsa", bits: 3000, wantErr: true},
		{name: "ec default p256", keyType: "ec", wantAlgo: "ec", wantCurv: elliptic.P256()},
		{name: "ecdsa alias", keyType: "ecdsa", curve: "p521", wantAlgo: "ec", wantCurv: elliptic.P521()},
		{name: "ec curve dashed", keyType: "ec", curve: "P-384", wantAlgo: "ec", wantCurv: elliptic.P384()},
		{name: "ec bad curve", keyType: "ec", curve: "p999", wantErr: true},
		{name: "ed25519", keyType: "ed25519", wantAlgo: "ed25519"},
		{name: "unknown type", keyType: "dsa", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ResolveKeySpec(tc.keyType, tc.bits, tc.curve, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if spec.Algorithm != tc.wantAlgo {
				t.Errorf("algo = %q, want %q", spec.Algorithm, tc.wantAlgo)
			}
			if tc.wantBits != 0 && spec.Bits != tc.wantBits {
				t.Errorf("bits = %d, want %d", spec.Bits, tc.wantBits)
			}
			if tc.wantCurv != nil && spec.Curve != tc.wantCurv {
				t.Errorf("curve = %v, want %v", spec.Curve, tc.wantCurv)
			}
		})
	}

	// Existing-key inference (reissue path): empty type defers to the
	// existing key's algorithm and parameters.
	t.Run("infer rsa from existing", func(t *testing.T) {
		spec, err := ResolveKeySpec("", 0, "", rsa2048)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Algorithm != "rsa" || spec.Bits != 2048 {
			t.Errorf("got %+v, want rsa/2048", spec)
		}
	})
	t.Run("infer ec curve from existing", func(t *testing.T) {
		spec, err := ResolveKeySpec("", 0, "", ecP384)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Algorithm != "ec" || spec.Curve != elliptic.P384() {
			t.Errorf("got %+v, want ec/P-384", spec)
		}
	})
	t.Run("infer ed25519 from existing", func(t *testing.T) {
		spec, err := ResolveKeySpec("", 0, "", edKey)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Algorithm != "ed25519" {
			t.Errorf("got %+v, want ed25519", spec)
		}
	})
	t.Run("override existing ec curve", func(t *testing.T) {
		spec, err := ResolveKeySpec("ec", 0, "p256", ecP384)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Curve != elliptic.P256() {
			t.Errorf("curve = %v, want P-256 (override)", spec.Curve)
		}
	})
}

// ---- GenerateKey concrete types --------------------------------------------

func TestGenerateKeyTypes(t *testing.T) {
	rk, err := GenerateKey(KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rk.(*rsa.PrivateKey); !ok {
		t.Errorf("rsa: got %T", rk)
	}

	ek, err := GenerateKey(KeySpec{Algorithm: "ec", Curve: elliptic.P256()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ek.(*ecdsa.PrivateKey); !ok {
		t.Errorf("ec: got %T", ek)
	}

	dk, err := GenerateKey(KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dk.(ed25519.PrivateKey); !ok {
		t.Errorf("ed25519: got %T", dk)
	}
}

// ---- algoForKey defaults ----------------------------------------------------

func TestAlgoForKeyDefaults(t *testing.T) {
	cases := []struct {
		spec    KeySpec
		pubAlgo x509.PublicKeyAlgorithm
		sigAlgo x509.SignatureAlgorithm
	}{
		{KeySpec{Algorithm: "rsa", Bits: 2048}, x509.RSA, x509.SHA512WithRSA},
		{KeySpec{Algorithm: "ec", Curve: elliptic.P256()}, x509.ECDSA, x509.ECDSAWithSHA256},
		{KeySpec{Algorithm: "ec", Curve: elliptic.P384()}, x509.ECDSA, x509.ECDSAWithSHA384},
		{KeySpec{Algorithm: "ec", Curve: elliptic.P521()}, x509.ECDSA, x509.ECDSAWithSHA512},
		{KeySpec{Algorithm: "ed25519"}, x509.Ed25519, x509.PureEd25519},
	}
	for _, tc := range cases {
		key, err := GenerateKey(tc.spec)
		if err != nil {
			t.Fatal(err)
		}
		pub, sig, err := algoForKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if pub != tc.pubAlgo || sig != tc.sigAlgo {
			t.Errorf("%s: got (%v,%v) want (%v,%v)", tc.spec.Describe(), pub, sig, tc.pubAlgo, tc.sigAlgo)
		}
	}
}

// ---- End-to-end: issue -> self-sign -> Validate -> Secret -> parse ----------

func issueSpec(t *testing.T, spec KeySpec, ca bool) *X509 {
	t.Helper()
	usage := []string{"server_auth", "client_auth"}
	if ca {
		usage = append(usage, "key_cert_sign", "crl_sign")
	}
	cert, err := NewCertificate("CN=test.example.com", []string{"test.example.com"}, usage, "", spec)
	if err != nil {
		t.Fatalf("NewCertificate(%s): %v", spec.Describe(), err)
	}
	if ca {
		cert.MakeCA()
	}
	if err := cert.Sign(cert, 24*time.Hour); err != nil {
		t.Fatalf("Sign(%s): %v", spec.Describe(), err)
	}
	return cert
}

func TestRoundTripAllKeyTypes(t *testing.T) {
	specs := []KeySpec{
		{Algorithm: "rsa", Bits: 2048},
		{Algorithm: "ec", Curve: elliptic.P256()},
		{Algorithm: "ec", Curve: elliptic.P384()},
		{Algorithm: "ec", Curve: elliptic.P521()},
		{Algorithm: "ed25519"},
	}
	for _, spec := range specs {
		spec := spec
		t.Run(spec.Describe(), func(t *testing.T) {
			cert := issueSpec(t, spec, false)

			// Serialize to a Secret then parse it back. Validate() runs on
			// the parsed cert because Certificate.PublicKey is only populated
			// by parsing — Sign() sets only Certificate.Raw. This mirrors the
			// real CLI path (load from Vault, then validate).
			sec, err := cert.Secret(false)
			if err != nil {
				t.Fatalf("Secret: %v", err)
			}

			// RSA must remain PKCS#1; everything else PKCS#8.
			keyPEM := sec.Get("key")
			if spec.Algorithm == "rsa" {
				if !strings.Contains(keyPEM, "RSA PRIVATE KEY") {
					t.Errorf("rsa key PEM not PKCS#1: %q", firstLine(keyPEM))
				}
			} else {
				if !strings.Contains(keyPEM, "-----BEGIN PRIVATE KEY-----") {
					t.Errorf("%s key PEM not PKCS#8: %q", spec.Algorithm, firstLine(keyPEM))
				}
			}

			parsed, err := sec.X509(true)
			if err != nil {
				t.Fatalf("X509 parse back: %v", err)
			}
			if err := parsed.Validate(); err != nil {
				t.Fatalf("Validate after parse: %v", err)
			}

			// KeyDescription should name the right algorithm.
			desc := parsed.KeyDescription()
			switch spec.Algorithm {
			case "rsa":
				if !strings.HasPrefix(desc, "RSA") {
					t.Errorf("KeyDescription = %q, want RSA*", desc)
				}
			case "ec":
				if !strings.HasPrefix(desc, "ECDSA") {
					t.Errorf("KeyDescription = %q, want ECDSA*", desc)
				}
			case "ed25519":
				if desc != "Ed25519" {
					t.Errorf("KeyDescription = %q, want Ed25519", desc)
				}
			}
		})
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---- CA of each type signs a leaf, generates a CRL --------------------------

func TestCACrossTypeSignAndCRL(t *testing.T) {
	caSpecs := []KeySpec{
		{Algorithm: "rsa", Bits: 2048},
		{Algorithm: "ec", Curve: elliptic.P256()},
		{Algorithm: "ed25519"},
	}
	leafSpecs := []KeySpec{
		{Algorithm: "rsa", Bits: 2048},
		{Algorithm: "ec", Curve: elliptic.P384()},
		{Algorithm: "ed25519"},
	}

	for _, caSpec := range caSpecs {
		ca := issueSpec(t, caSpec, true)

		// CA Secret() exercises CreateRevocationList with this signer type.
		caSec, err := ca.Secret(false)
		if err != nil {
			t.Fatalf("CA(%s) Secret/CRL: %v", caSpec.Describe(), err)
		}
		if caSec.Get("crl") == "" {
			t.Errorf("CA(%s): no CRL emitted", caSpec.Describe())
		}
		// Parse the CA back, including its freshly-signed CRL.
		if _, err := caSec.X509(true); err != nil {
			t.Fatalf("CA(%s) parse with CRL: %v", caSpec.Describe(), err)
		}

		for _, leafSpec := range leafSpecs {
			leaf, err := NewCertificate("CN=leaf.example.com", []string{"leaf.example.com"},
				[]string{"server_auth"}, "", leafSpec)
			if err != nil {
				t.Fatalf("leaf NewCertificate(%s): %v", leafSpec.Describe(), err)
			}
			if err := ca.Sign(leaf, time.Hour); err != nil {
				t.Fatalf("CA(%s) sign leaf(%s): %v", caSpec.Describe(), leafSpec.Describe(), err)
			}
			// Round-trip the signed leaf and validate the parsed result, so
			// the cross-typed key/cert correspondence is checked on the real
			// (parsed) path.
			leafSec, err := leaf.Secret(false)
			if err != nil {
				t.Fatalf("leaf(%s) Secret: %v", leafSpec.Describe(), err)
			}
			parsedLeaf, err := leafSec.X509(true)
			if err != nil {
				t.Fatalf("leaf(%s) parse: %v", leafSpec.Describe(), err)
			}
			if err := parsedLeaf.Validate(); err != nil {
				t.Fatalf("leaf(%s) validate: %v", leafSpec.Describe(), err)
			}
			// The leaf must chain to the CA: its AuthorityKeyId equals the
			// CA's SubjectKeyId.
			caID, err := getKeyIDFromPublicKey(ca.PrivateKey.Public())
			if err != nil {
				t.Fatal(err)
			}
			if string(parsedLeaf.Certificate.AuthorityKeyId) != string(caID) {
				t.Errorf("CA(%s)/leaf(%s): AuthorityKeyId does not match CA SubjectKeyId",
					caSpec.Describe(), leafSpec.Describe())
			}
		}
	}
}

// ---- getKeyIDFromPublicKey for each type ------------------------------------

func TestGetKeyIDAllTypes(t *testing.T) {
	for _, spec := range []KeySpec{
		{Algorithm: "rsa", Bits: 2048},
		{Algorithm: "ec", Curve: elliptic.P256()},
		{Algorithm: "ed25519"},
	} {
		key, err := GenerateKey(spec)
		if err != nil {
			t.Fatal(err)
		}
		id, err := getKeyIDFromPublicKey(key.Public())
		if err != nil {
			t.Fatalf("%s: %v", spec.Describe(), err)
		}
		if len(id) != 20 { // SHA-1 digest length
			t.Errorf("%s: key id len = %d, want 20", spec.Describe(), len(id))
		}
	}
}

// ---- CheckStrength per type -------------------------------------------------

func TestCheckStrengthPerType(t *testing.T) {
	rsaCert := issueSpec(t, KeySpec{Algorithm: "rsa", Bits: 2048}, false)
	if err := rsaCert.CheckStrength(2048); err != nil {
		t.Errorf("rsa 2048 should pass: %v", err)
	}
	if err := rsaCert.CheckStrength(4096); err == nil {
		t.Error("rsa 2048 should fail a 4096 requirement")
	}

	ecCert := issueSpec(t, KeySpec{Algorithm: "ec", Curve: elliptic.P256()}, false)
	if err := ecCert.CheckStrength(256); err != nil {
		t.Errorf("ec p256 should pass a 256 requirement: %v", err)
	}
	if err := ecCert.CheckStrength(384); err == nil {
		t.Error("ec p256 should fail a 384 requirement")
	}

	edCert := issueSpec(t, KeySpec{Algorithm: "ed25519"}, false)
	if err := edCert.CheckStrength(256); err != nil {
		t.Errorf("ed25519 should pass a 256 requirement: %v", err)
	}

	// Empty requirement is always a no-op pass.
	if err := edCert.CheckStrength(); err != nil {
		t.Errorf("empty bits should pass: %v", err)
	}
}

// ---- Signature algorithm / key-type compatibility ---------------------------

func TestSigAlgoCompatibility(t *testing.T) {
	// An explicitly requested algorithm incompatible with the signing key is
	// rejected at Sign() time (the signer, not the subject key, governs the
	// signature algorithm). NewCertificate records the request without error.
	rsaCert, err := NewCertificate("CN=x", []string{"x"}, []string{"server_auth"},
		"ecdsa-sha256", KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate should record the request: %v", err)
	}
	if err := rsaCert.Sign(rsaCert, time.Hour); err == nil {
		t.Error("self-signing an RSA cert with ecdsa-sha256 should be rejected")
	}

	edCert, err := NewCertificate("CN=x", []string{"x"}, []string{"server_auth"},
		"sha256-rsa", KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("NewCertificate should record the request: %v", err)
	}
	if err := edCert.Sign(edCert, time.Hour); err == nil {
		t.Error("self-signing an Ed25519 cert with sha256-rsa should be rejected")
	}

	// A matching ECDSA algorithm for an ECDSA key signs cleanly.
	ecCert, err := NewCertificate("CN=x", []string{"x"}, []string{"server_auth"},
		"ecdsa-sha384", KeySpec{Algorithm: "ec", Curve: elliptic.P384()})
	if err != nil {
		t.Fatalf("ec key with ecdsa-sha384 should build: %v", err)
	}
	if err := ecCert.Sign(ecCert, time.Hour); err != nil {
		t.Errorf("ec key with ecdsa-sha384 should sign: %v", err)
	}

	// With no requested algorithm, Sign derives the CA-key default. An RSA CA
	// signing an ECDSA leaf must succeed (cross-family default reconciliation).
	caRSA := issueSpec(t, KeySpec{Algorithm: "rsa", Bits: 2048}, true)
	ecLeaf, err := NewCertificate("CN=leaf", []string{"leaf"}, []string{"server_auth"},
		"", KeySpec{Algorithm: "ec", Curve: elliptic.P256()})
	if err != nil {
		t.Fatal(err)
	}
	if err := caRSA.Sign(ecLeaf, time.Hour); err != nil {
		t.Errorf("RSA CA signing ECDSA leaf (default algo) should succeed: %v", err)
	}
	if ecLeaf.Certificate.SignatureAlgorithm != x509.SHA512WithRSA {
		t.Errorf("leaf sig algo = %v, want SHA512WithRSA (from RSA CA)", ecLeaf.Certificate.SignatureAlgorithm)
	}
}

// TestResolveKeySpecFlagMismatch verifies the destructive-command guard that
// rejects parameter flags not matching the resolved key algorithm.
func TestResolveKeySpecFlagMismatch(t *testing.T) {
	if _, err := ResolveKeySpec("ec", 2048, "", nil); err == nil {
		t.Error("--bits with --type ec should be rejected")
	}
	if _, err := ResolveKeySpec("rsa", 0, "p256", nil); err == nil {
		t.Error("--curve with --type rsa should be rejected")
	}
	if _, err := ResolveKeySpec("ed25519", 2048, "", nil); err == nil {
		t.Error("--bits with --type ed25519 should be rejected")
	}
	// Inferred type from an existing EC key + stray --bits must also error.
	ecKey, err := GenerateKey(KeySpec{Algorithm: "ec", Curve: elliptic.P256()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveKeySpec("", 2048, "", ecKey); err == nil {
		t.Error("--bits on an inferred EC reissue should be rejected")
	}
}

// stubSigner is a crypto.Signer of an unrecognized key family, used to drive
// the unsupported-key-type error branches.
type stubSigner struct{ pub crypto.PublicKey }

func (s stubSigner) Public() crypto.PublicKey                                { return s.pub }
func (stubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

// ---- validateSigAlgoForKey: every compatibility branch ----------------------

func TestValidateSigAlgoForKey(t *testing.T) {
	rsaKey, err := GenerateKey(KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := GenerateKey(KeySpec{Algorithm: "ec", Curve: elliptic.P256()})
	if err != nil {
		t.Fatal(err)
	}
	edKey, err := GenerateKey(KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		key     crypto.Signer
		algo    x509.SignatureAlgorithm
		wantErr bool
	}{
		{"rsa accepts sha256", rsaKey, x509.SHA256WithRSA, false},
		{"rsa accepts sha512", rsaKey, x509.SHA512WithRSA, false},
		{"rsa accepts pss", rsaKey, x509.SHA384WithRSAPSS, false},
		{"rsa rejects ecdsa", rsaKey, x509.ECDSAWithSHA256, true},
		{"rsa rejects ed25519", rsaKey, x509.PureEd25519, true},
		{"ec accepts sha256", ecKey, x509.ECDSAWithSHA256, false},
		{"ec accepts sha512", ecKey, x509.ECDSAWithSHA512, false},
		{"ec rejects rsa", ecKey, x509.SHA256WithRSA, true},
		{"ec rejects ed25519", ecKey, x509.PureEd25519, true},
		{"ed25519 accepts pure", edKey, x509.PureEd25519, false},
		{"ed25519 rejects rsa", edKey, x509.SHA256WithRSA, true},
		{"ed25519 rejects ecdsa", edKey, x509.ECDSAWithSHA256, true},
		// An unrecognized key family is permissive (no constraint to enforce).
		{"unknown key permissive", stubSigner{}, x509.SHA256WithRSA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSigAlgoForKey(tc.key, tc.algo)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

// ---- curveDisplayName / Describe fallbacks ----------------------------------

func TestCurveDisplayNameFallbacks(t *testing.T) {
	cases := []struct {
		curve elliptic.Curve
		want  string
	}{
		{elliptic.P256(), "P-256"},
		{elliptic.P384(), "P-384"},
		{elliptic.P521(), "P-521"},
		// A NIST curve outside the named set falls through to Params().Name.
		{elliptic.P224(), "P-224"},
		{nil, "unknown-curve"},
	}
	for _, tc := range cases {
		if got := curveDisplayName(tc.curve); got != tc.want {
			t.Errorf("curveDisplayName = %q, want %q", got, tc.want)
		}
	}
}

func TestKeySpecDescribeUnknown(t *testing.T) {
	if got := (KeySpec{Algorithm: "bogus"}).Describe(); got != "unknown key" {
		t.Errorf("Describe = %q, want %q", got, "unknown key")
	}
}

// ---- algoForKey: default ECDSA curve and unsupported type -------------------

func TestAlgoForKeyEdgeCases(t *testing.T) {
	// An ECDSA key on a curve outside the named set still resolves to a sane
	// default (ECDSAWithSHA256) rather than erroring.
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, sig, err := algoForKey(p224)
	if err != nil {
		t.Fatalf("p224: unexpected error: %v", err)
	}
	if pub != x509.ECDSA || sig != x509.ECDSAWithSHA256 {
		t.Errorf("p224: got (%v,%v), want (ECDSA, ECDSAWithSHA256)", pub, sig)
	}

	// An unrecognized signer type is a hard error.
	if _, _, err := algoForKey(stubSigner{}); err == nil {
		t.Error("algoForKey should reject an unrecognized signer type")
	}
}

// ---- Error paths: GenerateKey, marshalPrivateKeyPEM, getKeyID, CheckStrength,
//      Validate -------------------------------------------------------------

func TestGenerateKeyUnknownAlgorithm(t *testing.T) {
	if _, err := GenerateKey(KeySpec{Algorithm: "dsa"}); err == nil {
		t.Error("GenerateKey should reject an unknown algorithm")
	}
}

func TestMarshalPrivateKeyPEMError(t *testing.T) {
	// PKCS#8 marshaling rejects an unrecognized signer type.
	if _, err := marshalPrivateKeyPEM(stubSigner{}); err == nil {
		t.Error("marshalPrivateKeyPEM should fail on an unmarshalable signer")
	}
}

func TestGetKeyIDFromPublicKeyUnsupported(t *testing.T) {
	if _, err := getKeyIDFromPublicKey(42); err == nil {
		t.Error("getKeyIDFromPublicKey should reject an unsupported public key type")
	}
	// An ECDSA public key with no curve cannot be PKIX-marshaled, exercising
	// the marshal-failure branch.
	if _, err := getKeyIDFromPublicKey(&ecdsa.PublicKey{}); err == nil {
		t.Error("getKeyIDFromPublicKey should fail on an unmarshalable ECDSA key")
	}
}

func TestKeyDescriptionUnknown(t *testing.T) {
	x := X509{Certificate: &x509.Certificate{PublicKey: 42}}
	if got := x.KeyDescription(); got != "unknown" {
		t.Errorf("KeyDescription = %q, want %q", got, "unknown")
	}
}

func TestNewCertificateErrors(t *testing.T) {
	good := KeySpec{Algorithm: "rsa", Bits: 2048}
	cases := []struct {
		name    string
		subj    string
		usage   []string
		sigAlgo string
		spec    KeySpec
	}{
		{"bad subject", "no-equals-sign", []string{"server_auth"}, "", good},
		{"bad key usage", "CN=x", []string{"bogus_usage"}, "", good},
		{"bad sig algo", "CN=x", []string{"server_auth"}, "no-such-algo", good},
		{"bad key spec", "CN=x", []string{"server_auth"}, "", KeySpec{Algorithm: "dsa"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCertificate(tc.subj, []string{"x"}, tc.usage, tc.sigAlgo, tc.spec); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestSignUnsupportedCAKey(t *testing.T) {
	// A CA whose key is of an unrecognized family cannot yield a default
	// signature algorithm, so Sign() fails before issuing.
	ca := &X509{PrivateKey: stubSigner{}, Certificate: &x509.Certificate{}}
	leaf, err := NewCertificate("CN=leaf", []string{"leaf"}, []string{"server_auth"},
		"", KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Sign(leaf, time.Hour); err == nil {
		t.Error("Sign should fail when the CA key family is unsupported")
	}
}

func TestCheckStrengthUnsupportedType(t *testing.T) {
	x := X509{PrivateKey: stubSigner{}}
	if err := x.CheckStrength(256); err == nil {
		t.Error("CheckStrength should reject an unsupported private key type")
	}
}

func TestValidateErrorBranches(t *testing.T) {
	keyA, err := GenerateKey(KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := GenerateKey(KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatal(err)
	}

	// No private key at all.
	if err := (X509{Certificate: &x509.Certificate{PublicKey: keyA.Public()}}).Validate(); err == nil {
		t.Error("Validate should fail when there is no private key")
	}

	// Certificate public key does not match the private key.
	mismatch := X509{
		Certificate: &x509.Certificate{PublicKey: keyA.Public()},
		PrivateKey:  keyB,
	}
	if err := mismatch.Validate(); err == nil {
		t.Error("Validate should fail when the public and private keys differ")
	}

	// Certificate public key is of an unsupported (non-equatable) type.
	unsupported := X509{
		Certificate: &x509.Certificate{PublicKey: 42},
		PrivateKey:  keyA,
	}
	if err := unsupported.Validate(); err == nil {
		t.Error("Validate should fail on an unsupported certificate public key type")
	}
}
