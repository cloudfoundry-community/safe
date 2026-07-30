package vault

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - SHA1 used for certificate fingerprint calculation per RFC standard
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type X509 struct {
	Intermediaries []*x509.Certificate
	Certificate    *x509.Certificate
	PrivateKey     crypto.Signer
	Serial         *big.Int
	CRL            *x509.RevocationList

	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
}

// KeySpec describes the key algorithm and parameters to generate for a
// certificate. Exactly one of Bits (RSA) or Curve (ECDSA) is meaningful,
// depending on Algorithm. Ed25519 takes no parameters.
type KeySpec struct {
	Algorithm string         // "rsa", "ec", or "ed25519"
	Bits      int            // RSA modulus size (rsa only)
	Curve     elliptic.Curve // ECDSA curve (ec only)
}

// Describe returns a human-readable summary of the key spec, e.g.
// "4096-bit RSA", "ECDSA P-256", or "Ed25519".
func (k KeySpec) Describe() string {
	switch k.Algorithm {
	case "rsa":
		return fmt.Sprintf("%d-bit RSA", k.Bits)
	case "ec":
		return fmt.Sprintf("ECDSA %s", curveDisplayName(k.Curve))
	case "ed25519":
		return "Ed25519"
	}
	return "unknown key"
}

// curveDisplayName maps an elliptic curve to its canonical display name.
func curveDisplayName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	}
	if c != nil {
		return c.Params().Name
	}
	return "unknown-curve"
}

// parseCurve resolves a user-supplied curve name to an elliptic.Curve.
// Accepts p256/p-256/256 forms, case-insensitively.
func parseCurve(name string) (elliptic.Curve, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "-", "")
	n = strings.TrimPrefix(n, "p")
	switch n {
	case "256":
		return elliptic.P256(), nil
	case "384":
		return elliptic.P384(), nil
	case "521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("ECDSA curve must be p256, p384, or p521; got %q", name)
}

// ResolveKeySpec builds a KeySpec from CLI inputs. keyType is one of
// "rsa", "ec"/"ecdsa", or "ed25519" (empty defers to the existing key's
// type, or RSA when there is no existing key). bits and curve apply to RSA
// and ECDSA respectively; when omitted they fall back to the existing key's
// parameters (for reissue) or to defaults (rsa:4096, ec:p256).
func ResolveKeySpec(keyType string, bits int, curve string, existing crypto.Signer) (KeySpec, error) {
	algo := strings.ToLower(strings.TrimSpace(keyType))
	if algo == "ecdsa" {
		algo = "ec"
	}

	if algo == "" {
		switch existing.(type) {
		case *ecdsa.PrivateKey:
			algo = "ec"
		case ed25519.PrivateKey:
			algo = "ed25519"
		default:
			algo = "rsa"
		}
	}

	// Reject parameter flags that do not belong to the resolved algorithm, so a
	// destructive reissue cannot silently ignore a requested key strength or
	// curve (e.g. --bits on an EC certificate, or --curve on an RSA one).
	if bits != 0 && algo != "rsa" {
		return KeySpec{}, fmt.Errorf("--bits applies only to RSA keys, not %s keys", algo)
	}
	if curve != "" && algo != "ec" {
		return KeySpec{}, fmt.Errorf("--curve applies only to EC keys, not %s keys", algo)
	}

	switch algo {
	case "rsa":
		if bits == 0 {
			if k, ok := existing.(*rsa.PrivateKey); ok {
				bits = k.N.BitLen()
			} else {
				bits = 4096
			}
		}
		if bits != 1024 && bits != 2048 && bits != 4096 {
			return KeySpec{}, fmt.Errorf("RSA key strength must be one of 1024, 2048, or 4096; got %d", bits)
		}
		return KeySpec{Algorithm: "rsa", Bits: bits}, nil

	case "ec":
		var c elliptic.Curve
		if curve != "" {
			var err error
			if c, err = parseCurve(curve); err != nil {
				return KeySpec{}, err
			}
		} else if k, ok := existing.(*ecdsa.PrivateKey); ok {
			c = k.Curve
		} else {
			c = elliptic.P256()
		}
		return KeySpec{Algorithm: "ec", Curve: c}, nil

	case "ed25519":
		return KeySpec{Algorithm: "ed25519"}, nil
	}

	return KeySpec{}, fmt.Errorf("unrecognized key type %q; use rsa, ec, or ed25519", keyType)
}

// GenerateKey produces a new private key (as a crypto.Signer) per the spec.
func GenerateKey(spec KeySpec) (crypto.Signer, error) {
	switch spec.Algorithm {
	case "rsa":
		return rsa.GenerateKey(rand.Reader, spec.Bits)
	case "ec":
		return ecdsa.GenerateKey(spec.Curve, rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	}
	return nil, fmt.Errorf("unrecognized key algorithm %q", spec.Algorithm)
}

// algoForKey returns the x509 public key algorithm and a sane default
// signature algorithm for the given signer.
func algoForKey(key crypto.Signer) (x509.PublicKeyAlgorithm, x509.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return x509.RSA, x509.SHA512WithRSA, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return x509.ECDSA, x509.ECDSAWithSHA256, nil
		case elliptic.P384():
			return x509.ECDSA, x509.ECDSAWithSHA384, nil
		case elliptic.P521():
			return x509.ECDSA, x509.ECDSAWithSHA512, nil
		default:
			return x509.ECDSA, x509.ECDSAWithSHA256, nil
		}
	case ed25519.PrivateKey:
		return x509.Ed25519, x509.PureEd25519, nil
	}
	return x509.UnknownPublicKeyAlgorithm, x509.UnknownSignatureAlgorithm,
		fmt.Errorf("unsupported key type %T", key)
}

// validateSigAlgoForKey ensures a user-requested signature algorithm is
// compatible with the key's algorithm family.
func validateSigAlgoForKey(key crypto.Signer, algo x509.SignatureAlgorithm) error {
	switch key.(type) {
	case *rsa.PrivateKey:
		switch algo {
		case x509.MD5WithRSA, x509.SHA1WithRSA, x509.SHA256WithRSA,
			x509.SHA384WithRSA, x509.SHA512WithRSA,
			x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			return nil
		}
		return fmt.Errorf("signature algorithm %v is not compatible with an RSA key", algo)
	case *ecdsa.PrivateKey:
		switch algo {
		case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			return nil
		}
		return fmt.Errorf("signature algorithm %v is not compatible with an ECDSA key", algo)
	case ed25519.PrivateKey:
		if algo != x509.PureEd25519 {
			return fmt.Errorf("Ed25519 keys only support the ed25519 signature algorithm, not %v", algo)
		}
		return nil
	}
	return nil
}

// marshalPrivateKeyPEM serializes a private key to PEM. RSA keys use PKCS#1
// ("RSA PRIVATE KEY") to preserve byte-identical output with prior versions;
// all other key types use PKCS#8 ("PRIVATE KEY").
func marshalPrivateKeyPEM(signer crypto.Signer) (string, error) {
	if k, ok := signer.(*rsa.PrivateKey); ok {
		return string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		})), nil
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key as PKCS#8: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})), nil
}

// KeyDescription summarizes the certificate's public key algorithm and
// parameters for display, e.g. "RSA (4096 bit)", "ECDSA (P-256)", "Ed25519".
func (x X509) KeyDescription() string {
	switch pub := x.Certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA (%d bit)", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA (%s)", curveDisplayName(pub.Curve))
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "unknown"
}

func (s Secret) X509(requireKey bool) (*X509, error) {
	if !s.Has("certificate") {
		return nil, fmt.Errorf("not a valid certificate (missing the `certificate` attribute)")
	}
	if !s.Has("key") && requireKey {
		return nil, fmt.Errorf("not a valid certificate (missing the `key` attribute)")
	}

	b := []byte(s.Get("certificate"))
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("not a valid certificate (failed to decode certificate PEM block)")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("not a valid certificate (type '%s' != 'CERTIFICATE')", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a valid certificate (%w)", err)
	}

	var (
		n              int
		intermediaries []*x509.Certificate
	)

	for len(rest) > 0 {
		n++
		b = rest
		block, rest = pem.Decode(b)
		if block == nil {
			//There might be trailing whitespace or certificate annotations, so we
			//don't want to return an error here. Not erroring here could
			//accidentally let a typo slip through (like a missing dash in the PEM
			//header), but if that becomes an issue, we can do some heuristics to
			//warn on that.
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("intermediary #%d: not a valid certificate (type '%s' != 'CERTIFICATE')", n, block.Type)
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("intermediary #%d: not a valid certificate (%w)", n, err)
		}

		intermediaries = append(intermediaries, c)
	}

	var key crypto.Signer
	if requireKey {
		v := s.Get("key")
		block, rest = pem.Decode([]byte(v))
		if block == nil {
			return nil, fmt.Errorf("not a valid certificate (failed to decode key PEM block)")
		}
		if len(rest) > 0 {
			return nil, fmt.Errorf("contains multiple keys (what?)")
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			k, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("not a valid RSA private key (%w)", parseErr)
			}
			key = k

		case "PRIVATE KEY":
			raw, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("not a valid private key (%w)", parseErr)
			}
			signer, ok := raw.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("private key type %T does not support signing", raw)
			}
			key = signer

		case "EC PRIVATE KEY":
			k, parseErr := x509.ParseECPrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("not a valid EC private key (%w)", parseErr)
			}
			key = k

		default:
			return nil, fmt.Errorf("not a valid certificate (unrecognized key PEM type '%s')", block.Type)
		}
	}

	o := &X509{
		Intermediaries: intermediaries,
		Certificate:    cert,
		PrivateKey:     key,
		KeyUsage:       cert.KeyUsage,
		ExtKeyUsage:    cert.ExtKeyUsage,
	}

	if s.Has("serial") {
		v := s.Get("serial")
		i, err := strconv.ParseInt(v, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("not a valid CA certificate (serial '%s' is malformed)", v)
		}
		o.Serial = big.NewInt(i)
	}

	if s.Has("crl") {
		v := s.Get("crl")
		block, _ := pem.Decode([]byte(v))
		var crlDER []byte
		if block != nil {
			crlDER = block.Bytes
		} else {
			crlDER = []byte(v)
		}
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			return nil, fmt.Errorf("not a valid CA certificate (CRL parsing failed: %w)", err)
		}
		o.CRL = crl
	}

	return o, nil
}

func formatSubject(name pkix.Name) string {
	ss := []string{}
	if name.CommonName != "" {
		ss = append(ss, fmt.Sprintf("cn=%s", name.CommonName))
	}
	for _, s := range name.Country {
		ss = append(ss, fmt.Sprintf("c=%s", s))
	}
	for _, s := range name.Province {
		ss = append(ss, fmt.Sprintf("st=%s", s))
	}
	for _, s := range name.Locality {
		ss = append(ss, fmt.Sprintf("l=%s", s))
	}
	for _, s := range name.Organization {
		ss = append(ss, fmt.Sprintf("o=%s", s))
	}
	for _, s := range name.OrganizationalUnit {
		ss = append(ss, fmt.Sprintf("ou=%s", s))
	}

	return strings.Join(ss, ",")
}

func (x *X509) Subject() string {
	return formatSubject(x.Certificate.Subject)
}

func (x *X509) Issuer() string {
	return formatSubject(x.Certificate.Issuer)
}

func (x *X509) IntermediarySubject(n int) string {
	return formatSubject(x.Intermediaries[n].Subject)
}

func ParseSubject(subj string) (pkix.Name, error) {
	/* parse subject names that look like this:
	    /cn=foo.bl/c=us/st=ny/l=buffalo/o=stark & wayne/ou=r&d
	and  CN=foo.bl,C=us,ST=ny,L=buffalo,O=stark & wayne,OU=r&d
	*/

	var (
		pairs []string
		name  pkix.Name
	)

	if len(subj) == 0 {
		return name, fmt.Errorf("subject string cannot be empty")
	}

	if subj[0] == '/' {
		pairs = strings.Split(subj[1:], "/")
	} else {
		pairs = strings.Split(subj, ",")
	}

	kvre := regexp.MustCompile(" *= *")
	for _, pair := range pairs {
		kv := kvre.Split(pair, 2)
		if len(kv) != 2 {
			return name, fmt.Errorf("malformed subject component '%s'", pair)
		}
		switch kv[0] {
		case "CN", "cn":
			if name.CommonName != "" {
				return name, fmt.Errorf("multiple common names (CN) found in '%s'", subj)
			}
			name.CommonName = kv[1]
		case "C", "c":
			name.Country = append(name.Country, kv[1])
		case "ST", "st":
			name.Province = append(name.Province, kv[1])
		case "L", "l":
			name.Locality = append(name.Locality, kv[1])
		case "O", "o":
			name.Organization = append(name.Organization, kv[1])
		case "OU", "ou":
			name.OrganizationalUnit = append(name.OrganizationalUnit, kv[1])
		default:
			return name, fmt.Errorf("unrecognized subject component '%s=%s'", kv[0], kv[1])
		}
	}

	return name, nil
}

func CategorizeSANs(in []string) (ips []net.IP, domains, emails []string) {
	ips = make([]net.IP, 0)
	domains = make([]string, 0)
	emails = make([]string, 0)

	for _, s := range in {
		ip := net.ParseIP(s)
		if ip != nil {
			ips = append(ips, ip)
			continue
		}

		// Note: strings.Index(s, "@") > 0 (not strings.Contains) is intentional —
		// an "@" at position 0 (e.g. "@foo") has an empty local-part and is
		// treated as a domain, not an email. See TestCategorizeSANs.
		if strings.Index(s, "@") > 0 {
			emails = append(emails, s)
		} else {
			domains = append(domains, s)
		}
	}

	return
}

var keyUsageLookup = map[string]x509.KeyUsage{
	"digital_signature":  x509.KeyUsageDigitalSignature,
	"non_repudiation":    x509.KeyUsageContentCommitment,
	"content_commitment": x509.KeyUsageContentCommitment,
	"key_encipherment":   x509.KeyUsageKeyEncipherment,
	"data_encipherment":  x509.KeyUsageDataEncipherment,
	"key_agreement":      x509.KeyUsageKeyAgreement,
	"key_cert_sign":      x509.KeyUsageCertSign,
	"crl_sign":           x509.KeyUsageCRLSign,
	"encipher_only":      x509.KeyUsageEncipherOnly,
	"decipher_only":      x509.KeyUsageDecipherOnly,
}

var extendedKeyUsageLookup = map[string]x509.ExtKeyUsage{
	"client_auth":      x509.ExtKeyUsageClientAuth,
	"server_auth":      x509.ExtKeyUsageServerAuth,
	"code_signing":     x509.ExtKeyUsageCodeSigning,
	"email_protection": x509.ExtKeyUsageEmailProtection,
	"timestamping":     x509.ExtKeyUsageTimeStamping,
}

var signatureAlgorithmLookup = map[string]x509.SignatureAlgorithm{
	"md5":           x509.MD5WithRSA,
	"md5-rsa":       x509.MD5WithRSA,
	"sha1":          x509.SHA1WithRSA,
	"sha1-rsa":      x509.SHA1WithRSA,
	"sha256":        x509.SHA256WithRSA,
	"sha256-rsa":    x509.SHA256WithRSA,
	"sha384":        x509.SHA384WithRSA,
	"sha384-rsa":    x509.SHA384WithRSA,
	"sha512":        x509.SHA512WithRSA,
	"sha512-rsa":    x509.SHA512WithRSA,
	"sha256-rsapss": x509.SHA256WithRSAPSS,
	"sha384-rsapss": x509.SHA384WithRSAPSS,
	"sha512-rsapss": x509.SHA512WithRSAPSS,
	"dsa-sha1":      x509.DSAWithSHA1,
	"dsa-sha256":    x509.DSAWithSHA256,
	"ecdsa-sha1":    x509.ECDSAWithSHA1,
	"ecdsa-sha256":  x509.ECDSAWithSHA256,
	"ecdsa-sha384":  x509.ECDSAWithSHA384,
	"ecdsa-sha512":  x509.ECDSAWithSHA512,
	"ed25519":       x509.PureEd25519,
	"pure-ed25519":  x509.PureEd25519,
}

func isNoKeyUsage(in string) bool {
	return in == "none" || in == "no"
}

func HandleJointKeyUsages(usages []string) (ku x509.KeyUsage, eku []x509.ExtKeyUsage, err error) {
	for i := range usages {
		usages[i] = strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ToLower(usages[i]), "-", "_",
			), " ", "_",
		)
	}

	sort.Strings(usages)
	uniqUsages := []string{}
	if len(usages) > 0 {
		uniqUsages = append(uniqUsages, usages[0])
	}

	var hasNoKeyUsage bool
	for i := 1; i < len(usages); i++ {
		if usages[i] != usages[i-1] {
			uniqUsages = append(uniqUsages, usages[i])
		}
	}

	usages = uniqUsages
	for _, usage := range usages {
		if isNoKeyUsage(usage) {
			hasNoKeyUsage = true
		}
	}
	if hasNoKeyUsage {
		if len(usages) > 1 {
			err = fmt.Errorf("cannot specify not to have key usages and also to use specific key usages")
		}

		return
	}

	keyUsageStrs, rest := keyUsages(usages)
	extKeyUsageStrs, rest := extendedKeyUsages(rest)
	if len(rest) > 0 {
		err = fmt.Errorf("unknown key usage string(s): `%s'", strings.Join(rest, "', `"))
		return
	}

	ku, err = translateKeyUsage(keyUsageStrs)
	if err != nil {
		return
	}

	eku, err = translateExtendedKeyUsage(extKeyUsageStrs)
	return
}

func keyUsages(usages []string) (keyUsages []string, rest []string) {
	for _, usage := range usages {
		if _, found := keyUsageLookup[strings.ToLower(usage)]; !found {
			rest = append(rest, usage)
		} else {
			keyUsages = append(keyUsages, usage)
		}
	}

	return
}

func extendedKeyUsages(usages []string) (extKeyUsages []string, rest []string) {
	for _, usage := range usages {
		if _, found := extendedKeyUsageLookup[strings.ToLower(usage)]; !found {
			rest = append(rest, usage)
		} else {
			extKeyUsages = append(extKeyUsages, usage)
		}
	}

	return
}

func translateKeyUsage(input []string) (keyUsage x509.KeyUsage, err error) {
	for _, usage := range input {
		var thisKeyUsage x509.KeyUsage
		var found bool
		if thisKeyUsage, found = keyUsageLookup[usage]; !found {
			err = fmt.Errorf("`%s' is not a valid key usage", usage)
			return
		}

		keyUsage = keyUsage | thisKeyUsage
	}

	return
}

func translateExtendedKeyUsage(input []string) (extendedKeyUsage []x509.ExtKeyUsage, err error) {
	for _, extUsage := range input {
		var thisExtKeyUsage x509.ExtKeyUsage
		var found bool
		if thisExtKeyUsage, found = extendedKeyUsageLookup[extUsage]; !found {
			err = fmt.Errorf("`%s' is not a valid extended key usage", extUsage)
			return
		}
		extendedKeyUsage = append(extendedKeyUsage, thisExtKeyUsage)
	}
	return
}

func TranslateSignatureAlgorithm(signatureAlgorithm string) (sigAlgo x509.SignatureAlgorithm, err error) {
	var found bool
	sigAlgo, found = signatureAlgorithmLookup[signatureAlgorithm]
	if !found {
		err = fmt.Errorf("%s is not a supported signature algorithm", signatureAlgorithm)
	}

	return
}

func NewCertificate(subj string, names, keyUsage []string, signatureAlgorithm string, spec KeySpec) (*X509, error) {
	name, err := ParseSubject(subj)
	if err != nil {
		return nil, err
	}

	ips, domains, emails := CategorizeSANs(names)

	key, err := GenerateKey(spec)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	ku, eku, err := HandleJointKeyUsages(keyUsage)
	if err != nil {
		return nil, err
	}

	pubKeyAlgo, _, err := algoForKey(key)
	if err != nil {
		return nil, err
	}

	// Leave SignatureAlgorithm unset when the user did not request one: Sign()
	// derives the correct algorithm from the signing CA key, which differs from
	// the subject key for CA-signed certs (e.g. an RSA CA signing an ECDSA
	// leaf). A user-supplied algorithm is recorded as-is and validated against
	// the actual signer in Sign(), not the subject key.
	var translatedSigAlgo x509.SignatureAlgorithm
	if signatureAlgorithm != "" {
		translatedSigAlgo, err = TranslateSignatureAlgorithm(signatureAlgorithm)
		if err != nil {
			return nil, err
		}
	}

	return &X509{
		PrivateKey: key,
		Certificate: &x509.Certificate{
			SignatureAlgorithm: translatedSigAlgo,
			PublicKeyAlgorithm: pubKeyAlgo,
			Subject:            name,
			DNSNames:           domains,
			EmailAddresses:     emails,
			IPAddresses:        ips,
			KeyUsage:           ku,
			ExtKeyUsage:        eku,
			/* ExtraExtensions */
		},
	}, nil
}

func (x X509) Validate() error {
	if x.PrivateKey == nil {
		return fmt.Errorf("no private key to validate against the certificate")
	}

	// Every standard public key type (*rsa.PublicKey, *ecdsa.PublicKey,
	// ed25519.PublicKey) implements Equal, which compares both the key type
	// and its value. This avoids reaching into deprecated raw coordinates.
	type equatableKey interface {
		Equal(crypto.PublicKey) bool
	}

	certPub, ok := x.Certificate.PublicKey.(equatableKey)
	if !ok {
		return fmt.Errorf("unsupported public key algorithm in certificate: %T", x.Certificate.PublicKey)
	}

	if !certPub.Equal(x.PrivateKey.Public()) {
		return fmt.Errorf("private key does not match the certificate's public key")
	}

	return nil
}

func (x X509) CheckStrength(bits ...int) error {
	if len(bits) == 0 {
		return nil
	}

	var effectiveBits int
	switch k := x.PrivateKey.(type) {
	case *rsa.PrivateKey:
		effectiveBits = k.N.BitLen()
	case *ecdsa.PrivateKey:
		effectiveBits = k.Curve.Params().BitSize
	case ed25519.PrivateKey:
		effectiveBits = 256
	default:
		return fmt.Errorf("unsupported private key type %T for strength check", x.PrivateKey)
	}

	for _, b := range bits {
		if effectiveBits == b {
			return nil
		}
	}
	return fmt.Errorf("key is %d bits (acceptable: %v)", effectiveBits, bits)
}

func (x X509) IsCA() bool {
	return x.Certificate.IsCA && x.Certificate.BasicConstraintsValid
}

func (x X509) Expired() bool {
	now := time.Now()
	return now.After(x.Certificate.NotAfter) || now.Before(x.Certificate.NotBefore)
}

func (x X509) ValidForIP(ip net.IP) bool {
	for _, valid := range x.Certificate.IPAddresses {
		if valid.Equal(ip) {
			return true
		}
	}
	return false
}

func (x X509) ValidForDomain(domain string) bool {
	for _, valid := range x.Certificate.DNSNames {
		if strings.HasPrefix(valid, "*.") {
			a := strings.Split(valid, ".")
			b := strings.Split(domain, ".")
			for len(a) > 0 && len(b) > 0 && a[0] == "*" {
				a = a[1:]
				b = b[1:]
			}
			if len(a) == 0 || len(b) == 0 || a[0] == "*" {
				return false
			}

			if strings.Join(a, ".") == strings.Join(b, ".") {
				return true
			}
		} else {
			if valid == domain {
				return true
			}
		}
	}
	return false
}

func (x X509) ValidForEmail(email string) bool {
	for _, valid := range x.Certificate.EmailAddresses {
		if valid == email {
			return true
		}
	}
	return false
}

func (x X509) ValidFor(names ...string) (bool, error) {
	ips, domains, emails := CategorizeSANs(names)

	for _, ip := range ips {
		if !x.ValidForIP(ip) {
			return false, fmt.Errorf("certificate is not valid for IP '%s'", ip)
		}
	}

	for _, domain := range domains {
		if !x.ValidForDomain(domain) {
			return false, fmt.Errorf("certificate is not valid for DNS domain '%s'", domain)
		}
	}

	for _, email := range emails {
		if !x.ValidForEmail(email) {
			return false, fmt.Errorf("certificate is not valid for email address '%s'", email)
		}
	}

	return true, nil
}

func (x *X509) MakeCA() {
	x.Certificate.BasicConstraintsValid = true
	x.Certificate.IsCA = true
	x.Certificate.MaxPathLen = 1
	x.Serial = big.NewInt(1)
	x.CRL = &x509.RevocationList{
		RevokedCertificateEntries: make([]x509.RevocationListEntry, 0),
		Number:                    big.NewInt(1),
	}
}

func (x X509) Secret(skipIfExists bool) (*Secret, error) {
	s := NewSecret()

	cert := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x.Certificate.Raw,
	}))
	key, err := marshalPrivateKeyPEM(x.PrivateKey)
	if err != nil {
		return s, err
	}

	err = s.Set("certificate", cert, skipIfExists)
	if err != nil {
		return s, err
	}
	err = s.Set("key", key, skipIfExists)
	if err != nil {
		return s, err
	}
	err = s.Set("combined", cert+key, skipIfExists)
	if err != nil {
		return s, err
	}

	if x.IsCA() {
		if x.Serial == nil {
			x.Serial = big.NewInt(1)
		}

		err = s.Set("serial", x.Serial.Text(16), skipIfExists)
		if err != nil {
			return s, err
		}

		if x.CRL == nil {
			x.CRL = &x509.RevocationList{
				RevokedCertificateEntries: make([]x509.RevocationListEntry, 0),
				Number:                    big.NewInt(1),
			}
		}
		if x.CRL.RevokedCertificateEntries == nil {
			x.CRL.RevokedCertificateEntries = make([]x509.RevocationListEntry, 0)
		}
		// Ensure issuer has SubjectKeyId populated, required by CreateRevocationList.
		if len(x.Certificate.SubjectKeyId) == 0 {
			if kid, kidErr := getKeyIDFromPublicKey(x.PrivateKey.Public()); kidErr == nil {
				x.Certificate.SubjectKeyId = kid
			}
		}
		now := time.Now()
		template := &x509.RevocationList{
			RevokedCertificateEntries: x.CRL.RevokedCertificateEntries,
			Number:                    x.CRL.Number,
			ThisUpdate:                now,
			NextUpdate:                now.Add(10 * 365 * 24 * time.Hour),
		}
		if template.Number == nil {
			template.Number = big.NewInt(1)
		}
		b, err := x509.CreateRevocationList(rand.Reader, template, x.Certificate, x.PrivateKey)
		if err != nil {
			return s, err
		}
		err = s.Set("crl", string(pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: b,
		})), skipIfExists)
		if err != nil {
			return s, err
		}
	}

	return s, nil
}

func (ca *X509) SaveTo(v *Vault, path string, skipIfExists bool) error {
	s, err := ca.Secret(skipIfExists)
	if err != nil {
		return err
	}
	return v.Write(path, s)
}

var maxSerial = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(159), nil)

func (ca *X509) Sign(x *X509, ttl time.Duration) error {
	if ca.Serial == nil || ca == x {
		serial, err := rand.Int(rand.Reader, maxSerial)
		if err != nil {
			return err
		}
		x.Certificate.SerialNumber = serial
	} else {
		x.Certificate.SerialNumber = ca.Serial
		ca.Serial.Add(ca.Serial, big.NewInt(1))
		ca.Serial.Mod(ca.Serial, maxSerial)
	}

	x.Certificate.NotBefore = time.Now()
	x.Certificate.NotAfter = time.Now().Add(ttl)

	// A certificate's SignatureAlgorithm describes how its issuer (the CA)
	// signs it, so it must be compatible with the CA's key — not the subject
	// key. When unset, derive the CA key's default (covers the common case and
	// cross-family signing, e.g. an RSA CA signing an ECDSA leaf). When the
	// user explicitly requested an algorithm the CA key cannot produce, fail
	// loudly rather than silently substituting a different one.
	if x.Certificate.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		_, defaultSigAlgo, err := algoForKey(ca.PrivateKey)
		if err != nil {
			return err
		}
		x.Certificate.SignatureAlgorithm = defaultSigAlgo
	} else if err := validateSigAlgoForKey(ca.PrivateKey, x.Certificate.SignatureAlgorithm); err != nil {
		return fmt.Errorf("requested signature algorithm is not compatible with the signing CA key: %w", err)
	}

	x.Certificate.AuthorityKeyId = ca.getKeyID()
	x.Certificate.SubjectKeyId, _ = getKeyIDFromPublicKey(x.PrivateKey.Public())
	raw, err := x509.CreateCertificate(rand.Reader, x.Certificate, ca.Certificate, x.PrivateKey.Public(), ca.PrivateKey)
	if err != nil {
		return err
	}
	x.Certificate.Raw = raw
	return nil
}

func (cert *X509) getKeyID() []byte {
	if len(cert.Certificate.SubjectKeyId) > 0 {
		return cert.Certificate.SubjectKeyId
	}

	if cert.Certificate.PublicKey != nil {
		ret, err := getKeyIDFromPublicKey(cert.Certificate.PublicKey)
		if err == nil {
			return ret
		}
	}
	return nil
}

func getKeyIDFromPublicKey(key any) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		// Preserved for backward compatibility: SHA1 over the PKCS#1 DER.
		// Existing RSA certs in Vault depend on this SubjectKeyId derivation.
		kASN1 := x509.MarshalPKCS1PublicKey(k)
		sum := sha1.Sum(kASN1) // #nosec G401 - SHA1 used for certificate fingerprint calculation per RFC standard
		return sum[:], nil

	case *ecdsa.PublicKey, ed25519.PublicKey:
		// RFC 5280 method 1: SHA1 over the SubjectPublicKeyInfo DER.
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key for key id: %w", err)
		}
		sum := sha1.Sum(der) // #nosec G401 - SHA1 used for certificate fingerprint calculation per RFC standard
		return sum[:], nil

	default:
		return nil, fmt.Errorf("unsupported public key algorithm")
	}
}

func (ca *X509) Revoke(cert *X509) {
	if ca.HasRevoked(cert) {
		return
	}

	//A CA read back out of the Vault carries no revocation list unless one
	// was stored alongside it. Secret() writes a fresh list in that case, so
	// starting one here keeps the first revocation from being dropped.
	if ca.CRL == nil {
		ca.CRL = &x509.RevocationList{
			RevokedCertificateEntries: make([]x509.RevocationListEntry, 0),
			Number:                    big.NewInt(1),
		}
	}

	ca.CRL.RevokedCertificateEntries = append(ca.CRL.RevokedCertificateEntries, x509.RevocationListEntry{
		SerialNumber:   cert.Certificate.SerialNumber,
		RevocationTime: time.Now(),
	})
}

func (ca *X509) HasRevoked(cert *X509) bool {
	//A certificate with no revocation list has revoked nothing. The list is
	// absent from anything that is not a CA, and reading a secret as a
	// certificate does not require one, so this is reachable with any path
	// the caller names as a signing authority.
	if ca.CRL == nil {
		return false
	}

	for _, rvk := range ca.CRL.RevokedCertificateEntries {
		if rvk.SerialNumber.Cmp(cert.Certificate.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func (c *X509) FormatSerial() string {
	serial := big.NewInt(0).Set(c.Certificate.SerialNumber)
	serialHex := []byte(fmt.Sprintf("%040x", serial))
	colonByte := []byte(":")[0]
	ret := []byte{}
	for i := range 40 / 2 {
		ret = append(ret, serialHex[i*2], serialHex[(i*2)+1], colonByte)
	}
	//cutoff last colon
	return string(ret[:59])
}

func (c *X509) ExpiryString() string {
	return c.Certificate.NotAfter.Format("Jan 02 2006 15:04 MST")
}
