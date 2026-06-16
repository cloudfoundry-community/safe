package cli

import (
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"os"
	"time"

	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func (c *CLI) cmdX509(command string, args ...string) error {
	r := c.r

	r.Help(os.Stdout, "x509")
	return nil
}

func (c *CLI) cmdX509Validate(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if len(args) < 1 {
		return r.Usage("x509 validate")
	}
	if opt.X509.Validate.SignedBy == "" && opt.X509.Validate.Revoked {
		return r.Usage("x509 validate")
	}
	if opt.X509.Validate.SignedBy == "" && opt.X509.Validate.NotRevoked {
		return r.Usage("x509 validate")
	}

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	v := connect(true)

	var ca *vault.X509
	if opt.X509.Validate.SignedBy != "" {
		s, err := v.Read(opt.X509.Validate.SignedBy)
		if err != nil {
			return err
		}
		ca, err = s.X509(true)
		if err != nil {
			return err
		}
	}

	for _, path := range args {
		s, err := v.Read(path)
		if err != nil {
			return err
		}
		cert, err := s.X509(true)
		if err != nil {
			return err
		}

		if err = cert.Validate(); err != nil {
			return fmt.Errorf("%s failed validation: %s", path, err)
		}

		if opt.X509.Validate.Bits != nil {
			if err = cert.CheckStrength(opt.X509.Validate.Bits...); err != nil {
				return fmt.Errorf("%s failed strength requirement: %s", path, err)
			}
		}

		if opt.X509.Validate.CA && !cert.IsCA() {
			return fmt.Errorf("%s is not a certificate authority", path)
		}

		if opt.X509.Validate.Revoked && !ca.HasRevoked(cert) {
			return fmt.Errorf("%s has not been revoked by %s", path, opt.X509.Validate.SignedBy)
		}
		if opt.X509.Validate.NotRevoked && ca.HasRevoked(cert) {
			return fmt.Errorf("%s has been revoked by %s", path, opt.X509.Validate.SignedBy)
		}

		if opt.X509.Validate.Expired && !cert.Expired() {
			return fmt.Errorf("%s has not yet expired", path)
		}
		if opt.X509.Validate.NotExpired && cert.Expired() {
			return fmt.Errorf("%s has expired", path)
		}

		if _, err = cert.ValidFor(opt.X509.Validate.Name...); err != nil {
			return err
		}

		if cert.IsCA() {
			if cert.Serial == nil {
				return fmt.Errorf("%s is missing its serial number tracker", path)
			}
			if cert.CRL == nil {
				return fmt.Errorf("%s is missing its certificate revocation list", path)
			}
		}

		if ca != nil { //If --signed-by was specified...
			err = cert.Certificate.CheckSignatureFrom(ca.Certificate)

			if err != nil {
				return fmt.Errorf("%s was not signed by %s", path, opt.X509.Validate.SignedBy)
			}
		}

		fmt.Printf("@G{%s} checks out.\n", path)
	}

	return nil
}

func (c *CLI) cmdX509Issue(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	var ca *vault.X509

	if len(args) != 1 || len(opt.X509.Issue.Name) == 0 {
		return r.Usage("x509 issue")
	}

	if opt.X509.Issue.Subject == "" {
		opt.X509.Issue.Subject = fmt.Sprintf("CN=%s", opt.X509.Issue.Name[0])
	}

	v := connect(true)
	if opt.SkipIfExists {
		if _, err := v.Read(args[0]); err == nil {
			if !opt.Quiet {
				fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to create a new certificate in} @C{%s} @R{as it is already present in Vault}\n", args[0])
			}
			return nil
		} else if err != nil && !vault.IsNotFound(err) {
			return err
		}
	}

	if opt.X509.Issue.SignedBy != "" {
		secret, err := v.Read(opt.X509.Issue.SignedBy)
		if err != nil {
			return err
		}

		ca, err = secret.X509(true)
		if err != nil {
			return err
		}
	}

	if len(opt.X509.Issue.KeyUsage) == 0 {
		opt.X509.Issue.KeyUsage = append(opt.X509.Issue.KeyUsage, "server_auth", "client_auth")
		if opt.X509.Issue.CA {
			opt.X509.Issue.KeyUsage = append(opt.X509.Issue.KeyUsage, "key_cert_sign", "crl_sign")
		}
	}

	spec, err := vault.ResolveKeySpec(opt.X509.Issue.Type, opt.X509.Issue.Bits, opt.X509.Issue.Curve, nil)
	if err != nil {
		return err
	}

	cert, err := vault.NewCertificate(opt.X509.Issue.Subject,
		uniq(opt.X509.Issue.Name), opt.X509.Issue.KeyUsage,
		opt.X509.Issue.SigAlgorithm, spec)
	if err != nil {
		return err
	}

	if opt.X509.Issue.CA {
		cert.MakeCA()
	}

	if opt.X509.Issue.TTL == "" {
		opt.X509.Issue.TTL = "2y"
		if opt.X509.Issue.CA {
			opt.X509.Issue.TTL = "10y"
		}
	}
	ttl, err := duration(opt.X509.Issue.TTL)
	if err != nil {
		return err
	}
	if ca == nil {
		if err := cert.Sign(cert, ttl); err != nil {
			return err
		}
	} else {
		if err := ca.Sign(cert, ttl); err != nil {
			return err
		}

		err = ca.SaveTo(v, opt.X509.Issue.SignedBy, opt.SkipIfExists)
		if err != nil {
			return err
		}
	}

	err = cert.SaveTo(v, args[0], opt.SkipIfExists)
	if err != nil {
		return err
	}

	return nil
}

func (c *CLI) cmdX509Reissue(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) != 1 {
		return r.Usage("x509 reissue")
	}
	if opt.SkipIfExists {
		fmt.Fprintf(os.Stderr, "@R{!!} @C{--no-clobber} @R{is incompatible with} @C{safe x509 reissue}\n")
		return r.Usage("x509 reissue")
	}

	v := connect(true)

	/* find the Certificate that we want to renew */
	s, err := v.Read(args[0])
	if err != nil {
		return err
	}
	cert, err := s.X509(true)
	if err != nil {
		return err
	}

	if len(opt.X509.Reissue.Name) > 0 {
		ips, dns, email := vault.CategorizeSANs(uniq(opt.X509.Renew.Name))
		cert.Certificate.IPAddresses = ips
		cert.Certificate.DNSNames = dns
		cert.Certificate.EmailAddresses = email
	}

	if opt.X509.Reissue.Subject != "" {
		cert.Certificate.Subject, err = vault.ParseSubject(opt.X509.Reissue.Subject)
		if err != nil {
			return err
		}

		cert.Certificate.RawSubject, err = asn1.Marshal(cert.Certificate.Subject.ToRDNSequence())
		if err != nil {
			return err
		}
	}

	if len(opt.X509.Reissue.KeyUsage) > 0 {
		keyUsage, extKeyUsage, err := vault.HandleJointKeyUsages(opt.X509.Reissue.KeyUsage)
		if err != nil {
			return err
		}

		cert.Certificate.KeyUsage = keyUsage
		cert.Certificate.ExtKeyUsage = extKeyUsage
	}

	if opt.X509.Reissue.SigAlgorithm != "" {
		sigAlgo, err := vault.TranslateSignatureAlgorithm(opt.X509.Reissue.SigAlgorithm)
		if err != nil {
			return err
		}

		cert.Certificate.SignatureAlgorithm = sigAlgo
	} else {
		// Re-derive the signature algorithm from the regenerated key and
		// signing CA at signing time, rather than preserving the previous
		// certificate's value, which may not match the new key.
		cert.Certificate.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	}

	/* find the CA */
	ca, caPath, err := v.FindSigningCA(cert, args[0], opt.X509.Reissue.SignedBy)
	if err != nil {
		return err
	}

	// Get new expiry date
	var ttl time.Duration
	if opt.X509.Reissue.TTL == "" {
		ttl = cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
	} else {
		ttl, err = duration(opt.X509.Reissue.TTL)
		if err != nil {
			return err
		}
	}

	// Determine the spec for the regenerated key. With no overriding
	// flags this preserves the existing certificate's key type and
	// parameters; --type/--bits/--curve override it.
	spec, err := vault.ResolveKeySpec(opt.X509.Reissue.Type, opt.X509.Reissue.Bits, opt.X509.Reissue.Curve, cert.PrivateKey)
	if err != nil {
		return err
	}

	// Generate new key per the resolved spec.
	fmt.Printf("\nGenerating new %s key...\n", spec.Describe())
	newKey, err := vault.GenerateKey(spec)
	if err != nil {
		return err
	}
	cert.PrivateKey = newKey
	err = ca.Sign(cert, ttl)
	if err != nil {
		return err
	}
	if caPath != args[0] {
		err = ca.SaveTo(v, caPath, false)
		if err != nil {
			return err
		}
	}

	err = cert.SaveTo(v, args[0], false)
	if err != nil {
		return err
	}

	fmt.Printf("Reissued x509 certificate at %s - expiry set to %s\n\n", args[0], cert.ExpiryString())

	return nil
}

func (c *CLI) cmdX509Renew(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) != 1 {
		return r.Usage("x509 renew")
	}
	if opt.SkipIfExists {
		fmt.Fprintf(os.Stderr, "@R{!!} @C{--no-clobber} @R{is incompatible with} @C{safe x509 renew}\n")
		return r.Usage("x509 renew")
	}

	v := connect(true)

	/* find the Certificate that we want to renew */
	s, err := v.Read(args[0])
	if err != nil {
		return err
	}
	cert, err := s.X509(true)
	if err != nil {
		return err
	}

	if len(opt.X509.Renew.Name) > 0 {
		ips, dns, email := vault.CategorizeSANs(uniq(opt.X509.Renew.Name))
		cert.Certificate.IPAddresses = ips
		cert.Certificate.DNSNames = dns
		cert.Certificate.EmailAddresses = email
	}

	if opt.X509.Renew.Subject != "" {
		cert.Certificate.Subject, err = vault.ParseSubject(opt.X509.Renew.Subject)
		if err != nil {
			return err
		}

		cert.Certificate.RawSubject, err = asn1.Marshal(cert.Certificate.Subject.ToRDNSequence())
		if err != nil {
			return err
		}
	}

	if len(opt.X509.Renew.KeyUsage) > 0 {
		keyUsage, extKeyUsage, err := vault.HandleJointKeyUsages(opt.X509.Renew.KeyUsage)
		if err != nil {
			return err
		}

		cert.Certificate.KeyUsage = keyUsage
		cert.Certificate.ExtKeyUsage = extKeyUsage
	}

	if opt.X509.Renew.SigAlgorithm != "" {
		sigAlgo, err := vault.TranslateSignatureAlgorithm(opt.X509.Renew.SigAlgorithm)
		if err != nil {
			return err
		}

		cert.Certificate.SignatureAlgorithm = sigAlgo
	}

	/* find the CA */
	ca, caPath, err := v.FindSigningCA(cert, args[0], opt.X509.Renew.SignedBy)
	if err != nil {
		return err
	}

	// Get new expiry date
	var ttl time.Duration
	if opt.X509.Renew.TTL == "" {
		ttl = cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
	} else {
		ttl, err = duration(opt.X509.Renew.TTL)
		if err != nil {
			return err
		}
	}

	err = ca.Sign(cert, ttl)
	if err != nil {
		return err
	}
	if caPath != args[0] {
		err = ca.SaveTo(v, caPath, false)
		if err != nil {
			return err
		}
	}

	err = cert.SaveTo(v, args[0], false)
	if err != nil {
		return err
	}

	fmt.Printf("\nRenewed x509 certificate at %s - expiry set to %s\n\n", args[0], cert.ExpiryString())
	return nil
}

func (c *CLI) cmdX509Revoke(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if opt.X509.Revoke.SignedBy == "" || len(args) != 1 {
		return r.Usage("x509 revoke")
	}

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	v := connect(true)

	/* find the CA */
	s, err := v.Read(opt.X509.Revoke.SignedBy)
	if err != nil {
		return err
	}
	ca, err := s.X509(true)
	if err != nil {
		return err
	}

	/* find the Certificate */
	s, err = v.Read(args[0])
	if err != nil {
		return err
	}
	cert, err := s.X509(true)
	if err != nil {
		return err
	}

	/* revoke the Certificate */
	/* FIXME make sure the CA signed this cert */
	ca.Revoke(cert)
	s, err = ca.Secret(false) // SkipIfExists doesnt make sense in the context of revoke
	if err != nil {
		return err
	}

	err = v.Write(opt.X509.Revoke.SignedBy, s)
	if err != nil {
		return err
	}

	return nil
}

func (c *CLI) cmdX509Show(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if len(args) == 0 {
		return r.Usage("x509 show")
	}

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	v := connect(true)

	for _, path := range args {
		s, err := v.Read(args[0])
		if err != nil {
			return err
		}

		fmt.Printf("%s:\n", path)
		cert, err := s.X509(false)
		if err != nil {
			fmt.Printf("  !! %s\n\n", err)
			continue
		}

		printX509(os.Stdout, cert)
	}

	return nil
}

// printX509 renders the human-readable detail block for a single
// certificate to w. Output is identical to the original inline
// rendering in cmdX509Show (go-ansi Printf is Fprintf to os.Stdout).
func printX509(w io.Writer, cert *vault.X509) {
	fmt.Fprintf(w, "  @G{%s}\n\n", cert.Subject())
	if cert.Subject() != cert.Issuer() {
		fmt.Fprintf(w, "  issued by: @C{%s}\n", cert.Issuer())
		for i := range cert.Intermediaries {
			fmt.Fprintf(w, "        via: @C{%s}\n", cert.IntermediarySubject(i))
		}
	} else {
		fmt.Fprintf(w, "  @C{self-signed}\n")
	}

	toStart := time.Until(cert.Certificate.NotBefore)
	toEnd := time.Until(cert.Certificate.NotAfter)

	days := int(toStart.Hours() / 24)
	if days == 1 {
		fmt.Fprintf(w, "  @Y{not valid for another day}\n")
	} else if days > 1 {
		fmt.Fprintf(w, "  @Y{not valid for another %d days}\n", days)
	}

	days = int(toEnd.Hours() / 24)
	if days < -1 {
		fmt.Fprintf(w, "  @R{EXPIRED %d days ago}\n", -1*days)
	} else if days < 0 {
		fmt.Fprintf(w, "  @R{EXPIRED a day ago}\n")
	} else if days < 1 {
		fmt.Fprintf(w, "  @R{EXPIRED}\n")
	} else if days == 1 {
		fmt.Fprintf(w, "  @Y{expires in a day}\n")
	} else if days < 30 {
		fmt.Fprintf(w, "  @Y{expires in %d days}\n", days)
	} else {
		fmt.Fprintf(w, "  expires in @G{%d days}\n", days)
	}
	fmt.Fprintf(w, "  valid from @C{%s} - @C{%s}", cert.Certificate.NotBefore.Format("Jan 2 2006"), cert.Certificate.NotAfter.Format("Jan 2 2006"))

	life := int(cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore).Hours())
	if life < 360*24 {
		fmt.Fprintf(w, " (@M{~%d days})\n", life/24)
	} else {
		fmt.Fprintf(w, " (@M{~%d years})\n", life/365/24)
	}
	fmt.Fprintf(w, "\n")

	n := 0
	fmt.Fprintf(w, "  for the following purposes:\n")
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		n++
		fmt.Fprintf(w, "    - @C{digital-signature}  can be used to verify digital signatures.\n")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		n++
		fmt.Fprintf(w, "    - @C{non-repudiation}    can be used for non-repudiation / content commitment.\n")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		n++
		fmt.Fprintf(w, "    - @C{key-encipherment}   can be used encrypt other keys, for transport.\n")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		n++
		fmt.Fprintf(w, "    - @C{data-encipherment}  can be used to encrypt user data directly.\n")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		n++
		fmt.Fprintf(w, "    - @C{key-agreement}      can be used in key exchange, a la Diffie-Hellman key exchange.\n")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		n++
		fmt.Fprintf(w, "    - @C{key-cert-sign}      can be used to verify digital signatures on public key certificates.\n")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		n++
		fmt.Fprintf(w, "    - @C{crl-sign}           can be used to verify digital signatures on certificate revocation lists.\n")
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		n++
		if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
			fmt.Fprintf(w, "    - @C{encipher-only}      can only be used to encrypt data in a key exchange.\n")
		} else {
			fmt.Fprintf(w, "    - @C{encipher-only}      this key-usage is undefined if key-agreement is not set (which it isn't).\n")
		}
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		n++
		if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
			fmt.Fprintf(w, "    - @C{decipher-only}      can only be used to decrypt data in a key exchange.\n")
		} else {
			fmt.Fprintf(w, "    - @C{decipher-only}      this key-usage is undefined if key-agreement is not set (which it isn't).\n")
		}
	}
	for _, ku := range cert.ExtKeyUsage {
		n++
		switch ku {
		default:
			n--
		case x509.ExtKeyUsageClientAuth:
			fmt.Fprintf(w, "    - @C{client-auth}*       can be used by a TLS client for authentication.\n")
		case x509.ExtKeyUsageServerAuth:
			fmt.Fprintf(w, "    - @C{server-auth}*       can be used by a TLS server for authentication.\n")
		case x509.ExtKeyUsageCodeSigning:
			fmt.Fprintf(w, "    - @C{code-signing}*      can be used to sign software packages to prove source.\n")
		case x509.ExtKeyUsageEmailProtection:
			fmt.Fprintf(w, "    - @C{email-protection}*  can be used to protect email (signing, encryption, and key exchange).\n")
		case x509.ExtKeyUsageTimeStamping:
			fmt.Fprintf(w, "    - @C{timestamping}*      can be used to generate trusted timestamps.\n")
		}
	}
	if n == 0 {
		fmt.Fprintf(w, "    (no special key usage constraints present)\n")
	}
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "  key: @G{%s}\n\n", cert.KeyDescription())

	fmt.Fprintf(w, "  signed with the algorithm ")
	sigView := map[x509.SignatureAlgorithm]string{
		x509.UnknownSignatureAlgorithm: "Unknown",
		x509.MD2WithRSA:                "MD2 With RSA",
		x509.MD5WithRSA:                "MD5 With RSA",
		x509.SHA1WithRSA:               "SHA1 With RSA",
		x509.SHA256WithRSA:             "SHA256 With RSA",
		x509.SHA384WithRSA:             "SHA384 With RSA",
		x509.SHA512WithRSA:             "SHA512 With RSA",
		x509.DSAWithSHA1:               "DSA With SHA1",
		x509.DSAWithSHA256:             "DSA With SHA256",
		x509.ECDSAWithSHA1:             "ECDSA With SHA1",
		x509.ECDSAWithSHA256:           "ECDSA With SHA256",
		x509.ECDSAWithSHA384:           "ECDSA With SHA384",
		x509.ECDSAWithSHA512:           "ECDSA With SHA512",
		x509.SHA256WithRSAPSS:          "SHA256 With RSAPSS",
		x509.SHA384WithRSAPSS:          "SHA384 With RSAPSS",
		x509.SHA512WithRSAPSS:          "SHA512 With RSAPSS",
	}
	sigAlgo := sigView[cert.Certificate.SignatureAlgorithm]
	fmt.Fprintf(w, "@G{%s}\n", sigAlgo)
	fmt.Fprintf(w, "\n")

	fmt.Fprintf(w, "  for the following names:\n")
	for _, s := range cert.Certificate.DNSNames {
		fmt.Fprintf(w, "    - @G{%s} (DNS)\n", s)
	}
	for _, s := range cert.Certificate.EmailAddresses {
		fmt.Fprintf(w, "    - @G{%s} (email)\n", s)
	}
	for _, s := range cert.Certificate.IPAddresses {
		fmt.Fprintf(w, "    - @G{%s} (IP)\n", s)
	}
	fmt.Fprintf(w, "\n")

	serialString := fmt.Sprintf("@M{%[1]d} (@M{%#[1]x})", cert.Certificate.SerialNumber)
	if cert.Certificate.SerialNumber.Cmp(big.NewInt(1000)) == 1 {
		serialString = fmt.Sprintf("@M{%s}", cert.FormatSerial())
	}
	fmt.Fprintf(w, "  serial: %s\n", serialString)
	fmt.Fprintf(w, "  ")
	if cert.IsCA() {
		fmt.Fprintf(w, "@G{is}")
	} else {
		fmt.Fprintf(w, "@Y{is not}")
	}
	fmt.Fprintf(w, " a CA\n")
	fmt.Fprintf(w, "\n")
}

func (c *CLI) cmdX509Crl(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if !opt.X509.CRL.Renew || len(args) != 1 {
		return r.Usage("x509 crl")
	}

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	v := connect(true)

	s, err := v.Read(args[0])
	if err != nil {
		return err
	}
	ca, err := s.X509(true)
	if err != nil {
		return err
	}

	if !ca.IsCA() {
		return fmt.Errorf("%s is not a certificate authority", args[0])
	}

	/* simply re-saving the CA X509 object regens the CRL */
	s, err = ca.Secret(false) // SkipIfExists doesn't make sense in the context of crl regeneration
	if err != nil {
		return err
	}
	err = v.Write(args[0], s)
	if err != nil {
		return err
	}

	return nil
}
