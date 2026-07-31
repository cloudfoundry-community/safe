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
		//Checking a signature and reading a revocation list both need the
		// CA's certificate and neither needs its key, so validating against
		// a CA whose private key is held somewhere else — an offline root,
		// or one belonging to another team — works rather than failing on
		// the missing attribute.
		ca, err = s.X509(false)
		if err != nil {
			return err
		}

		//Only a certificate authority keeps a revocation list, so a
		// revocation check against anything else has no answer to give.
		if opt.X509.Validate.Revoked || opt.X509.Validate.NotRevoked {
			if !ca.IsCA() {
				return fmt.Errorf("%s is not a certificate authority", opt.X509.Validate.SignedBy)
			}
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

		_, _ = fmt.Printf("@G{%s} checks out.\n", path)
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

	//Both the new certificate and the CA that signed it are written back, and
	// checking now means the refusal arrives before a key is generated rather
	// than after.
	if err := assertWritablePaths(args[0], opt.X509.Issue.SignedBy); err != nil {
		return err
	}

	//Issuing writes the new certificate over whatever the path held. Naming
	// the signing authority as the destination — a slip of one word on the
	// command line — replaces the authority with the certificate it just
	// signed, taking its private key, its serial number, and its revocation
	// list with it, and everything it ever issued becomes unverifiable.
	if args[0] == opt.X509.Issue.SignedBy {
		return fmt.Errorf("refusing to overwrite the signing authority %s with the certificate it signs", args[0])
	}

	if opt.X509.Issue.Subject == "" {
		opt.X509.Issue.Subject = fmt.Sprintf("CN=%s", opt.X509.Issue.Name[0])
	}

	v := connect(true)
	if opt.SkipIfExists {
		if _, err := v.Read(args[0]); err == nil {
			if !opt.Quiet {
				_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to create a new certificate in} @C{%s} @R{as it is already present in Vault}\n", args[0])
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

		//Signing with a certificate that is not an authority produces one no
		// relying party will accept, and nothing further along says so: the
		// certificate is written, looks ordinary, and fails at the far end.
		if !ca.IsCA() {
			return fmt.Errorf("%s is not a certificate authority", opt.X509.Issue.SignedBy)
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
		_, _ = fmt.Fprintf(os.Stderr, "@R{!!} @C{--no-clobber} @R{is incompatible with} @C{safe x509 reissue}\n")
		return r.Usage("x509 reissue")
	}

	if err := assertWritablePaths(args[0], opt.X509.Reissue.SignedBy); err != nil {
		return err
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

	//Which authority signed this is a fact about the certificate as stored,
	// and answering it reads the signature the certificate arrived with. The
	// changes below overwrite the algorithm that signature was made with, so
	// the authority has to be found before they are applied.
	ca, caPath, err := v.FindSigningCA(cert, args[0], opt.X509.Reissue.SignedBy)
	if err != nil {
		return err
	}

	if len(opt.X509.Reissue.Name) > 0 {
		ips, dns, email := vault.CategorizeSANs(uniq(opt.X509.Reissue.Name))
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
	_, _ = fmt.Printf("\nGenerating new %s key...\n", spec.Describe())
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

	_, _ = fmt.Printf("Reissued x509 certificate at %s - expiry set to %s\n\n", args[0], cert.ExpiryString())

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
		_, _ = fmt.Fprintf(os.Stderr, "@R{!!} @C{--no-clobber} @R{is incompatible with} @C{safe x509 renew}\n")
		return r.Usage("x509 renew")
	}

	if err := assertWritablePaths(args[0], opt.X509.Renew.SignedBy); err != nil {
		return err
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

	//Which authority signed this is a fact about the certificate as stored,
	// and answering it reads the signature the certificate arrived with.
	// --sig-algorithm overwrites the algorithm that signature was made with,
	// so the authority has to be found before the changes below are applied.
	ca, caPath, err := v.FindSigningCA(cert, args[0], opt.X509.Renew.SignedBy)
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

	_, _ = fmt.Printf("\nRenewed x509 certificate at %s - expiry set to %s\n\n", args[0], cert.ExpiryString())
	return nil
}

func (c *CLI) cmdX509Revoke(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if opt.X509.Revoke.SignedBy == "" || len(args) != 1 {
		return r.Usage("x509 revoke")
	}

	//Only the CA is written; the certificate named on the command line is
	// read to find its serial number.
	if err := assertWritablePaths(opt.X509.Revoke.SignedBy); err != nil {
		return err
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
	//Revocation is recorded on the CA's revocation list, and only a
	// certificate authority carries one.
	if !ca.IsCA() {
		return fmt.Errorf("%s is not a certificate authority", opt.X509.Revoke.SignedBy)
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

	//A revocation list names serial numbers, and a serial number only
	// identifies a certificate within the authority that issued it. safe
	// numbers the certificates each of its CAs issues from one, so a serial
	// borrowed from another CA is very likely to be one this CA handed out
	// itself: revoking a foreign certificate would revoke an unrelated one
	// of the CA's own, and say nothing about the certificate named here.
	if err := ca.Certificate.CheckSignature(
		cert.Certificate.SignatureAlgorithm,
		cert.Certificate.RawTBSCertificate,
		cert.Certificate.Signature,
	); err != nil {
		return fmt.Errorf("%s was not signed by %s", args[0], opt.X509.Revoke.SignedBy)
	}

	/* revoke the Certificate */
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
		s, err := v.Read(path)
		if err != nil {
			return err
		}

		_, _ = fmt.Printf("%s:\n", path)
		cert, err := s.X509(false)
		if err != nil {
			_, _ = fmt.Printf("  !! %s\n\n", err)
			continue
		}

		printX509(os.Stdout, cert)
	}

	return nil
}

const day = 24 * time.Hour

// daysAway rounds a span of time still to come to the nearest whole day, so
// that a span of very nearly n days is reported as n rather than as the n-1
// whole days it technically holds.
func daysAway(d time.Duration) int {
	return int((d + day/2) / day)
}

// count names a quantity of something, in the singular when there is one of
// it.
func count(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// printX509 renders the human-readable detail block for a single
// certificate to w. Output is identical to the original inline
// rendering in cmdX509Show (go-ansi Printf is Fprintf to os.Stdout).
func printX509(w io.Writer, cert *vault.X509) {
	_, _ = fmt.Fprintf(w, "  @G{%s}\n\n", cert.Subject())
	if cert.Subject() != cert.Issuer() {
		_, _ = fmt.Fprintf(w, "  issued by: @C{%s}\n", cert.Issuer())
		for i := range cert.Intermediaries {
			_, _ = fmt.Fprintf(w, "        via: @C{%s}\n", cert.IntermediarySubject(i))
		}
	} else {
		_, _ = fmt.Fprintf(w, "  @C{self-signed}\n")
	}

	toStart := time.Until(cert.Certificate.NotBefore)
	toEnd := time.Until(cert.Certificate.NotAfter)

	//A wait or a countdown is reported to the nearest day rather than in
	// whole days elapsed. A certificate issued to run for 30 days is a moment
	// short of 30 days old the instant it is written, and counting whole days
	// reported every one of them one day short.
	switch days := daysAway(toStart); {
	case toStart <= 0:
		//Already in force; nothing to say about it starting.
	case days <= 1:
		//Rounding a wait of a few hours to no days at all said nothing at
		// all, and a certificate that cannot be used yet read as usable.
		if toStart < day {
			_, _ = fmt.Fprintf(w, "  @Y{not valid yet}\n")
		} else {
			_, _ = fmt.Fprintf(w, "  @Y{not valid for another day}\n")
		}
	default:
		_, _ = fmt.Fprintf(w, "  @Y{not valid for another %d days}\n", days)
	}

	//Time already spent is counted in whole days, which is how "expired two
	// days ago" is read; time still to come is rounded, as above.
	switch days := daysAway(toEnd); {
	case toEnd <= -2*day:
		_, _ = fmt.Fprintf(w, "  @R{EXPIRED %d days ago}\n", int(-toEnd/day))
	case toEnd <= -day:
		_, _ = fmt.Fprintf(w, "  @R{EXPIRED a day ago}\n")
	case toEnd <= 0:
		_, _ = fmt.Fprintf(w, "  @R{EXPIRED}\n")
	case toEnd < day:
		//The case whole days cannot tell from an expired certificate: still
		// valid, and out of days. It used to be reported as EXPIRED.
		_, _ = fmt.Fprintf(w, "  @Y{expires in less than a day}\n")
	case days <= 1:
		_, _ = fmt.Fprintf(w, "  @Y{expires in a day}\n")
	case days < 30:
		_, _ = fmt.Fprintf(w, "  @Y{expires in %d days}\n", days)
	default:
		_, _ = fmt.Fprintf(w, "  expires in @G{%d days}\n", days)
	}
	_, _ = fmt.Fprintf(w, "  valid from @C{%s} - @C{%s}", cert.Certificate.NotBefore.Format("Jan 2 2006"), cert.Certificate.NotAfter.Format("Jan 2 2006"))

	//The life a certificate was issued for is given in the largest unit that
	// counts it. Years and days used to be the only two, divided at 360 days
	// -- five short of the year the years are counted in -- so a life of 360
	// to 364 days divided to nothing and was reported as `~0 years'. A life
	// of a few hours, which `--ttl 12h' asks for, had the same nothing to say
	// for itself in days.
	life := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)
	switch {
	case life < day:
		_, _ = fmt.Fprintf(w, " (@M{~%s})\n", count(int(life/time.Hour), "hour"))
	case life < 365*day:
		_, _ = fmt.Fprintf(w, " (@M{~%s})\n", count(int(life/day), "day"))
	default:
		_, _ = fmt.Fprintf(w, " (@M{~%s})\n", count(int(life/(365*day)), "year"))
	}
	_, _ = fmt.Fprintf(w, "\n")

	n := 0
	_, _ = fmt.Fprintf(w, "  for the following purposes:\n")
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		n++
		_, _ = fmt.Fprintf(w, "    - @C{digital-signature}  can be used to verify digital signatures.\n")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		n++
		_, _ = fmt.Fprintf(w, "    - @C{non-repudiation}    can be used for non-repudiation / content commitment.\n")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		n++
		_, _ = fmt.Fprintf(w, "    - @C{key-encipherment}   can be used encrypt other keys, for transport.\n")
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		n++
		_, _ = fmt.Fprintf(w, "    - @C{data-encipherment}  can be used to encrypt user data directly.\n")
	}
	if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		n++
		_, _ = fmt.Fprintf(w, "    - @C{key-agreement}      can be used in key exchange, a la Diffie-Hellman key exchange.\n")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		n++
		_, _ = fmt.Fprintf(w, "    - @C{key-cert-sign}      can be used to verify digital signatures on public key certificates.\n")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		n++
		_, _ = fmt.Fprintf(w, "    - @C{crl-sign}           can be used to verify digital signatures on certificate revocation lists.\n")
	}
	if cert.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		n++
		if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
			_, _ = fmt.Fprintf(w, "    - @C{encipher-only}      can only be used to encrypt data in a key exchange.\n")
		} else {
			_, _ = fmt.Fprintf(w, "    - @C{encipher-only}      this key-usage is undefined if key-agreement is not set (which it isn't).\n")
		}
	}
	if cert.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		n++
		if cert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
			_, _ = fmt.Fprintf(w, "    - @C{decipher-only}      can only be used to decrypt data in a key exchange.\n")
		} else {
			_, _ = fmt.Fprintf(w, "    - @C{decipher-only}      this key-usage is undefined if key-agreement is not set (which it isn't).\n")
		}
	}
	for _, ku := range cert.ExtKeyUsage {
		n++
		switch ku {
		default:
			n--
		case x509.ExtKeyUsageClientAuth:
			_, _ = fmt.Fprintf(w, "    - @C{client-auth}*       can be used by a TLS client for authentication.\n")
		case x509.ExtKeyUsageServerAuth:
			_, _ = fmt.Fprintf(w, "    - @C{server-auth}*       can be used by a TLS server for authentication.\n")
		case x509.ExtKeyUsageCodeSigning:
			_, _ = fmt.Fprintf(w, "    - @C{code-signing}*      can be used to sign software packages to prove source.\n")
		case x509.ExtKeyUsageEmailProtection:
			_, _ = fmt.Fprintf(w, "    - @C{email-protection}*  can be used to protect email (signing, encryption, and key exchange).\n")
		case x509.ExtKeyUsageTimeStamping:
			_, _ = fmt.Fprintf(w, "    - @C{timestamping}*      can be used to generate trusted timestamps.\n")
		}
	}
	if n == 0 {
		_, _ = fmt.Fprintf(w, "    (no special key usage constraints present)\n")
	}
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "  key: @G{%s}\n\n", cert.KeyDescription())

	_, _ = fmt.Fprintf(w, "  signed with the algorithm ")
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
	//An algorithm the table above does not name is named the way Go names it,
	// which for Ed25519 -- what `safe x509 issue --type ed25519' signs with --
	// is `Ed25519'. Reading the table alone, the line came out with nothing
	// after it.
	sigAlgo, ok := sigView[cert.Certificate.SignatureAlgorithm]
	if !ok {
		sigAlgo = cert.Certificate.SignatureAlgorithm.String()
	}
	_, _ = fmt.Fprintf(w, "@G{%s}\n", sigAlgo)
	_, _ = fmt.Fprintf(w, "\n")

	_, _ = fmt.Fprintf(w, "  for the following names:\n")
	for _, s := range cert.Certificate.DNSNames {
		_, _ = fmt.Fprintf(w, "    - @G{%s} (DNS)\n", s)
	}
	for _, s := range cert.Certificate.EmailAddresses {
		_, _ = fmt.Fprintf(w, "    - @G{%s} (email)\n", s)
	}
	for _, s := range cert.Certificate.IPAddresses {
		_, _ = fmt.Fprintf(w, "    - @G{%s} (IP)\n", s)
	}
	_, _ = fmt.Fprintf(w, "\n")

	serialString := fmt.Sprintf("@M{%[1]d} (@M{%#[1]x})", cert.Certificate.SerialNumber)
	if cert.Certificate.SerialNumber.Cmp(big.NewInt(1000)) == 1 {
		serialString = fmt.Sprintf("@M{%s}", cert.FormatSerial())
	}
	_, _ = fmt.Fprintf(w, "  serial: %s\n", serialString)
	_, _ = fmt.Fprintf(w, "  ")
	if cert.IsCA() {
		_, _ = fmt.Fprintf(w, "@G{is}")
	} else {
		_, _ = fmt.Fprintf(w, "@Y{is not}")
	}
	_, _ = fmt.Fprintf(w, " a CA\n")
	_, _ = fmt.Fprintf(w, "\n")
}

func (c *CLI) cmdX509Crl(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if !opt.X509.CRL.Renew || len(args) != 1 {
		return r.Usage("x509 crl")
	}

	//Regenerating the CRL saves the CA back over itself.
	if err := assertWritablePaths(args[0]); err != nil {
		return err
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
