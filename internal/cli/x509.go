package cli

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/internal/parallel"
	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// prefetchReads reads every path concurrently into an index-addressed
// slice, so an order-sensitive loop can run sequentially in argument order
// over results that were fetched together. fn always returns nil: per-path
// errors ride in the slice for the sequential loop to report exactly as a
// serial read would have, so EachLimit's fail-fast never triggers. The one
// visible consequence is that every path's read happens even when an
// earlier path's result is going to end the loop.
type prefetched struct {
	s   *vault.Secret
	err error
}

func prefetchReads(v *vault.Vault, paths []string) []prefetched {
	fetches := make([]prefetched, len(paths))
	_ = parallel.EachLimit(context.Background(), paths, parallel.IOLimit(), func(_ context.Context, i int, path string) error {
		s, err := v.Read(path)
		fetches[i] = prefetched{s: s, err: err}
		return nil
	})
	return fetches
}

// warnIfReparenting says so on standard error when the authority a
// certificate is about to be signed under is not the one that issued it.
// Signing under it hands back a certificate carrying an issuer it did not go
// in with, which is the point when --signed-by names a new authority
// deliberately and a surprise when it does not: FindSigningCA refuses a
// guessed sibling that did not issue the certificate by naming --signed-by,
// so following that advice with the refused path lands here. Renewing or
// reissuing under the authority that did issue it -- including one that has
// rotated its key, and a self-signed certificate answering for itself --
// says nothing.
func warnIfReparenting(cert, ca *vault.X509, caPath string) {
	if cert == nil || ca == nil || cert.IssuedBy(ca) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr,
		"@Y{!!} @C{%s} did not issue this certificate; it moves from @C{%s} to @C{%s}\n",
		caPath, cert.Issuer(), ca.Subject())
}

func (c *CLI) cmdX509(command string, args ...string) error {
	r := c.r

	_ = r.Help(os.Stdout, "x509")
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

	// The reads are prefetched; the checks below stay sequential in
	// argument order, so which path fails, and with what, is unchanged.
	fetches := prefetchReads(v, args)
	for i, path := range args {
		s, err := fetches[i].s, fetches[i].err
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

// issueTarget is one destination of an x509 issue batch: the path as it
// was given on the command line, the subject its certificate will carry,
// and — once built — the certificate itself.
type issueTarget struct {
	arg     string
	subject string
	cert    *vault.X509
}

// pathBasename returns the last segment of a canonicalized secret path,
// which is what a batch certificate's subject defaults to.
func pathBasename(arg string) string {
	p := vault.Canonicalize(arg)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// signCertsUnderCA reserves one serial per certificate from the CA's
// counter, signs each certificate, and produces the CA's replacement
// secret — the counter advanced past the whole batch, the revocation list
// re-signed exactly once. ca must be freshly parsed from the CA's stored
// secret every time this runs: producing the secret advances the CRL
// number through the shared CRL pointer, so a reused X509 would publish a
// double-bumped number. The certificates' keys were generated before this
// ran and stay outside it, so re-running against a freshly re-read CA
// re-signs the same keys with freshly drawn serials.
func signCertsUnderCA(ca *vault.X509, certs []*vault.X509, ttl time.Duration, skipIfExists bool) (*vault.Secret, error) {
	//An authority that keeps no counter hands out random serials, exactly
	// as Sign does for it; the nil entries below ask SignWithSerial for
	// that draw.
	serials := make([]*big.Int, len(certs))
	if ca.Serial != nil {
		serials = ca.ReserveSerials(len(certs))
	}
	for i, cert := range certs {
		if err := ca.SignWithSerial(cert, ttl, serials[i]); err != nil {
			return nil, err
		}
	}
	return ca.Secret(skipIfExists)
}

func (c *CLI) cmdX509Issue(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) < 1 || len(opt.X509.Issue.Name) == 0 {
		return r.Usage("x509 issue")
	}

	//Both the new certificates and the CA that signed them are written
	// back, and checking now means the refusal arrives before a key is
	// generated rather than after.
	if err := assertWritablePaths(append(append([]string(nil), args...), opt.X509.Issue.SignedBy)...); err != nil {
		return err
	}

	//Issuing writes each new certificate over whatever its path held.
	// Naming the signing authority as a destination — a slip of one word on
	// the command line — replaces the authority with a certificate it just
	// signed, taking its private key, its serial number, and its revocation
	// list with it, and everything it ever issued becomes unverifiable. And
	// naming the same destination twice would race one certificate's write
	// against the other's, which distinct paths are the whole point of a
	// batch avoiding.
	caPath := vault.Canonicalize(opt.X509.Issue.SignedBy)
	seen := map[string]bool{}
	for _, arg := range args {
		p := vault.Canonicalize(arg)
		if p == caPath {
			return fmt.Errorf("refusing to overwrite the signing authority %s with the certificate it signs", arg)
		}
		if seen[p] {
			return fmt.Errorf("refusing to issue two certificates to the same path %s", p)
		}
		seen[p] = true
	}

	//Every certificate in the batch carries the same SAN set from --name;
	// the subject is the one per-path attribute. A single path keeps the
	// old default of the first name; several default to each path's
	// basename, which is what tells the certificates apart. An explicit
	// --subject stamps the same subject on all of them, which defeats
	// that, so it draws a warning rather than a refusal.
	targets := make([]*issueTarget, len(args))
	for i, arg := range args {
		targets[i] = &issueTarget{arg: arg}
	}
	switch {
	case opt.X509.Issue.Subject == "" && len(args) == 1:
		targets[0].subject = fmt.Sprintf("CN=%s", opt.X509.Issue.Name[0])
	case opt.X509.Issue.Subject == "":
		for _, target := range targets {
			target.subject = fmt.Sprintf("CN=%s", pathBasename(target.arg))
		}
	default:
		for _, target := range targets {
			target.subject = opt.X509.Issue.Subject
		}
		if len(args) > 1 {
			_, _ = fmt.Fprintf(os.Stderr, "@Y{!!} --subject %s applies to all %d certificates; without it each would default to its path's basename\n",
				opt.X509.Issue.Subject, len(args))
		}
	}

	v := connect(true)
	if opt.SkipIfExists {
		//One read per destination decides every skip before a key is
		// generated: keygen-before-refusal burns seconds. The reads run
		// concurrently and the notices replay in argument order.
		readErrs := make([]error, len(targets))
		_ = parallel.EachLimit(context.Background(), targets, parallel.IOLimit(), func(_ context.Context, i int, target *issueTarget) error {
			_, err := v.Read(target.arg)
			readErrs[i] = err
			return nil
		})
		kept := targets[:0]
		for i, target := range targets {
			switch err := readErrs[i]; {
			case err == nil:
				if !opt.Quiet {
					_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to create a new certificate in} @C{%s} @R{as it is already present in Vault}\n", target.arg)
				}
			case vault.IsNotFound(err):
				kept = append(kept, target)
			default:
				//A read that could not be made sense of is not the same
				// answer as a path with nothing on it, and only the latter
				// is permission to write.
				return err
			}
		}
		targets = kept
		//Every path already taken leaves nothing to issue, so the CA is
		// neither read nor written: no CRL bump, no burned serials.
		if len(targets) == 0 {
			return nil
		}
	}

	if len(opt.X509.Issue.KeyUsage) == 0 {
		opt.X509.Issue.KeyUsage = append(opt.X509.Issue.KeyUsage, "server_auth", "client_auth")
		if opt.X509.Issue.CA {
			opt.X509.Issue.KeyUsage = append(opt.X509.Issue.KeyUsage, "key_cert_sign", "crl_sign")
		}
	}

	//A bad key spec or a malformed subject is knowable from the flags and
	// paths alone, so both are refused before the CA read and before any
	// key generation is paid for.
	spec, err := vault.ResolveKeySpec(opt.X509.Issue.Type, opt.X509.Issue.Bits, opt.X509.Issue.Curve, nil)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if _, err := vault.ParseSubject(target.subject); err != nil {
			return err
		}
	}

	//The CA read is a network round trip and the key draws are pure CPU,
	// and neither depends on the other, so they run at the same time and
	// join here. A CA problem comes back without waiting the draws out.
	var ca *vault.X509
	keys, err := vault.GenerateKeysWhileFetching(spec, len(targets), parallel.CPULimit(), func() error {
		if opt.X509.Issue.SignedBy == "" {
			return nil
		}
		secret, rerr := v.Read(opt.X509.Issue.SignedBy)
		if rerr != nil {
			return rerr
		}

		signer, xerr := secret.X509(true)
		if xerr != nil {
			return xerr
		}

		//Signing with a certificate that is not an authority produces one no
		// relying party will accept, and nothing further along says so: the
		// certificate is written, looks ordinary, and fails at the far end.
		if !signer.IsCA() {
			return fmt.Errorf("%s is not a certificate authority", opt.X509.Issue.SignedBy)
		}
		ca = signer
		return nil
	})
	if err != nil {
		return err
	}

	for i, target := range targets {
		cert, err := vault.NewCertificateWithKey(target.subject,
			uniq(opt.X509.Issue.Name), opt.X509.Issue.KeyUsage,
			opt.X509.Issue.SigAlgorithm, keys[i])
		if err != nil {
			return err
		}
		if opt.X509.Issue.CA {
			cert.MakeCA()
		}
		target.cert = cert
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
		//Self-signed: each certificate answers for itself, and no CA
		// read-modify-write exists to order around.
		for _, target := range targets {
			if err := target.cert.Sign(target.cert, ttl); err != nil {
				return err
			}
		}
	} else {
		certs := make([]*vault.X509, len(targets))
		for i, target := range targets {
			certs[i] = target.cert
		}
		caSecret, err := signCertsUnderCA(ca, certs, ttl, opt.SkipIfExists)
		if err != nil {
			return err
		}
		//The CA write lands before any certificate write: a crash between
		// the two burns reserved serials, which is harmless, rather than
		// leaving certificates the persisted counter does not account for.
		if err := v.Write(opt.X509.Issue.SignedBy, caSecret); err != nil {
			return err
		}
	}

	writeErrs := make([]error, len(targets))
	_ = parallel.EachLimit(context.Background(), targets, parallel.IOLimit(), func(_ context.Context, i int, target *issueTarget) error {
		writeErrs[i] = target.cert.SaveTo(v, target.arg, opt.SkipIfExists)
		return nil
	})

	var failures []error
	for i, target := range targets {
		if writeErrs[i] != nil {
			failures = append(failures, fmt.Errorf("failed to write the certificate to %s: %s", target.arg, writeErrs[i]))
		}
	}
	if len(failures) == 0 {
		return nil
	}
	if len(targets) == 1 {
		//A lone destination fails the way it always has: the bare error.
		return writeErrs[0]
	}
	//The CA write already landed, so every serial that went out is
	// accounted for and the certificates that did write stand. Say which,
	// so a partial batch reads as partial rather than silently half-done.
	for i, target := range targets {
		if writeErrs[i] == nil {
			_, _ = fmt.Fprintf(os.Stderr, "@G{wrote} @C{%s}\n", target.arg)
		}
	}
	return parallel.NewErrors(failures...)
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

	//Flag problems are knowable from the certificate just read and the
	// flags alone, so the spec and every override are validated here,
	// before the authority is found and before any key generation is paid
	// for. The overrides are applied further down, after the fetch joins.
	// With no overriding flags the spec preserves the existing
	// certificate's key type and parameters; --type/--bits/--curve
	// override it.
	spec, err := vault.ResolveKeySpec(opt.X509.Reissue.Type, opt.X509.Reissue.Bits, opt.X509.Reissue.Curve, cert.PrivateKey)
	if err != nil {
		return err
	}
	if opt.X509.Reissue.Subject != "" {
		if _, err := vault.ParseSubject(opt.X509.Reissue.Subject); err != nil {
			return err
		}
	}
	if len(opt.X509.Reissue.KeyUsage) > 0 {
		if _, _, err := vault.HandleJointKeyUsages(opt.X509.Reissue.KeyUsage); err != nil {
			return err
		}
	}
	if opt.X509.Reissue.SigAlgorithm != "" {
		if _, err := vault.TranslateSignatureAlgorithm(opt.X509.Reissue.SigAlgorithm); err != nil {
			return err
		}
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

	//Which authority signed this is a fact about the certificate as stored,
	// and answering it reads the signature the certificate arrived with. The
	// changes below overwrite the algorithm that signature was made with, so
	// the authority has to be found before they are applied -- and finding
	// it is a network round trip the new key's generation does not depend
	// on, so the two run at the same time and join here.
	_, _ = fmt.Printf("\nGenerating new %s key...\n", spec.Describe())
	var (
		ca     *vault.X509
		caPath string
	)
	newKey, err := vault.GenerateKeyWhileFetching(spec, func() error {
		var ferr error
		ca, caPath, ferr = v.FindSigningCA(cert, args[0], opt.X509.Reissue.SignedBy)
		return ferr
	})
	if err != nil {
		return err
	}
	warnIfReparenting(cert, ca, caPath)

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

	cert.PrivateKey = newKey
	err = ca.Sign(cert, ttl)
	if err != nil {
		return err
	}
	//caPath and args[0] can spell the same secret differently (a leading or
	// trailing slash); FindSigningCA compares them as raw strings and, not
	// recognizing the alias, reads the authority as a second, separate copy.
	// Saving that copy back is then a second write to the record the
	// reissued certificate below is about to overwrite anyway — one that
	// carries a serial-counter increment the final write does not, since it
	// lands on a copy that is discarded rather than the one that is saved.
	if vault.Canonicalize(caPath) != vault.Canonicalize(args[0]) {
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
	warnIfReparenting(cert, ca, caPath)

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
	//See the matching comment in cmdX509Reissue: caPath and args[0] can
	// spell the same secret differently, and the raw comparison here has to
	// see through that or write the same record twice.
	if vault.Canonicalize(caPath) != vault.Canonicalize(args[0]) {
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

	//A path that holds no certificate was reported on the screen and nowhere
	// else, so a run that showed nothing at all still exited 0 and a script
	// checking a batch of paths was told they were fine. A path that could
	// not be read ended the run where it stood, leaving the paths after it
	// unreported. Both are now said as they are reached, and the run answers
	// for them at the end.
	var unshown []string

	// The reads are prefetched; the report below stays sequential in
	// argument order, never fetch-completion order.
	fetches := prefetchReads(v, args)
	for i, path := range args {
		_, _ = fmt.Printf("%s:\n", path)

		var cert *vault.X509
		s, err := fetches[i].s, fetches[i].err
		if err == nil {
			cert, err = s.X509(false)
		}
		if err != nil {
			_, _ = fmt.Printf("  !! %s\n\n", err)
			unshown = append(unshown, path)
			continue
		}

		printX509(os.Stdout, cert)
	}

	if len(unshown) > 0 {
		return fmt.Errorf("no certificate to show at %s", strings.Join(unshown, ", "))
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
