package cli

// Arg-count / option guard tests for x509 subcommand handlers.
//
// Covered handlers and the pre-connect guard each exercises:
//
//   cmdX509Validate — zero args fires before rc.Apply; flag combos fire before rc.Apply
//   cmdX509Issue    — arg!=1 or no --name fires after rc.Apply but before connect
//   cmdX509Reissue  — arg!=1 fires after rc.Apply but before connect;
//                     --no-clobber fires at same point
//   cmdX509Renew    — arg!=1 fires after rc.Apply but before connect;
//                     --no-clobber fires at same point
//   cmdX509Revoke   — missing --signed-by or wrong arg count fires BEFORE rc.Apply
//   cmdX509Show     — zero args fires after rc.Apply but before connect
//   cmdX509Crl      — !--renew or arg!=1 fires BEFORE rc.Apply
//
// Cases that call connect() before the guard are NOT testable without a live
// Vault and are documented with t.Skip.

import "testing"

// newX509CLI builds a *CLI with x509 subcommands registered for r.Usage.
func newX509CLI(t *testing.T) *CLI {
	t.Helper()
	r := NewRunner()
	opt := &Options{}
	c := &CLI{opt: opt, r: r}
	for _, name := range []string{
		"x509 validate", "x509 issue", "x509 reissue",
		"x509 renew", "x509 revoke", "x509 show", "x509 crl",
	} {
		r.Dispatch(name, &Help{
			Summary: name,
			Usage:   "safe " + name + " ...",
			Type:    NonDestructiveCommand,
		}, func(cmd string, args ...string) error { return nil })
	}
	c.r = r
	c.opt = opt
	return c
}

// ---------------------------------------------------------------------------
// cmdX509Validate
// ---------------------------------------------------------------------------

// Zero args fires before rc.Apply — no HOME isolation needed, but we isolate
// anyway to keep tests hermetic.
func TestCmdX509Validate_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	err := c.cmdX509Validate("x509 validate")
	assertUsageError(t, err, "x509 validate")
}

// --revoked without --signed-by: guard fires before rc.Apply.
func TestCmdX509Validate_RevokedWithoutSignedBy_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.X509.Validate.Revoked = true
	// SignedBy is ""
	err := c.cmdX509Validate("x509 validate", "secret/cert")
	assertUsageError(t, err, "x509 validate")
}

// --not-revoked without --signed-by: guard fires before rc.Apply.
func TestCmdX509Validate_NotRevokedWithoutSignedBy_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.X509.Validate.NotRevoked = true
	// SignedBy is ""
	err := c.cmdX509Validate("x509 validate", "secret/cert")
	assertUsageError(t, err, "x509 validate")
}

// ---------------------------------------------------------------------------
// cmdX509Issue
// ---------------------------------------------------------------------------

// Zero args, no --name: guard fires after rc.Apply but before connect.
func TestCmdX509Issue_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	err := c.cmdX509Issue("x509 issue")
	assertUsageError(t, err, "x509 issue")
}

// Two args (even with --name): guard fires because len(args) != 1.
func TestCmdX509Issue_TwoArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"example.com"}
	err := c.cmdX509Issue("x509 issue", "secret/cert", "extra")
	assertUsageError(t, err, "x509 issue")
}

// One arg but no --name: guard fires because Name is empty.
func TestCmdX509Issue_OneArgNoName_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	// Name is nil/empty
	err := c.cmdX509Issue("x509 issue", "secret/cert")
	assertUsageError(t, err, "x509 issue")
}

// ---------------------------------------------------------------------------
// cmdX509Reissue
// ---------------------------------------------------------------------------

// Zero args: guard fires after rc.Apply but before connect.
func TestCmdX509Reissue_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	err := c.cmdX509Reissue("x509 reissue")
	assertUsageError(t, err, "x509 reissue")
}

// Two args: guard fires.
func TestCmdX509Reissue_TwoArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	err := c.cmdX509Reissue("x509 reissue", "secret/cert", "extra")
	assertUsageError(t, err, "x509 reissue")
}

// --no-clobber with one arg: SkipIfExists guard fires before connect.
func TestCmdX509Reissue_NoClobber_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.SkipIfExists = true
	err := c.cmdX509Reissue("x509 reissue", "secret/cert")
	assertUsageError(t, err, "x509 reissue")
}

// ---------------------------------------------------------------------------
// cmdX509Renew
// ---------------------------------------------------------------------------

// Zero args: guard fires after rc.Apply but before connect.
func TestCmdX509Renew_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	err := c.cmdX509Renew("x509 renew")
	assertUsageError(t, err, "x509 renew")
}

// Two args: guard fires.
func TestCmdX509Renew_TwoArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	err := c.cmdX509Renew("x509 renew", "secret/cert", "extra")
	assertUsageError(t, err, "x509 renew")
}

// --no-clobber with one arg: SkipIfExists guard fires before connect.
func TestCmdX509Renew_NoClobber_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.SkipIfExists = true
	err := c.cmdX509Renew("x509 renew", "secret/cert")
	assertUsageError(t, err, "x509 renew")
}

// ---------------------------------------------------------------------------
// cmdX509Revoke
// ---------------------------------------------------------------------------

// No --signed-by: guard fires before rc.Apply.
func TestCmdX509Revoke_NoSignedBy_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	// SignedBy is ""
	err := c.cmdX509Revoke("x509 revoke", "secret/cert")
	assertUsageError(t, err, "x509 revoke")
}

// --signed-by set but zero args: guard fires before rc.Apply (len(args) != 1).
func TestCmdX509Revoke_SignedByButZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"
	err := c.cmdX509Revoke("x509 revoke")
	assertUsageError(t, err, "x509 revoke")
}

// --signed-by set but two args: guard fires before rc.Apply (len(args) != 1).
func TestCmdX509Revoke_SignedByButTwoArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"
	err := c.cmdX509Revoke("x509 revoke", "secret/cert", "extra")
	assertUsageError(t, err, "x509 revoke")
}

// ---------------------------------------------------------------------------
// cmdX509Show
// ---------------------------------------------------------------------------

// Zero args: guard fires after rc.Apply but before connect.
func TestCmdX509Show_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	err := c.cmdX509Show("x509 show")
	assertUsageError(t, err, "x509 show")
}

// ---------------------------------------------------------------------------
// cmdX509Crl
// ---------------------------------------------------------------------------

// --renew not set (zero value false): guard fires before rc.Apply.
func TestCmdX509Crl_RenewNotSet_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	// CRL.Renew defaults to false
	err := c.cmdX509Crl("x509 crl", "secret/ca")
	assertUsageError(t, err, "x509 crl")
}

// --renew set but zero args: guard fires before rc.Apply.
func TestCmdX509Crl_RenewSetZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.X509.CRL.Renew = true
	err := c.cmdX509Crl("x509 crl")
	assertUsageError(t, err, "x509 crl")
}

// --renew set but two args: guard fires before rc.Apply.
func TestCmdX509Crl_RenewSetTwoArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newX509CLI(t)
	c.opt.X509.CRL.Renew = true
	err := c.cmdX509Crl("x509 crl", "secret/ca", "extra")
	assertUsageError(t, err, "x509 crl")
}
