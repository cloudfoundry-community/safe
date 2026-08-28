package cli

// `safe x509 validate' and `safe x509 show' read one path at a time, though
// nothing about either command's output depends on when the reads happen --
// only the parse/validate/print loops are order-sensitive. Both now
// prefetch every path's read concurrently, cmdGet-style, and run their
// existing loops sequentially in argument order over the prefetched
// results. Output and exit codes are unchanged; the one declared delta is
// that validate issues every path's read even when an early path is going
// to fail.
//
// Certificates here are EC rather than RSA: these tests mint several
// certificates per run and P-256 keygen is microseconds where RSA is not.

import (
	"crypto/elliptic"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// newECCA builds a self-signed EC certificate authority.
func newECCA(t *testing.T, cn string) *vault.X509 {
	t.Helper()
	ca, err := vault.NewCertificate("CN="+cn, []string{cn},
		[]string{"key_cert_sign", "crl_sign"}, "",
		vault.KeySpec{Algorithm: "ec", Curve: elliptic.P256()})
	if err != nil {
		t.Fatalf("NewCertificate(%s): %v", cn, err)
	}
	ca.MakeCA()
	if err := ca.Sign(ca, 24*time.Hour); err != nil {
		t.Fatalf("self-sign %s: %v", cn, err)
	}
	return ca
}

// newECLeaf builds an EC certificate signed by ca.
func newECLeaf(t *testing.T, ca *vault.X509, cn string) *vault.X509 {
	t.Helper()
	leaf, err := vault.NewCertificate("CN="+cn, []string{cn},
		[]string{"server_auth"}, "",
		vault.KeySpec{Algorithm: "ec", Curve: elliptic.P256()})
	if err != nil {
		t.Fatalf("NewCertificate(%s): %v", cn, err)
	}
	if err := ca.Sign(leaf, time.Hour); err != nil {
		t.Fatalf("sign %s: %v", cn, err)
	}
	return leaf
}

// storeECLeaves mints count EC leaves under one CA and stores them at
// secret/l0, secret/l1, ... returning the paths.
func storeECLeaves(t *testing.T, fv *cliFakeVault, count int) []string {
	t.Helper()
	ca := newECCA(t, "ec-ca")
	var paths []string
	for i := 0; i < count; i++ {
		path := "secret/l" + string(rune('0'+i))
		storeCert(t, fv, path, newECLeaf(t, ca, "leaf"+string(rune('0'+i))))
		paths = append(paths, path)
	}
	return paths
}

// runOverlapped drives cmd in a goroutine against a gate already installed
// for pattern, and reports whether the gate tripped -- i.e. whether two
// matching requests were ever in flight together. The command's error comes
// back too. Not run under captureStdout, for the reason the other overlap
// tests give: on a genuine miss the parked request would still be blocked
// when the test returns.
func runOverlapped(t *testing.T, fv *cliFakeVault, release <-chan struct{}, pattern string, cmd func() error) (bool, error) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- cmd()
	}()

	var cmdErr error
	var overlapped bool
	select {
	case <-release:
		overlapped = true
		cmdErr = <-done
	case cmdErr = <-done:
		// finished with no observed overlap
	case <-time.After(5 * time.Second):
		fv.holdRequests(0, pattern) // let the parked request, and the command, finish
		cmdErr = <-done
	}
	return overlapped, cmdErr
}

// Validate reads its paths concurrently rather than one at a time.
func TestX509ValidateReadsPathsConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	paths := storeECLeaves(t, fv, 4)

	pattern := `^GET /v1/secret/l[0-9]$`
	release := fv.holdRequests(2, pattern)

	c := newX509CLI(t)
	overlapped, err := runOverlapped(t, fv, release, pattern, func() error {
		return c.cmdX509Validate("x509 validate", paths...)
	})
	if err != nil {
		t.Fatalf("cmdX509Validate: %v", err)
	}
	if !overlapped {
		t.Fatal("no overlap observed: validate reads its paths sequentially")
	}
}

// Show reads its paths concurrently rather than one at a time.
func TestX509ShowReadsPathsConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	paths := storeECLeaves(t, fv, 4)

	pattern := `^GET /v1/secret/l[0-9]$`
	release := fv.holdRequests(2, pattern)

	c := newX509CLI(t)
	overlapped, err := runOverlapped(t, fv, release, pattern, func() error {
		return c.cmdX509Show("x509 show", paths...)
	})
	if err != nil {
		t.Fatalf("cmdX509Show: %v", err)
	}
	if !overlapped {
		t.Fatal("no overlap observed: show reads its paths sequentially")
	}
}

// Show still reports every path in argument order -- never fetch-completion
// order -- and still answers for exactly the paths it could not show, in
// that same order.
func TestX509ShowKeepsArgumentOrderOverAMixedBatch(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ca := newECCA(t, "ec-ca")
	storeCert(t, fv, "secret/leaf", newECLeaf(t, ca, "leaf"))
	fv.set("secret/password", map[string]string{"password": "sekrit"})

	c := newX509CLI(t)

	var err error
	out := captureStdout(t, func() {
		err = c.cmdX509Show("x509 show", "secret/password", "secret/nowhere", "secret/leaf")
	})

	if err == nil {
		t.Fatal("show over a path holding no certificate = nil, want an error")
	}
	if got, want := err.Error(), "no certificate to show at secret/password, secret/nowhere"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}

	prev := -1
	for _, header := range []string{"secret/password:", "secret/nowhere:", "secret/leaf:"} {
		at := strings.Index(out, header)
		if at < 0 {
			t.Fatalf("output should contain %q\n---\n%s", header, out)
		}
		if at < prev {
			t.Errorf("%q reported out of argument order\n---\n%s", header, out)
		}
		prev = at
	}
}

// A failure on the first path reads the same as it did when the reads were
// serial: the error text is identical to a run over that path alone, even
// though the later paths' reads now happen too.
func TestX509ValidateFirstPathFailureIsUnchanged(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ca := newECCA(t, "ec-ca")
	storeCert(t, fv, "secret/good", newECLeaf(t, ca, "leaf"))
	fv.set("secret/junk", map[string]string{"password": "sekrit"})

	c := newX509CLI(t)
	batchErr := c.cmdX509Validate("x509 validate", "secret/junk", "secret/good")
	if batchErr == nil {
		t.Fatal("validate with an invalid first path = nil, want an error")
	}

	fv.forgetRequests()
	soloErr := c.cmdX509Validate("x509 validate", "secret/junk")
	if soloErr == nil {
		t.Fatal("validate of the invalid path alone = nil, want an error")
	}
	if batchErr.Error() != soloErr.Error() {
		t.Errorf("batch error = %q, solo error = %q; want them identical", batchErr, soloErr)
	}
}
