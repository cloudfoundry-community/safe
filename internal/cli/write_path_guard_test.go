package cli

// The commands that write a whole secret reject a path naming a key or a
// version before connecting, so the complaint arrives ahead of the prompt or
// the key generation rather than after the work is discarded.
//
// These guards sit before connect(), so no Vault seam is needed; HOME is
// isolated so rc.Apply returns an empty config without error.

import (
	"strings"
	"testing"
)

// newWritePathCLI registers the commands whose guards are exercised here so
// that r.Usage returns a properly-typed *UsageError when arg counts are short.
func newWritePathCLI(t *testing.T) *CLI {
	t.Helper()
	r := NewRunner()
	opt := &Options{}
	c := &CLI{opt: opt, r: r}
	for _, name := range []string{
		"set", "paste", "ask", "ssh", "rsa", "dhparam",
		"fmt", "x509 issue", "x509 reissue", "x509 renew", "x509 revoke", "x509 crl",
	} {
		r.Dispatch(name, &Help{
			Summary: name,
			Usage:   "safe " + name + " ...",
			Type:    DestructiveCommand,
		}, func(cmd string, args ...string) error { return nil })
	}
	return c
}

func assertWritePathRejected(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err.Error(), want)
	}
}

func TestAssertWritablePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		path string
		want string
	}{
		{"plain path", "secret/foo", ""},
		{"key", "secret/foo:bar", "/path:key"},
		{"version", "secret/foo^2", "/path^version"},
		{"escaped colon is part of the path", `secret/we\:ird`, ""},
		{"escaped caret is part of the path", `secret/ca\^ret`, ""},
		{"escaped path with a real key", `secret/we\:ird:bar`, "/path:key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := assertWritablePath(tc.path)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("assertWritablePath(%q) = %v, want nil", tc.path, err)
				}
				return
			}
			assertWritePathRejected(t, err, tc.want)
		})
	}
}

// The remaining tests drive the command handlers, which is what pins the
// guard to a position ahead of connect(): reaching Vault would fail on the
// isolated HOME long before returning this error.

func TestCmdSet_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdSet("set", "secret/foo:bar", "k=v"), "/path:key")
}

func TestCmdSet_VersionInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdSet("set", "secret/foo^2", "k=v"), "/path^version")
}

func TestCmdPaste_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdPaste("paste", "secret/foo:bar", "k=v"), "/path:key")
}

func TestCmdAsk_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdAsk("ask", "secret/foo:bar", "k=v"), "/path:key")
}

func TestCmdSsh_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdSsh("ssh", "secret/foo:private"), "/path:key")
}

// A later path in the list is checked too, so one bad argument cannot slip
// through behind a good one.
func TestCmdSsh_KeyInSecondPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdSsh("ssh", "secret/ok", "secret/foo:private"), "/path:key")
}

func TestCmdRsa_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdRsa("rsa", "secret/foo:private"), "/path:key")
}

func TestCmdDhparam_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t, c.cmdDhparam("dhparam", "secret/foo:dhparam-pem"), "/path:key")
}

// assertWritablePaths reports the first bad path and ignores empty ones, so
// an unset --signed-by does not look like a path naming nothing.
func TestAssertWritablePaths(t *testing.T) {
	t.Parallel()
	if err := assertWritablePaths("secret/ok", "", "secret/also-ok"); err != nil {
		t.Fatalf("assertWritablePaths(...) = %v, want nil", err)
	}
	assertWritePathRejected(t,
		assertWritablePaths("secret/ok", "", "secret/foo^2"), "/path^version")
	assertWritePathRejected(t,
		assertWritablePaths("secret/foo:bar", "secret/foo^2"), "/path:key")
}

// fmt names the keys it reads and writes as separate arguments. Before the
// guard, a key on the path was read as one, and the complaint that came back
// was that the key did not exist rather than that it did not belong there.
func TestCmdFmt_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t,
		c.cmdFmt("fmt", "base64", "secret/foo:bar", "pw", "b64"), "/path:key")
}

func TestCmdFmt_VersionInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t,
		c.cmdFmt("fmt", "base64", "secret/foo^2", "pw", "b64"), "/path^version")
}

// The x509 commands used to reach Vault.Write, which meant a certificate had
// already been generated by the time the path was refused.

func TestCmdX509Issue_KeyInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	c.opt.X509.Issue.Name = []string{"c.example.com"}
	assertWritePathRejected(t,
		c.cmdX509Issue("x509 issue", "secret/ca:bar"), "/path:key")
}

func TestCmdX509Issue_VersionInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	c.opt.X509.Issue.Name = []string{"c.example.com"}
	assertWritePathRejected(t,
		c.cmdX509Issue("x509 issue", "secret/ca^2"), "/path^version")
}

// Issuing writes the signing CA back as well, so --signed-by is checked too.
func TestCmdX509Issue_VersionInSignedBy_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	c.opt.X509.Issue.Name = []string{"c.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/ca^2"
	assertWritePathRejected(t,
		c.cmdX509Issue("x509 issue", "secret/cert"), "/path^version")
}

func TestCmdX509Reissue_VersionInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t,
		c.cmdX509Reissue("x509 reissue", "secret/cert^2"), "/path^version")
}

func TestCmdX509Renew_VersionInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	assertWritePathRejected(t,
		c.cmdX509Renew("x509 renew", "secret/cert^2"), "/path^version")
}

// revoke writes only the CA; the certificate it names is read for its serial.
func TestCmdX509Revoke_VersionInSignedBy_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca^2"
	assertWritePathRejected(t,
		c.cmdX509Revoke("x509 revoke", "secret/cert"), "/path^version")
}

func TestCmdX509Crl_VersionInPath_RejectedBeforeConnect(t *testing.T) {
	isolateHome(t)
	c := newWritePathCLI(t)
	c.opt.X509.CRL.Renew = true
	assertWritePathRejected(t,
		c.cmdX509Crl("x509 crl", "secret/ca^2"), "/path^version")
}
