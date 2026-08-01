package cli

// safe curl hands whatever it is given to the Vault API. What it makes of its
// arguments, and what it does with the answer, are the two things it is for.
//
// captureStdout mutates the process-global os.Stdout — do NOT add t.Parallel
// to any test in this file.

import (
	"errors"
	"strings"
	"testing"
)

// newCurlCLI builds a CLI with curl registered, so r.Usage("curl") returns a
// properly-typed error, and points it at a fake Vault holding one secret.
func newCurlCLI(t *testing.T) (*CLI, *cliFakeVault) {
	t.Helper()
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/handshake", map[string]string{"k": "v"})

	r := NewRunner()
	r.Dispatch("curl", &Help{
		Summary: "curl",
		Usage:   "safe curl [OPTIONS] METHOD REL-URI [DATA]",
		Type:    DestructiveCommand,
	}, func(cmd string, args ...string) error { return nil })

	return &CLI{opt: &Options{}, r: r}, fv
}

// A lone argument naming a method has no URI with it. It used to be taken for
// the URI, so safe curl GET asked the Vault for /v1/GET.
func TestCmdCurlRefusesAMethodWithNoURI(t *testing.T) {
	for _, arg := range []string{"GET", "get", "LIST", "delete"} {
		t.Run(arg, func(t *testing.T) {
			c, fv := newCurlCLI(t)

			err := c.cmdCurl("curl", arg)
			if err == nil {
				t.Fatalf("safe curl %s returned no error", arg)
			}
			if !strings.Contains(err.Error(), "REL-URI") {
				t.Errorf("error was %q, want it to name the missing REL-URI", err)
			}
			if reqs := fv.requests(); len(reqs) != 0 {
				t.Errorf("asked the Vault %v, want nothing asked at all", reqs)
			}
		})
	}
}

// A first argument that is not a method means the arguments are in the wrong
// order or one too many, and the request that used to go out named the URI as
// its method.
func TestCmdCurlRefusesSomethingThatIsNotAMethod(t *testing.T) {
	c, fv := newCurlCLI(t)

	err := c.cmdCurl("curl", "/secret/handshake", `{"k":"v"}`)
	if err == nil {
		t.Fatal("expected an error for a URI where a method belongs")
	}
	if !strings.Contains(err.Error(), "not an HTTP method") {
		t.Errorf("error was %q, want it to say what is wrong", err)
	}
	if !strings.Contains(err.Error(), "GET") {
		t.Errorf("error was %q, want it to name the methods that work", err)
	}
	if reqs := fv.requests(); len(reqs) != 0 {
		t.Errorf("asked the Vault %v, want nothing asked at all", reqs)
	}
}

func TestCmdCurlWithNoArgumentsIsAUsageError(t *testing.T) {
	c, _ := newCurlCLI(t)

	var usage *UsageError
	if err := c.cmdCurl("curl"); !errors.As(err, &usage) {
		t.Fatalf("error was %v, want a UsageError", err)
	}
}

// A lone URI is a GET, which is the form that made a method with no URI look
// like a URI in the first place.
func TestCmdCurlTakesALoneURIAsAGet(t *testing.T) {
	c, fv := newCurlCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdCurl("curl", "/secret/handshake"); err != nil {
			t.Fatalf("cmdCurl: %v", err)
		}
	})

	if !strings.Contains(out, `"k":"v"`) {
		t.Errorf("printed %q, want the secret the Vault answered with", out)
	}
	want := "GET /v1/secret/handshake"
	if reqs := fv.requests(); len(reqs) != 1 || reqs[0] != want {
		t.Errorf("asked the Vault %v, want [%s]", reqs, want)
	}
}

// A refused request used to leave safe exiting 0, so a script could not tell
// it from one that worked.
func TestCmdCurlFailsWhenTheVaultRefuses(t *testing.T) {
	c, _ := newCurlCLI(t)

	var err error
	out := captureStdout(t, func() { err = c.cmdCurl("curl", "GET", "/nowhere") })

	if err == nil {
		t.Fatal("a 404 from the Vault returned no error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error was %q, want it to name the status", err)
	}
	//What the Vault said is the answer to the question that was asked, and it
	// is printed whether or not the status was one safe reports as a failure.
	if !strings.Contains(out, "404") {
		t.Errorf("printed %q, want the response the Vault sent", out)
	}
}

// --data-only hides the status line, so without an exit code there is nothing
// left to say the request was refused.
func TestCmdCurlDataOnlyFailsWhenTheVaultRefuses(t *testing.T) {
	c, _ := newCurlCLI(t)
	c.opt.Curl.DataOnly = true

	var err error
	out := captureStdout(t, func() { err = c.cmdCurl("curl", "GET", "/nowhere") })

	if err == nil {
		t.Fatal("a 404 from the Vault returned no error")
	}
	if !strings.Contains(out, `"errors"`) {
		t.Errorf("printed %q, want the body the Vault sent", out)
	}
	if strings.Contains(out, "HTTP/") {
		t.Errorf("printed %q, want the body alone under --data-only", out)
	}
}

// A request the Vault answered is a success, and stays one.
func TestCmdCurlSucceedsWhenTheVaultAnswers(t *testing.T) {
	c, _ := newCurlCLI(t)

	var err error
	out := captureStdout(t, func() { err = c.cmdCurl("curl", "GET", "/secret/handshake") })

	if err != nil {
		t.Fatalf("cmdCurl: %v", err)
	}
	if !strings.Contains(out, "200 OK") {
		t.Errorf("printed %q, want the status line", out)
	}
}

// A method is sent as it is named, whatever case it was written in.
func TestCmdCurlUppercasesTheMethod(t *testing.T) {
	c, fv := newCurlCLI(t)

	captureStdout(t, func() {
		if err := c.cmdCurl("curl", "get", "/secret/handshake"); err != nil {
			t.Fatalf("cmdCurl: %v", err)
		}
	})

	want := "GET /v1/secret/handshake"
	if reqs := fv.requests(); len(reqs) != 1 || reqs[0] != want {
		t.Errorf("asked the Vault %v, want [%s]", reqs, want)
	}
}
