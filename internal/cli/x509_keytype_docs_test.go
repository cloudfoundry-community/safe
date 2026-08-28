package cli

// The default key type stays RSA-4096 -- changing it out from under
// existing users is a compatibility and security-posture decision safe does
// not make for them. What the help for issue and reissue does instead is
// hand the lever over: it names the fast key types and their approximate
// cost, and says that reissue keeps the existing key's parameters unless
// told otherwise, so a certificate born RSA-4096 does not pay seconds of
// key generation forever out of silence.

import (
	"strings"
	"testing"
)

func TestIssueHelpNamesTheFastKeyTypes(t *testing.T) {
	stdout, _, status := run(t, "help", "x509", "issue")
	if status != 0 {
		t.Fatalf("safe help x509 issue exited %d, want 0", status)
	}
	for _, want := range []string{"--type ec", "--type ed25519", "microseconds"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("issue help does not mention %q:\n%s", want, stdout)
		}
	}
}

func TestReissueHelpSaysKeyParametersArePreserved(t *testing.T) {
	stdout, _, status := run(t, "help", "x509", "reissue")
	if status != 0 {
		t.Fatalf("safe help x509 reissue exited %d, want 0", status)
	}
	for _, want := range []string{
		"preserves the existing key's type",
		"--type ec",
		"--type ed25519",
		"microseconds",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("reissue help does not mention %q:\n%s", want, stdout)
		}
	}
}
