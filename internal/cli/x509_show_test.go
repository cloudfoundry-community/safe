package cli

// `safe x509 show' reports how much life a certificate has left. The report
// was built from the number of whole days between now and the dates on the
// certificate, and a day that is not yet whole counts as none: a certificate
// with hours left to run was reported EXPIRED, and one that had not come into
// force yet was reported as though it had.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// showCert builds a certificate whose validity window is exactly the one the
// test names. The window is set after signing, which is what a certificate
// read back out of Vault presents.
func showCert(t *testing.T, notBefore, notAfter time.Time) *vault.X509 {
	t.Helper()
	cert := signedCert(t, "CN=leaf.example.com", []string{"leaf.example.com"}, false)
	cert.Certificate.Issuer = cert.Certificate.Subject
	cert.Certificate.NotBefore = notBefore
	cert.Certificate.NotAfter = notAfter
	return cert
}

func showOutput(t *testing.T, cert *vault.X509) string {
	t.Helper()
	var buf bytes.Buffer
	printX509(&buf, cert)
	return buf.String()
}

func TestPrintX509_ReportsWhatIsLeftOfTheValidityWindow(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      string
		notWant   string
	}{
		{
			name:      "expired three days ago",
			notBefore: now.Add(-10 * day),
			notAfter:  now.Add(-3 * day),
			want:      "EXPIRED 3 days ago",
		},
		{
			name:      "expired a day and a half ago",
			notBefore: now.Add(-10 * day),
			notAfter:  now.Add(-36 * time.Hour),
			want:      "EXPIRED a day ago",
		},
		{
			name:      "expired this morning",
			notBefore: now.Add(-10 * day),
			notAfter:  now.Add(-2 * time.Hour),
			want:      "EXPIRED",
			notWant:   "ago",
		},
		{
			//The case a whole-day count cannot tell from an expired
			// certificate: still valid, and out of days.
			name:      "expires within the day",
			notBefore: now.Add(-10 * day),
			notAfter:  now.Add(12 * time.Hour),
			want:      "expires in less than a day",
			notWant:   "EXPIRED",
		},
		{
			name:      "expires tomorrow",
			notBefore: now.Add(-10 * day),
			notAfter:  now.Add(30 * time.Hour),
			want:      "expires in a day",
		},
		{
			name:      "expires in a fortnight",
			notBefore: now.Add(-day),
			notAfter:  now.Add(14 * day),
			want:      "expires in 14 days",
		},
		{
			name:      "expires well after the warning window",
			notBefore: now.Add(-day),
			notAfter:  now.Add(400 * day),
			want:      "expires in 400 days",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := showOutput(t, showCert(t, tc.notBefore, tc.notAfter))
			if !strings.Contains(out, tc.want) {
				t.Errorf("output should report %q\n---\n%s", tc.want, out)
			}
			if tc.notWant != "" && strings.Contains(out, tc.notWant) {
				t.Errorf("output should not say %q\n---\n%s", tc.notWant, out)
			}
		})
	}
}

func TestPrintX509_ReportsACertificateThatIsNotInForceYet(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		want      string
	}{
		{
			name:      "comes into force in three days",
			notBefore: now.Add(3 * day),
			want:      "not valid for another 3 days",
		},
		{
			name:      "comes into force tomorrow",
			notBefore: now.Add(30 * time.Hour),
			want:      "not valid for another day",
		},
		{
			//A wait shorter than a day rounded to no days at all, and
			// nothing was said about it: the certificate read as usable.
			name:      "comes into force this afternoon",
			notBefore: now.Add(12 * time.Hour),
			want:      "not valid yet",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := showOutput(t, showCert(t, tc.notBefore, now.Add(100*day)))
			if !strings.Contains(out, tc.want) {
				t.Errorf("output should report %q\n---\n%s", tc.want, out)
			}
		})
	}
}

// A certificate already in force says nothing about coming into force.
func TestPrintX509_SaysNothingAboutForceForACertificateInForce(t *testing.T) {
	now := time.Now()
	out := showOutput(t, showCert(t, now.Add(-day), now.Add(100*day)))
	if strings.Contains(out, "not valid") {
		t.Errorf("output should not talk about validity starting\n---\n%s", out)
	}
}
