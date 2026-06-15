package vault

import (
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// CategorizeSANs
// ---------------------------------------------------------------------------

func TestCategorizeSANs(t *testing.T) {
	tests := []struct {
		name        string
		in          []string
		wantIPs     []string
		wantDomains []string
		wantEmails  []string
	}{
		{
			name:        "empty input",
			in:          []string{},
			wantIPs:     []string{},
			wantDomains: []string{},
			wantEmails:  []string{},
		},
		{
			name:        "single IPv4",
			in:          []string{"10.0.0.1"},
			wantIPs:     []string{"10.0.0.1"},
			wantDomains: []string{},
			wantEmails:  []string{},
		},
		{
			name:        "single IPv6",
			in:          []string{"::1"},
			wantIPs:     []string{"::1"},
			wantDomains: []string{},
			wantEmails:  []string{},
		},
		{
			name:        "single domain",
			in:          []string{"example.com"},
			wantIPs:     []string{},
			wantDomains: []string{"example.com"},
			wantEmails:  []string{},
		},
		{
			name:        "single email",
			in:          []string{"user@example.com"},
			wantIPs:     []string{},
			wantDomains: []string{},
			wantEmails:  []string{"user@example.com"},
		},
		{
			name:        "mixed types",
			in:          []string{"192.168.1.1", "foo.example.com", "admin@corp.io", "2001:db8::1"},
			wantIPs:     []string{"192.168.1.1", "2001:db8::1"},
			wantDomains: []string{"foo.example.com"},
			wantEmails:  []string{"admin@corp.io"},
		},
		{
			name: "at-sign at position 0 treated as domain (strings.Index > 0 check)",
			// "@foo" has Index('@') == 0, which is NOT > 0, so goes to domains
			in:          []string{"@foo"},
			wantIPs:     []string{},
			wantDomains: []string{"@foo"},
			wantEmails:  []string{},
		},
		{
			name:        "wildcard domain not an IP",
			in:          []string{"*.internal.example.com"},
			wantIPs:     []string{},
			wantDomains: []string{"*.internal.example.com"},
			wantEmails:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, domains, emails := CategorizeSANs(tt.in)

			if len(ips) != len(tt.wantIPs) {
				t.Fatalf("ips len: got %d, want %d", len(ips), len(tt.wantIPs))
			}
			for i, ip := range ips {
				if ip.String() != tt.wantIPs[i] {
					t.Errorf("ips[%d]: got %s, want %s", i, ip, tt.wantIPs[i])
				}
			}

			if len(domains) != len(tt.wantDomains) {
				t.Fatalf("domains len: got %d, want %d", len(domains), len(tt.wantDomains))
			}
			for i, d := range domains {
				if d != tt.wantDomains[i] {
					t.Errorf("domains[%d]: got %s, want %s", i, d, tt.wantDomains[i])
				}
			}

			if len(emails) != len(tt.wantEmails) {
				t.Fatalf("emails len: got %d, want %d", len(emails), len(tt.wantEmails))
			}
			for i, e := range emails {
				if e != tt.wantEmails[i] {
					t.Errorf("emails[%d]: got %s, want %s", i, e, tt.wantEmails[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isNoKeyUsage
// ---------------------------------------------------------------------------

func TestIsNoKeyUsage(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"none", true},
		{"no", true},
		{"yes", false},
		{"", false},
		{"NONE", false}, // case-sensitive
		{"digital_signature", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := isNoKeyUsage(tt.in)
			if got != tt.want {
				t.Errorf("isNoKeyUsage(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HandleJointKeyUsages
// ---------------------------------------------------------------------------

func TestHandleJointKeyUsages(t *testing.T) {
	tests := []struct {
		name    string
		usages  []string
		wantKU  x509.KeyUsage
		wantEKU []x509.ExtKeyUsage
		wantErr bool
	}{
		{
			name:    "empty list",
			usages:  []string{},
			wantKU:  0,
			wantEKU: nil,
			wantErr: false,
		},
		{
			name:    "none alone",
			usages:  []string{"none"},
			wantKU:  0,
			wantEKU: nil,
			wantErr: false,
		},
		{
			name:    "no alone",
			usages:  []string{"no"},
			wantKU:  0,
			wantEKU: nil,
			wantErr: false,
		},
		{
			name:    "none combined with real usage errors",
			usages:  []string{"none", "digital_signature"},
			wantErr: true,
		},
		{
			name:   "single key usage digital_signature",
			usages: []string{"digital_signature"},
			wantKU: x509.KeyUsageDigitalSignature,
		},
		{
			name:   "key_cert_sign",
			usages: []string{"key_cert_sign"},
			wantKU: x509.KeyUsageCertSign,
		},
		{
			name:   "crl_sign",
			usages: []string{"crl_sign"},
			wantKU: x509.KeyUsageCRLSign,
		},
		{
			name:    "single ext key usage server_auth",
			usages:  []string{"server_auth"},
			wantEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:    "single ext key usage client_auth",
			usages:  []string{"client_auth"},
			wantEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		{
			name:    "mixed key and ext key usages",
			usages:  []string{"digital_signature", "key_encipherment", "server_auth"},
			wantKU:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			wantEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:    "normalization: dashes and spaces become underscores",
			usages:  []string{"digital-signature", "server auth"},
			wantKU:  x509.KeyUsageDigitalSignature,
			wantEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		{
			name:    "deduplication: duplicate entries treated once",
			usages:  []string{"digital_signature", "digital_signature"},
			wantKU:  x509.KeyUsageDigitalSignature,
			wantEKU: nil,
		},
		{
			name:    "unknown usage returns error",
			usages:  []string{"fly_to_the_moon"},
			wantErr: true,
		},
		{
			name:    "content_commitment alias for non_repudiation",
			usages:  []string{"content_commitment"},
			wantKU:  x509.KeyUsageContentCommitment,
			wantEKU: nil,
		},
		{
			name:    "non_repudiation alias",
			usages:  []string{"non_repudiation"},
			wantKU:  x509.KeyUsageContentCommitment,
			wantEKU: nil,
		},
		{
			name:    "all ext key usages",
			usages:  []string{"client_auth", "server_auth", "code_signing", "email_protection", "timestamping"},
			wantEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageTimeStamping},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ku, eku, err := HandleJointKeyUsages(tt.usages)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ku != tt.wantKU {
				t.Errorf("KeyUsage: got %v, want %v", ku, tt.wantKU)
			}
			if len(eku) != len(tt.wantEKU) {
				t.Errorf("ExtKeyUsage len: got %d, want %d (got %v, want %v)", len(eku), len(tt.wantEKU), eku, tt.wantEKU)
				return
			}
			// The function sorts usages before processing, so ext key usages come back
			// in alphabetical order of the usage string.
			for i := range eku {
				if eku[i] != tt.wantEKU[i] {
					t.Errorf("ExtKeyUsage[%d]: got %v, want %v", i, eku[i], tt.wantEKU[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TranslateSignatureAlgorithm
// ---------------------------------------------------------------------------

func TestTranslateSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		in      string
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{"sha256", x509.SHA256WithRSA, false},
		{"sha256-rsa", x509.SHA256WithRSA, false},
		{"sha384", x509.SHA384WithRSA, false},
		{"sha512", x509.SHA512WithRSA, false},
		{"sha1", x509.SHA1WithRSA, false},
		{"md5", x509.MD5WithRSA, false},
		{"sha256-rsapss", x509.SHA256WithRSAPSS, false},
		{"sha384-rsapss", x509.SHA384WithRSAPSS, false},
		{"sha512-rsapss", x509.SHA512WithRSAPSS, false},
		{"ecdsa-sha256", x509.ECDSAWithSHA256, false},
		{"ecdsa-sha384", x509.ECDSAWithSHA384, false},
		{"ecdsa-sha512", x509.ECDSAWithSHA512, false},
		{"ecdsa-sha1", x509.ECDSAWithSHA1, false},
		{"dsa-sha1", x509.DSAWithSHA1, false},
		{"dsa-sha256", x509.DSAWithSHA256, false},
		{"bogus-algo", x509.UnknownSignatureAlgorithm, true},
		{"", x509.UnknownSignatureAlgorithm, true},
		{"SHA256", x509.UnknownSignatureAlgorithm, true}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := TranslateSignatureAlgorithm(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil (algo=%v)", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("TranslateSignatureAlgorithm(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseSubject
// ---------------------------------------------------------------------------

func TestParseSubject(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantCN  string
		wantC   []string
		wantST  []string
		wantL   []string
		wantO   []string
		wantOU  []string
		wantErr bool
	}{
		{
			name:   "slash-delimited full subject",
			in:     "/cn=foo.bar/c=us/st=ny/l=buffalo/o=stark & wayne/ou=r&d",
			wantCN: "foo.bar",
			wantC:  []string{"us"},
			wantST: []string{"ny"},
			wantL:  []string{"buffalo"},
			wantO:  []string{"stark & wayne"},
			wantOU: []string{"r&d"},
		},
		{
			name:   "comma-delimited full subject",
			in:     "CN=foo.bl,C=us,ST=ny,L=buffalo,O=stark & wayne,OU=r&d",
			wantCN: "foo.bl",
			wantC:  []string{"us"},
			wantST: []string{"ny"},
			wantL:  []string{"buffalo"},
			wantO:  []string{"stark & wayne"},
			wantOU: []string{"r&d"},
		},
		{
			name:   "lowercase comma-delimited",
			in:     "cn=myhost.example.com,c=de,o=my org",
			wantCN: "myhost.example.com",
			wantC:  []string{"de"},
			wantO:  []string{"my org"},
		},
		{
			name:   "cn only slash style",
			in:     "/cn=just.a.host",
			wantCN: "just.a.host",
		},
		{
			name:   "multiple o and ou",
			in:     "/cn=x/o=acme/o=corp/ou=eng/ou=ops",
			wantCN: "x",
			wantO:  []string{"acme", "corp"},
			wantOU: []string{"eng", "ops"},
		},
		{
			name:    "duplicate CN errors",
			in:      "/cn=first/cn=second",
			wantErr: true,
		},
		{
			name:    "unknown component errors",
			in:      "/cn=foo/dc=example",
			wantErr: true,
		},
		{
			name:    "malformed pair no equals",
			in:      "cnfoo",
			wantErr: true,
		},
		{
			name:   "spaces around equals allowed",
			in:     "cn = mysite.io,c=us",
			wantCN: "mysite.io",
			wantC:  []string{"us"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := ParseSubject(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (name=%+v)", name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if name.CommonName != tt.wantCN {
				t.Errorf("CommonName: got %q, want %q", name.CommonName, tt.wantCN)
			}
			checkStringSlice(t, "Country", name.Country, tt.wantC)
			checkStringSlice(t, "Province", name.Province, tt.wantST)
			checkStringSlice(t, "Locality", name.Locality, tt.wantL)
			checkStringSlice(t, "Organization", name.Organization, tt.wantO)
			checkStringSlice(t, "OrganizationalUnit", name.OrganizationalUnit, tt.wantOU)
		})
	}
}

func checkStringSlice(t *testing.T, field string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: len got %d, want %d (got=%v, want=%v)", field, len(got), len(want), got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d]: got %q, want %q", field, i, got[i], want[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers to build minimal X509 structs for method tests (no network/Vault).
// ---------------------------------------------------------------------------

func makeX509WithSANs(ips []net.IP, domains, emails []string) *X509 {
	return &X509{
		Certificate: &x509.Certificate{
			IPAddresses:    ips,
			DNSNames:       domains,
			EmailAddresses: emails,
		},
	}
}

// ---------------------------------------------------------------------------
// ValidForIP
// ---------------------------------------------------------------------------

func TestX509ValidForIP(t *testing.T) {
	tests := []struct {
		name      string
		certIPs   []net.IP
		checkIP   net.IP
		wantValid bool
	}{
		{
			name:      "exact IPv4 match",
			certIPs:   []net.IP{net.ParseIP("10.0.0.1")},
			checkIP:   net.ParseIP("10.0.0.1"),
			wantValid: true,
		},
		{
			name:      "IPv4 not in cert",
			certIPs:   []net.IP{net.ParseIP("10.0.0.1")},
			checkIP:   net.ParseIP("10.0.0.2"),
			wantValid: false,
		},
		{
			name:      "empty cert IPs",
			certIPs:   []net.IP{},
			checkIP:   net.ParseIP("1.2.3.4"),
			wantValid: false,
		},
		{
			name:      "IPv6 match",
			certIPs:   []net.IP{net.ParseIP("::1")},
			checkIP:   net.ParseIP("::1"),
			wantValid: true,
		},
		{
			name:      "multiple IPs, second matches",
			certIPs:   []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
			checkIP:   net.ParseIP("10.0.0.2"),
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := makeX509WithSANs(tt.certIPs, nil, nil)
			got := x.ValidForIP(tt.checkIP)
			if got != tt.wantValid {
				t.Errorf("ValidForIP(%s) = %v, want %v", tt.checkIP, got, tt.wantValid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidForDomain
// ---------------------------------------------------------------------------

func TestX509ValidForDomain(t *testing.T) {
	tests := []struct {
		name      string
		certDNS   []string
		checkDom  string
		wantValid bool
	}{
		{
			name:      "exact match",
			certDNS:   []string{"example.com"},
			checkDom:  "example.com",
			wantValid: true,
		},
		{
			name:      "no match",
			certDNS:   []string{"example.com"},
			checkDom:  "other.com",
			wantValid: false,
		},
		{
			name:      "empty cert domains",
			certDNS:   []string{},
			checkDom:  "example.com",
			wantValid: false,
		},
		{
			name:      "wildcard matches one level deep",
			certDNS:   []string{"*.example.com"},
			checkDom:  "foo.example.com",
			wantValid: true,
		},
		{
			name:      "wildcard does not match two levels deep",
			certDNS:   []string{"*.example.com"},
			checkDom:  "foo.bar.example.com",
			wantValid: false,
		},
		{
			name:      "wildcard does not match apex",
			certDNS:   []string{"*.example.com"},
			checkDom:  "example.com",
			wantValid: false,
		},
		{
			name:      "multiple domains second matches",
			certDNS:   []string{"foo.com", "bar.com"},
			checkDom:  "bar.com",
			wantValid: true,
		},
		{
			name:      "wildcard matches another subdomain",
			certDNS:   []string{"*.internal.corp"},
			checkDom:  "api.internal.corp",
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := makeX509WithSANs(nil, tt.certDNS, nil)
			got := x.ValidForDomain(tt.checkDom)
			if got != tt.wantValid {
				t.Errorf("ValidForDomain(%q) = %v, want %v", tt.checkDom, got, tt.wantValid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ValidForEmail
// ---------------------------------------------------------------------------

func TestX509ValidForEmail(t *testing.T) {
	tests := []struct {
		name       string
		certEmails []string
		checkEmail string
		wantValid  bool
	}{
		{
			name:       "exact match",
			certEmails: []string{"user@example.com"},
			checkEmail: "user@example.com",
			wantValid:  true,
		},
		{
			name:       "no match",
			certEmails: []string{"other@example.com"},
			checkEmail: "user@example.com",
			wantValid:  false,
		},
		{
			name:       "empty cert emails",
			certEmails: []string{},
			checkEmail: "user@example.com",
			wantValid:  false,
		},
		{
			name:       "case-sensitive mismatch",
			certEmails: []string{"User@example.com"},
			checkEmail: "user@example.com",
			wantValid:  false,
		},
		{
			name:       "multiple emails second matches",
			certEmails: []string{"a@b.com", "c@d.com"},
			checkEmail: "c@d.com",
			wantValid:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := makeX509WithSANs(nil, nil, tt.certEmails)
			got := x.ValidForEmail(tt.checkEmail)
			if got != tt.wantValid {
				t.Errorf("ValidForEmail(%q) = %v, want %v", tt.checkEmail, got, tt.wantValid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FormatSerial
// ---------------------------------------------------------------------------

func TestX509FormatSerial(t *testing.T) {
	tests := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{
			name:   "serial zero",
			serial: big.NewInt(0),
			want:   "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
		},
		{
			name:   "serial one",
			serial: big.NewInt(1),
			want:   "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01",
		},
		{
			name:   "serial 255 (ff)",
			serial: big.NewInt(255),
			want:   "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:ff",
		},
		{
			name:   "serial 256 (0100)",
			serial: big.NewInt(256),
			want:   "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01:00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &X509{
				Certificate: &x509.Certificate{
					SerialNumber: tt.serial,
				},
			}
			got := x.FormatSerial()
			if got != tt.want {
				t.Errorf("FormatSerial() = %q, want %q", got, tt.want)
			}
			// Output must be exactly 59 chars: 20 hex pairs joined by colons.
			if len(got) != 59 {
				t.Errorf("FormatSerial() len = %d, want 59", len(got))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ExpiryString
// ---------------------------------------------------------------------------

func TestX509ExpiryString(t *testing.T) {
	loc := time.UTC
	tests := []struct {
		name     string
		notAfter time.Time
		wantFmt  string
	}{
		{
			name:     "known date",
			notAfter: time.Date(2025, time.December, 31, 23, 59, 0, 0, loc),
			wantFmt:  "Dec 31 2025 23:59 UTC",
		},
		{
			name:     "epoch",
			notAfter: time.Unix(0, 0).UTC(),
			wantFmt:  "Jan 01 1970 00:00 UTC",
		},
		{
			name:     "leap day",
			notAfter: time.Date(2024, time.February, 29, 12, 0, 0, 0, loc),
			wantFmt:  "Feb 29 2024 12:00 UTC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &X509{
				Certificate: &x509.Certificate{
					NotAfter: tt.notAfter,
				},
			}
			got := x.ExpiryString()
			if got != tt.wantFmt {
				t.Errorf("ExpiryString() = %q, want %q", got, tt.wantFmt)
			}
		})
	}
}
