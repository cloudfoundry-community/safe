// Package vault white-box tests for ParseSubject regression and edge cases
// not already present in x509_test.go (which covers the main table).
// These tests focus on the panic-regression for empty input and additional
// formatting variants.
package vault

import (
	"strings"
	"testing"
)

// TestParseSubjectEmptyNoPanic is the regression guard: ParseSubject("") must
// return a non-nil error and must NOT panic. This was a real bug.
func TestParseSubjectEmptyNoPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseSubject(\"\") panicked: %v", r)
		}
	}()

	_, err := ParseSubject("")
	if err == nil {
		t.Error("ParseSubject(\"\") returned nil error; want non-nil")
	}
}

// TestParseSubjectSlashPrefix covers the "/" prefix path and verifies
// each field is populated correctly.
func TestParseSubjectSlashPrefix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		in     string
		wantCN string
		wantC  string
		wantST string
		wantL  string
		wantO  string
		wantOU string
	}{
		{
			name:   "full slash subject",
			in:     "/cn=host.example.com/c=us/st=California/l=San Francisco/o=Acme Corp/ou=Engineering",
			wantCN: "host.example.com",
			wantC:  "us",
			wantST: "California",
			wantL:  "San Francisco",
			wantO:  "Acme Corp",
			wantOU: "Engineering",
		},
		{
			name:   "slash cn only",
			in:     "/cn=bare-cn",
			wantCN: "bare-cn",
		},
		{
			name:   "slash uppercase fields",
			in:     "/CN=Upper/C=GB/ST=England/L=London/O=Big Co/OU=Dev",
			wantCN: "Upper",
			wantC:  "GB",
			wantST: "England",
			wantL:  "London",
			wantO:  "Big Co",
			wantOU: "Dev",
		},
		{
			name:   "slash lowercase fields",
			in:     "/cn=lower/c=fr/st=IDF/l=Paris/o=Societe/ou=Prod",
			wantCN: "lower",
			wantC:  "fr",
			wantST: "IDF",
			wantL:  "Paris",
			wantO:  "Societe",
			wantOU: "Prod",
		},
		{
			name:   "value with ampersand",
			in:     "/cn=x/o=stark & wayne",
			wantCN: "x",
			wantO:  "stark & wayne",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSubject(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.CommonName != tc.wantCN {
				t.Errorf("CN: got %q, want %q", got.CommonName, tc.wantCN)
			}
			if tc.wantC != "" {
				if len(got.Country) == 0 || got.Country[0] != tc.wantC {
					t.Errorf("C: got %v, want [%q]", got.Country, tc.wantC)
				}
			}
			if tc.wantST != "" {
				if len(got.Province) == 0 || got.Province[0] != tc.wantST {
					t.Errorf("ST: got %v, want [%q]", got.Province, tc.wantST)
				}
			}
			if tc.wantL != "" {
				if len(got.Locality) == 0 || got.Locality[0] != tc.wantL {
					t.Errorf("L: got %v, want [%q]", got.Locality, tc.wantL)
				}
			}
			if tc.wantO != "" {
				if len(got.Organization) == 0 || got.Organization[0] != tc.wantO {
					t.Errorf("O: got %v, want [%q]", got.Organization, tc.wantO)
				}
			}
			if tc.wantOU != "" {
				if len(got.OrganizationalUnit) == 0 || got.OrganizationalUnit[0] != tc.wantOU {
					t.Errorf("OU: got %v, want [%q]", got.OrganizationalUnit, tc.wantOU)
				}
			}
		})
	}
}

// TestParseSubjectCommaSeparated covers the comma-separated (non-"/"-prefixed)
// form, including spaces around the "=" sign.
func TestParseSubjectCommaSeparated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		wantCN  string
		wantErr bool
	}{
		{
			name:   "standard comma form",
			in:     "CN=myhost.example.com,C=DE,ST=Bayern,L=Munich,O=Test GmbH,OU=IT",
			wantCN: "myhost.example.com",
		},
		{
			name:   "spaces around equals",
			in:     "CN = spaced.host,C=us",
			wantCN: "spaced.host",
		},
		{
			name:   "lowercase comma form",
			in:     "cn=lower.host,c=au,o=Org",
			wantCN: "lower.host",
		},
		{
			name:    "duplicate CN comma form",
			in:      "CN=first,CN=second",
			wantErr: true,
		},
		{
			name:    "unknown field comma form",
			in:      "CN=x,DC=example",
			wantErr: true,
		},
		{
			name:    "no equals sign",
			in:      "CNnoequalssign",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseSubject(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (name=%+v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.CommonName != tc.wantCN {
				t.Errorf("CN: got %q, want %q", got.CommonName, tc.wantCN)
			}
		})
	}
}

// TestParseSubjectMultiValue verifies multi-value O and OU fields accumulate
// correctly under the slash form.
func TestParseSubjectMultiValue(t *testing.T) {
	t.Parallel()

	got, err := ParseSubject("/cn=x/o=alpha/o=beta/ou=team-a/ou=team-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CommonName != "x" {
		t.Errorf("CN: got %q, want x", got.CommonName)
	}
	if len(got.Organization) != 2 || got.Organization[0] != "alpha" || got.Organization[1] != "beta" {
		t.Errorf("Organization: got %v, want [alpha beta]", got.Organization)
	}
	if len(got.OrganizationalUnit) != 2 || got.OrganizationalUnit[0] != "team-a" || got.OrganizationalUnit[1] != "team-b" {
		t.Errorf("OrganizationalUnit: got %v, want [team-a team-b]", got.OrganizationalUnit)
	}
}

// TestParseSubjectUnknownComponentError verifies the error message includes the
// unrecognized component name so operators can diagnose typos.
func TestParseSubjectUnknownComponentError(t *testing.T) {
	t.Parallel()

	_, err := ParseSubject("/cn=foo/dc=example")
	if err == nil {
		t.Fatal("expected error for unknown dc= component, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "dc") {
		t.Errorf("error message %q does not mention unknown component 'dc'", msg)
	}
}
