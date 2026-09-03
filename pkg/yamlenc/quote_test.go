// pkg/yamlenc/quote_test.go
package yamlenc

import (
	"testing"

	"github.com/goccy/go-yaml"
)

// Each row is a string a Vault secret could hold. quoted says whether
// needsQuote must fire. Every row, quoted or not, must round-trip through
// Marshal and goccy's decoder as the identical string, never as a number,
// bool, or null. The rows that goccy alone gets wrong are marked.
var quoteCases = []struct {
	name   string
	in     string
	quoted bool
}{
	{"NULL", "NULL", true},
	{"amp", "&foo", true},
	{"apos", "it's a secret", false},
	{"at", "@x", true},
	{"b64", "aGVsbG8gd29ybGQ=", false},
	{"backtick", "`x", true},
	{"bang", "!x", true},
	{"big", "18446744073709551616", true},
	{"binish", "0b101", true},
	{"bom", "\ufeffx", true},
	{"bool", "true", true},
	{"brace", "{a}", true},
	{"bracket", "[a]", true},
	{"bs", "a\\b", false},
	{"bslash", "C:\\path\\x", false},
	{"bsn", "a\\nb", false},
	{"cert", "-----BEGIN CERTIFICATE-----\nMIIB\nAAAA\n-----END CERTIFICATE-----\n", false},
	{"clever", "is clever", false},
	{"colon", "a: b", true},
	{"colonend", "a:", true},
	{"colonspace", ":x", false},
	{"colonword", ":foo", false},
	{"cr", "a\rb", true},     // goccy alone drops the \r
	{"crlf", "a\r\nb", true}, // goccy alone drops the \r
	{"ctrl", "a\x01b", true},
	{"dash", "- x", true},
	{"dashonly", "-", true},
	{"date", "2026-09-03", true},
	{"del", "a\x7fb", true},
	{"doc", "---\nx", false},
	{"docend", "...", true},
	{"dotend", "1.", true},
	{"dotstart", ".5", true},
	{"dq", "say \"hi\"", false},
	{"email", "a@b.c", false},
	{"emoji", "🔑", false},
	{"empty", "", true},
	{"exp", "1e3", true}, // goccy alone emits a float
	{"float", "1.5", true},
	{"gt", ">x", true},
	{"hash", "a #b", true},
	{"hashonly", "#", true},
	{"hex", "0x1f", true},
	{"hexpw", "deadbeef", false},
	{"hexpw2", "0xdeadbeef", true},
	{"hyphen", "-foo", false},
	{"inf", ".inf", true}, // goccy alone emits a float
	{"ip", "10.0.0.1", false},
	{"json", "{\"a\":1}", true},
	{"kv", "a=b", false},
	{"lead", " leading", true},
	{"leadnl", "\na", true},
	{"long", "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789 abcdefghij abcdefghij abcdefghij", false},
	{"lsep", "a\u2028b", true},
	{"minus", "-", true},
	{"mixed", "123abc", false},
	{"mixedq", "it's \"x\"", false},
	{"multi", "line1\nline2\n", false},
	{"multi2", "line1\nline2", false},
	{"multiblank", "a\n\nb\n", false},
	{"multiend", "a\nb\n\n\n", true}, // goccy alone loses trailing newlines
	{"multilead", "  a\nb", false},
	{"multitab", "a\n\tb\n", true},
	{"multitrail", "a \nb", true},
	{"multitrail2", "a\nb  \n", true}, // goccy alone drops the spaces
	{"multitrailend", "a\nb ", true},  // goccy alone drops the space
	{"multiws", "a\n  b\n", false},
	{"multiwsline", "a\n   \nb", true}, // goccy alone drops the spaces
	{"n", "n", true},
	{"nan", ".nan", true}, // goccy alone emits a float
	{"nbsp", "a\u00a0b", false},
	{"neg", "-1", true},
	{"negfloat", "-1.5", true},
	{"nl", "\n", true}, // goccy alone emits an empty block
	{"nlnl", "\n\n", true},
	{"null", "null", true},
	{"num", "123", true},
	{"oct", "0755", true},
	{"octish", "0123", true},
	{"off", "off", true},
	{"on", "on", true},
	{"password", "s3cr3t!", false},
	{"path", "/var/lib/x", false},
	{"pct", "%x", true},
	{"pemcrlf", "-----BEGIN-----\r\nAAA\r\n-----END-----\r\n", true},
	{"pipe", "|x", true},
	{"plus", "+1", true},
	{"port", "8200", true},
	{"qmark", "? x", true}, // goccy alone emits invalid YAML
	{"qonly", "?", true},
	{"quote", "\"q\"", true},
	{"sci", "6.02e23", true},
	{"sexa", "1:30", true},
	{"spaces", "  ", true},
	{"squote", "'q'", true},
	{"ssh", "ssh-rsa AAAAB3Nza user@host", false},
	{"star", "*foo", true},
	{"tab", "a\tb", true},     // goccy alone collapses the tab
	{"tabstart", "\tx", true}, // goccy alone drops the tab
	{"tilde", "~", true},
	{"time", "2026-09-03T11:00:00Z", true},
	{"trail", "trailing ", true},
	{"trailnl2", "a\n\n", true}, // goccy alone loses a newline
	{"under", "1_000", true},
	{"uni", "héllo ✓", false},
	{"url", "https://vault.example.com:8200/v1/secret", false},
	{"uuid", "0a1b2c3d-1111-2222-3333-444455556666", false},
	{"ver", "1.2.3", false},
	{"y", "y", true},
	{"yes", "yes", true},
	{"zero", "0", true},
}

func TestNeedsQuote(t *testing.T) {
	for _, tc := range quoteCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsQuote(tc.in); got != tc.quoted {
				t.Errorf("needsQuote(%q) = %v, want %v", tc.in, got, tc.quoted)
			}
		})
	}
}

// Marshal must produce YAML that decodes back to the identical Go string,
// with the string type intact, for every probe value.
func TestMarshalRoundTripsStrings(t *testing.T) {
	for _, tc := range quoteCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Marshal(map[string]string{"k": tc.in})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var back map[string]any
			if err := yaml.Unmarshal(out, &back); err != nil {
				t.Fatalf("output does not parse: %v\n%s", err, out)
			}
			got, ok := back["k"].(string)
			if !ok {
				t.Fatalf("value decoded as %T (%v), want string\n%s", back["k"], back["k"], out)
			}
			if got != tc.in {
				t.Errorf("round trip changed the value:\n got %q\nwant %q\nyaml:\n%s", got, tc.in, out)
			}
		})
	}
}

// Map keys go through the same rule, so a key spelled like a bool or a
// number stays a string too.
func TestMarshalQuotesRiskyKeys(t *testing.T) {
	out, err := Marshal(map[string]string{"123": "x", "yes": "y", "plain": "z"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "\"123\": x\nplain: z\n\"yes\": \"y\"\n"
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}
