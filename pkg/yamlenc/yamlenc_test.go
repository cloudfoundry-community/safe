// pkg/yamlenc/yamlenc_test.go
package yamlenc

import (
	"strings"
	"testing"
)

// The struct shapes pkg/rc writes must come out exactly as the previous
// encoder wrote them; tags, field order, omitempty, and nested maps.
func TestMarshalStructMatchesPreviousEncoder(t *testing.T) {
	type vault struct {
		URL        string   `yaml:"url"`
		Token      string   `yaml:"token"`
		CACerts    []string `yaml:"ca_certs,omitempty"`
		SkipVerify bool     `yaml:"skip_verify,omitempty"`
		Namespace  string   `yaml:"namespace,omitempty"`
	}
	type config struct {
		Version int               `yaml:"version"`
		Current string            `yaml:"current"`
		Vaults  map[string]*vault `yaml:"vaults"`
	}
	out, err := Marshal(config{
		Version: 1,
		Current: "prod",
		Vaults: map[string]*vault{
			"prod": {URL: "https://v:8200", Token: "s.abc", CACerts: []string{"-----BEGIN-----\nAAA\n-----END-----\n"}, SkipVerify: true},
			"dev":  {URL: "http://127.0.0.1:8200"},
			"gone": nil,
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `version: 1
current: prod
vaults:
  dev:
    url: http://127.0.0.1:8200
    token: ""
  gone: null
  prod:
    url: https://v:8200
    token: s.abc
    ca_certs:
    - |
      -----BEGIN-----
      AAA
      -----END-----
    skip_verify: true
`
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

// safe get prints {path: {key: value}}; keys sort, values quote per rule.
func TestMarshalNestedMap(t *testing.T) {
	out, err := Marshal(map[string]map[string]string{
		"secret/b": {"k": "v"},
		"secret/a": {"z": "1", "a": "? x", "m": "plain text"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "secret/a:\n  a: \"? x\"\n  m: plain text\n  z: \"1\"\nsecret/b:\n  k: v\n"
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

// safe get -K prints {path: [keys]} with an unindented block sequence.
func TestMarshalKeysList(t *testing.T) {
	out, err := Marshal(map[string][]string{"secret/x": {"a", "b"}, "secret/y": {}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "secret/x:\n- a\n- b\nsecret/y: []\n"
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

// An empty map is "{}\n"; Secret.YAML relies on a non-empty result.
func TestMarshalEmptyMap(t *testing.T) {
	out, err := Marshal(map[string]string{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != "{}\n" {
		t.Errorf("got %q, want %q", out, "{}\n")
	}
}

// The parse error we hand to users must not carry the source excerpt; the
// line next to a syntax error in ~/.saferc is often the token.
func TestErrorMessageOmitsSourceExcerpt(t *testing.T) {
	var v struct {
		Vaults map[string]struct {
			Token string `yaml:"token"`
			URL   string `yaml:"url"`
		} `yaml:"vaults"`
	}
	err := Unmarshal([]byte("vaults:\n  prod:\n    token: s.SUPERSECRET\n    url: [unterminated\n"), &v)
	if err == nil {
		t.Fatal("expected a parse error")
	}
	if !strings.Contains(err.Error(), "s.SUPERSECRET") {
		t.Fatalf("precondition: the library's default error no longer includes the excerpt; revisit whether ErrorMessage is still needed: %q", err.Error())
	}
	msg := ErrorMessage(err)
	if strings.Contains(msg, "s.SUPERSECRET") {
		t.Errorf("ErrorMessage leaked file contents: %q", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Errorf("ErrorMessage is not one line: %q", msg)
	}
	if !strings.Contains(msg, "sequence end token") {
		t.Errorf("ErrorMessage lost the diagnosis: %q", msg)
	}
}

// Unknown fields in ~/.saferc are tolerated, as they were before.
func TestUnmarshalIgnoresUnknownFields(t *testing.T) {
	var v struct {
		Version int `yaml:"version"`
	}
	if err := Unmarshal([]byte("version: 1\nfuture_field: x\n"), &v); err != nil {
		t.Fatalf("unknown field rejected: %v", err)
	}
	if v.Version != 1 {
		t.Errorf("Version = %d, want 1", v.Version)
	}
}

// Map keys sort the way go.yaml.in/yaml/v2 sorted them: non-letters
// before letters, digit runs by numeric value, then rune order. The
// expected bytes are the previous encoder's output for this map.
func TestMarshalKeyOrderMatchesPreviousEncoder(t *testing.T) {
	out, err := Marshal(map[string]string{
		"key1": "a", "key2": "b", "key9": "c", "key10": "d", "_under": "e",
		"Alpha": "f", "beta": "g", "a-b": "h", "a.b": "i", "ab": "j",
		"A": "k", "a": "l", "10": "m", "9": "n", "x01": "o", "x1": "p",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "_under: e\n\"9\": \"n\"\n\"10\": m\nA: k\nAlpha: f\na: l\na-b: h\na.b: i\nab: j\nbeta: g\nkey1: a\nkey2: b\nkey9: c\nkey10: d\nx1: p\nx01: o\n"
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

// The reorder pass reaches maps nested inside structs, slices, and other
// maps, and leaves struct fields in declaration order.
func TestMarshalReordersNestedMaps(t *testing.T) {
	type vault struct {
		URL     string   `yaml:"url"`
		Token   string   `yaml:"token"`
		CACerts []string `yaml:"ca_certs,omitempty"`
	}
	type config struct {
		Version int               `yaml:"version"`
		Current string            `yaml:"current"`
		Vaults  map[string]*vault `yaml:"vaults"`
	}
	out, err := Marshal(&config{
		Version: 1,
		Current: "env10",
		Vaults: map[string]*vault{
			"env10":  {URL: "https://v10:8200", Token: "t10"},
			"env2":   {URL: "https://v2:8200", Token: "t2"},
			"_local": {URL: "http://127.0.0.1:8200"},
			"gone":   nil,
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `version: 1
current: env10
vaults:
  _local:
    url: http://127.0.0.1:8200
    token: ""
  env2:
    url: https://v2:8200
    token: t2
  env10:
    url: https://v10:8200
    token: t10
  gone: null
`
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	nested, err := Marshal(map[string]map[string]string{
		"secret/b10": {"k2": "v", "k10": "w"},
		"secret/b2":  {"z": "x"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wantNested := "secret/b2:\n  z: x\nsecret/b10:\n  k2: v\n  k10: w\n"
	if string(nested) != wantNested {
		t.Errorf("got:\n%s\nwant:\n%s", nested, wantNested)
	}
}

// keyLess is the previous encoder's sorter; this pins its quirks.
func TestKeyLess(t *testing.T) {
	ordered := []string{"_under", "9", "10", "A", "Alpha", "a", "a-b", "a.b", "ab", "beta", "key1", "key2", "key9", "key10", "x1", "x01"}
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			if !keyLess(ordered[i], ordered[j]) {
				t.Errorf("keyLess(%q, %q) = false, want true", ordered[i], ordered[j])
			}
			if keyLess(ordered[j], ordered[i]) {
				t.Errorf("keyLess(%q, %q) = true, want false", ordered[j], ordered[i])
			}
		}
	}
}

// A blank line inside a literal block is written empty, not indented, as
// the previous encoder wrote it; the joined CA certs in ~/.svtoken rely
// on this.
func TestMarshalLiteralBlankLineIsEmpty(t *testing.T) {
	out, err := Marshal(map[string]string{"k": "a\n\nb\n"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := "k: |\n  a\n\n  b\n"; string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// Trailing whitespace on any line of a multi-line value forces the
// double-quoted style, exactly as the previous encoder did.
func TestMarshalQuotesTrailingWhitespaceLines(t *testing.T) {
	out, err := Marshal(map[string]string{"t1": "a \nb", "t2": "a\nb  \n", "t3": "a\nb ", "t4": "a\n   \nb"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "t1: \"a \\nb\"\nt2: \"a\\nb  \\n\"\nt3: \"a\\nb \"\nt4: \"a\\n   \\nb\"\n"
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
}

// quoter leaves alone any value the encoder already quoted, recognizing it
// by the quote baked into the node text. That holds only while Marshal
// uses the encoder's default string style; this pins it.
func TestMarshalLeavesEncoderQuotedValuesAlone(t *testing.T) {
	out, err := Marshal(map[string]string{"k": "\"q\""})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := "k: \"\\\"q\\\"\"\n"; string(out) != want {
		t.Errorf("got %q, want %q", out, want)
	}
}
