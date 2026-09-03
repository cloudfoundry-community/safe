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
