package cli

// set, ask, and paste all update a path by reading it, changing the keys
// they were given, and writing everything back. On an auth role that
// write-back carries fields the operator never named, and Vault CE 1.21.3
// and later refuse alias_metadata when it arrives as the string "{}"
// instead of an object. These drive each command end to end against a
// role that answers the way those Vaults do.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

const typedRolePath = "/v1/auth/approle/role/web"

// typedRole serves one AppRole role at typedRolePath and hands every other
// request to the KV fake. A write merges into the role, and one that sends
// alias_metadata as a string is refused with the message Vault gives.
type typedRole struct {
	fv     *cliFakeVault
	mu     sync.Mutex
	data   map[string]json.RawMessage
	writes []map[string]json.RawMessage
}

func newTypedRole(t *testing.T) *typedRole {
	t.Helper()
	tr := &typedRole{
		fv: newCLIFake(t),
		data: map[string]json.RawMessage{
			"alias_metadata": json.RawMessage(`{}`),
			"token_policies": json.RawMessage(`["a"]`),
			"token_ttl":      json.RawMessage(`3600`),
			"token_type":     json.RawMessage(`"default"`),
		},
	}
	srv := httptest.NewServer(tr)
	t.Cleanup(srv.Close)
	t.Setenv("VAULT_ADDR", srv.URL)
	return tr
}

func (tr *typedRole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != typedRolePath {
		tr.fv.ServeHTTP(w, r)
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]any{"data": tr.data})

	case http.MethodPut, http.MethodPost:
		body := map[string]json.RawMessage{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":["malformed body"]}`))
			return
		}
		var s string
		if json.Unmarshal(body["alias_metadata"], &s) == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"errors": []string{`invalid key pair "` + s + `"`},
			})
			return
		}
		tr.writes = append(tr.writes, body)
		for k, v := range body {
			tr.data[k] = v
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (tr *typedRole) onlyWrite(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes to the role, want 1", len(tr.writes))
	}
	return tr.writes[0]
}

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatalf("invalid JSON %q: %v", raw, err)
	}
	return b.String()
}

func TestWriteCommandsKeepRoleFieldsTyped(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, c *CLI) error
	}{
		{"set", func(t *testing.T, c *CLI) error {
			return c.cmdSet("set", "auth/approle/role/web", "token_type=service")
		}},
		{"paste", func(t *testing.T, c *CLI) error {
			return c.cmdPaste("paste", "auth/approle/role/web", "token_type=service")
		}},
		{"ask", func(t *testing.T, c *CLI) error {
			prompt.SetReader(strings.NewReader("service\n"))
			t.Cleanup(func() { prompt.SetReader(nil) })
			return c.cmdAsk("ask", "auth/approle/role/web", "token_type")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			tr := newTypedRole(t)
			c := newTestCLI(t)

			var err error
			captureStderr(t, func() {
				captureStdout(t, func() { err = tc.run(t, c) })
			})
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			body := tr.onlyWrite(t)
			for key, want := range map[string]string{
				"alias_metadata": `{}`,
				"token_policies": `["a"]`,
				"token_ttl":      `3600`,
				"token_type":     `"service"`,
			} {
				raw, sent := body[key]
				if !sent {
					t.Errorf("%s did not send %s", tc.name, key)
					continue
				}
				if got := compactJSON(t, raw); got != want {
					t.Errorf("%s sent %s = %s, want %s", tc.name, key, got, want)
				}
			}
		})
	}
}
