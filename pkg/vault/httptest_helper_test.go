// Package vault_test provides a fake Vault HTTP server for black-box tests.
// The helper stands up a KV v1 backend at /secret/ and wires a *Vault to it
// via the vaultkv client's VaultURL field. Further mounts can be added with
// mount(), which is what the mount listing and the walk of a whole Vault are
// tested against.
//
// Endpoints handled:
//
//	GET  /v1/sys/internal/ui/mounts — mount discovery, with each mount's version
//	GET  /v1/auth/token/lookup-self — token validity check (200 OK)
//	POST /v1/auth/token/renew-self  — lease renewal (used by RenewLease)
//	PUT/DELETE /v1/sys/generate-root/{attempt,update} — root token generation
//	GET  /v1/sys/mounts            — list mounts (used by Mounts)
//	POST /v1/sys/mounts/<path>     — enable a mount (used by AddMount)
//	GET  /v1/<mount>/*             — read secret
//	POST /v1/<mount>/*             — write secret
//	DELETE /v1/<mount>/*           — delete secret
//	LIST /v1/<mount>/*             — list secrets (uses X-List-Method or PROPFIND-style)
//
// Every KV mount added with mount() is version 1. A version 2 mount answers
// on different paths again -- data/, metadata/, delete/, undelete/,
// destroy/ -- and is modelled in httptest_kv2_helper_test.go; add one with
// mountV2().
package vault_test

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
	"github.com/cloudfoundry-community/vaultkv"
)

// fakeMount is a secrets backend the fake serves. Version is the KV version,
// and is 1 for every mount the fake can actually answer for.
type fakeMount struct {
	typ     string
	version int
}

// fakeVault is an in-memory key-value store that mimics a Vault KV v1 backend.
type fakeVault struct {
	mu   sync.RWMutex
	data map[string]map[string]string // path → key → value

	// v2data holds the version histories of secrets on KV v2 mounts, keyed
	// by their full path. See httptest_kv2_helper_test.go.
	v2data map[string]*fakeV2History

	// mounts holds the KV mounts the fake serves, keyed by mount name with no
	// slashes. A Vault has more than one mount and safe reaches all of them
	// when it is asked to walk the whole thing.
	mounts map[string]fakeMount

	// forbidden marks secret paths whose list and get requests return 403,
	// modeling a token whose policy denies part of the tree.
	forbidden map[string]bool

	// pki holds registered PKI mount names (for sys/mounts responses).
	pki map[string]bool

	// seal models the sys/seal, sys/unseal, sys/init, and sys/seal-status
	// endpoints for Init/Seal/Unseal/Sealed/SealKeys tests.
	initialized bool
	sealed      bool
	threshold   int      // keys required to unseal
	shares      int      // total unseal keys
	progress    int      // keys submitted so far this unseal attempt
	rootToken   string   // returned by sys/init
	initKeys    []string // returned by sys/init

	// renewFails makes auth/token/renew-self answer 403, modeling a token
	// that cannot renew itself.
	renewFails bool

	// genRoot models the sys/generate-root/attempt and /update endpoints.
	// The fake plays a Vault old enough to accept the client's own OTP, so
	// vaultkv XORs the encoded token with it and formats the result as a
	// UUID. genRootToken is the plaintext token handed out on completion; it
	// must be as long as the 16-byte OTP, and defaults to fakeRootToken.
	genRootActive   bool
	genRootOTP      []byte
	genRootProgress int    // keys submitted so far; threshold completes it
	genRootToken    []byte // plaintext token to encode, nil for the default

	// rekey models the sys/rekey/init and sys/rekey/update endpoints.
	rekeyActive   bool
	rekeyNonce    string
	rekeyRequired int      // existing keys needed to authorize the rekey
	rekeyProgress int      // existing keys submitted so far; reset on cancel or completion
	rekeyShares   int      // new key count to mint on completion
	rekeyNewKeys  []string // new keys returned on completion

	// rekeyUpdateCalls counts every PUT to /v1/sys/rekey/update the fake has
	// received, and is never reset. rekeyProgress resets on cancel, so it
	// cannot tell a test whether a key was ever transmitted before an abort;
	// this can.
	rekeyUpdateCalls int
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		data:      make(map[string]map[string]string),
		v2data:    make(map[string]*fakeV2History),
		mounts:    map[string]fakeMount{"secret": {typ: "kv", version: 1}},
		forbidden: make(map[string]bool),
		pki:       make(map[string]bool),

		initialized: true,
	}
}

// mount adds a KV mount of the given type ("kv" or "generic"). Secrets are
// stored under it by their full path, the same as for the default mount.
func (f *fakeVault) mount(name, typ string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mounts[strings.Trim(name, "/")] = fakeMount{typ: typ, version: 1}
}

// mountFor returns the mount a request path belongs to, and the path within
// it. The path given is what follows /v1/.
func (f *fakeVault) mountFor(path string) (name string, sub string, ok bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	path = strings.TrimLeft(path, "/")
	name, sub, _ = strings.Cut(path, "/")
	if _, ok = f.mounts[name]; !ok {
		return "", "", false
	}
	return name, strings.Trim(sub, "/"), true
}

// mountVersion returns the KV version of a mount, or 0 if there is none.
func (f *fakeVault) mountVersion(name string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mounts[name].version
}

// forbid makes list and get requests for a secret path return 403.
func (f *fakeVault) forbid(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forbidden[path] = true
}

// isForbidden reports whether a secret path has been marked 403.
func (f *fakeVault) isForbidden(path string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.forbidden[path]
}

// set stores kv pairs at a secret path. Callers own the map.
func (f *fakeVault) set(path string, kv map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]string, len(kv))
	maps.Copy(cp, kv)
	f.data[path] = cp
}

// get retrieves kv pairs for a path. Returns nil if absent.
func (f *fakeVault) get(path string) map[string]string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	kv := f.data[path]
	if kv == nil {
		return nil
	}
	cp := make(map[string]string, len(kv))
	maps.Copy(cp, kv)
	return cp
}

// del removes a secret path.
func (f *fakeVault) del(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, path)
}

// listUnder returns immediate children under prefix (relative paths).
// Paths that have deeper nesting appear as "child/" (folder) entries.
func (f *fakeVault) listUnder(prefix string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	prefix = strings.TrimRight(prefix, "/") + "/"
	seen := map[string]bool{}
	var out []string
	for p := range f.data {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rel := strings.TrimPrefix(p, prefix)
		// immediate child vs sub-folder
		parts := strings.SplitN(rel, "/", 2)
		entry := parts[0]
		if len(parts) == 2 {
			entry = parts[0] + "/"
		}
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	return out
}

// sysMountsForListJSON returns payload used by Vault.Mounts (sys/mounts endpoint).
func (f *fakeVault) sysMountsForListJSON() []byte {
	f.mu.RLock()
	defer f.mu.RUnlock()
	type mountEntry struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Config      any    `json:"config"`
	}
	mounts := map[string]mountEntry{}
	for name, m := range f.mounts {
		mounts[name+"/"] = mountEntry{Type: m.typ, Config: map[string]any{}}
	}
	for name := range f.pki {
		mounts[name+"/"] = mountEntry{Type: "pki", Config: map[string]any{}}
	}
	//Vault 1.10 and later repeat the mounts under a data key, with other
	// metadata beside them at the top level. The client reads the data key
	// and gives back nothing at all for the older shape.
	b, _ := json.Marshal(map[string]any{"data": mounts})
	return b
}

// uiMountsJSON returns the /sys/internal/ui/mounts payload used by IsKVv2Mount.
func (f *fakeVault) uiMountsJSON() []byte {
	f.mu.RLock()
	defer f.mu.RUnlock()
	type optEntry struct {
		Version string `json:"version"`
	}
	type secretMount struct {
		Type    string   `json:"type"`
		Options optEntry `json:"options"`
	}
	secretMap := map[string]secretMount{}
	for name, m := range f.mounts {
		secretMap[name+"/"] = secretMount{
			Type:    m.typ,
			Options: optEntry{Version: strconv.Itoa(m.version)},
		}
	}
	for name := range f.pki {
		secretMap[name+"/"] = secretMount{Type: "pki"}
	}
	payload := map[string]any{
		"data": map[string]any{
			"secret": secretMap,
		},
	}
	b, _ := json.Marshal(payload)
	return b
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

// ServeHTTP dispatches requests to the fake Vault server.
func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path // e.g. /v1/secret/foo

	switch {
	case p == "/v1/sys/internal/ui/mounts" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.uiMountsJSON())

	case p == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"test-token"}}`))

	case p == "/v1/auth/token/renew-self" && r.Method == http.MethodPost:
		f.handleTokenRenewSelf(w)

	case p == "/v1/sys/generate-root/attempt",
		p == "/v1/sys/generate-root/update":
		f.handleGenerateRoot(w, r)

	case p == "/v1/sys/mounts" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.sysMountsForListJSON())

	case strings.HasPrefix(p, "/v1/sys/mounts/") && r.Method == http.MethodPost:
		f.handleEnableMount(w, r)

	case p == "/v1/sys/health",
		p == "/v1/sys/seal-status",
		p == "/v1/sys/init",
		p == "/v1/sys/seal",
		p == "/v1/sys/unseal",
		p == "/v1/sys/rekey/init",
		p == "/v1/sys/rekey/update":
		f.handleSys(w, r)

	default:
		if mount, subpath, ok := f.mountFor(strings.TrimPrefix(p, "/v1/")); ok {
			f.handleKV(w, r, mount, subpath)
			return
		}
		jsonErr(w, http.StatusNotFound, "not found")
	}
}

// handleEnableMount records the mount a POST to sys/mounts/<path> asks for,
// which is what AddMount sends.
func (f *fakeVault) handleEnableMount(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/sys/mounts/"), "/")
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "no mount path given")
		return
	}

	var body struct {
		Type    string `json:"type"`
		Options struct {
			Version string `json:"version"`
		} `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if _, taken := f.mounts[name]; taken {
		jsonErr(w, http.StatusBadRequest, "path is already in use at "+name+"/")
		return
	}
	version, err := strconv.Atoi(body.Options.Version)
	if err != nil || version == 0 {
		version = 1
	}
	f.mounts[name] = fakeMount{typ: body.Type, version: version}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeVault) handleKV(w http.ResponseWriter, r *http.Request, mount, subpath string) {
	if f.mountVersion(mount) == 2 {
		f.handleKVv2(w, r, mount, subpath)
		return
	}

	// LIST is sent as GET with ?list=true or as PROPFIND-alike.
	// vaultkv sends it as a GET with ?list=true query param for v1.
	isList := r.Method == "LIST" || r.URL.Query().Get("list") == "true"

	switch {
	case isList:
		prefix := mount + "/" + subpath
		if f.isForbidden(strings.TrimRight(prefix, "/")) {
			jsonErr(w, http.StatusForbidden, "permission denied")
			return
		}
		children := f.listUnder(prefix)
		if len(children) == 0 {
			jsonErr(w, http.StatusNotFound, "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": children,
			},
		})

	case r.Method == http.MethodGet:
		secretPath := strings.TrimRight(mount+"/"+subpath, "/")
		if f.isForbidden(secretPath) {
			jsonErr(w, http.StatusForbidden, "permission denied")
			return
		}
		kv := f.get(secretPath)
		if kv == nil {
			jsonErr(w, http.StatusNotFound, "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": kv,
		})

	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		secretPath := strings.TrimRight(mount+"/"+subpath, "/")
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		kv := make(map[string]string)
		for k, v := range body {
			switch s := v.(type) {
			case string:
				kv[k] = s
			default:
				b, _ := json.Marshal(v)
				kv[k] = string(b)
			}
		}
		f.set(secretPath, kv)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete:
		secretPath := strings.TrimRight(mount+"/"+subpath, "/")
		f.del(secretPath)
		w.WriteHeader(http.StatusNoContent)

	default:
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// sealStateJSON renders the SealState payload shared by seal-status and unseal.
func (f *fakeVault) sealStateJSON() map[string]any {
	return map[string]any{
		"type":        "shamir",
		"sealed":      f.sealed,
		"t":           f.threshold,
		"n":           f.shares,
		"progress":    f.progress,
		"nonce":       "",
		"version":     "1.0.0",
		"initialized": f.initialized,
	}
}

// handleSys models the subset of sys/* endpoints used by the seal, unseal,
// init, and rekey flows. All state lives on the fakeVault under f.mu.
func (f *fakeVault) handleSys(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path

	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	switch {
	case p == "/v1/sys/health" && r.Method == http.MethodGet:
		// Status code alone drives Health(); body is decoded but unused.
		switch {
		case !f.initialized:
			w.WriteHeader(http.StatusNotImplemented) // 501 → uninitialized
		case f.sealed:
			w.WriteHeader(http.StatusServiceUnavailable) // 503 → sealed
		default:
			w.WriteHeader(http.StatusOK)
		}
		writeJSON(map[string]any{})

	case p == "/v1/sys/seal-status" && r.Method == http.MethodGet:
		writeJSON(f.sealStateJSON())

	case p == "/v1/sys/init" && r.Method == http.MethodGet:
		writeJSON(map[string]any{"initialized": f.initialized})

	case p == "/v1/sys/init" && r.Method == http.MethodPut:
		var conf struct {
			Shares    int `json:"secret_shares"`
			Threshold int `json:"secret_threshold"`
		}
		_ = json.NewDecoder(r.Body).Decode(&conf)
		f.initialized = true
		f.shares = conf.Shares
		f.threshold = conf.Threshold
		if f.rootToken == "" {
			f.rootToken = "root-test-token"
		}
		keys := f.initKeys
		if keys == nil {
			keys = make([]string, conf.Shares)
			for i := range keys {
				keys[i] = "init-key-" + string(rune('A'+i))
			}
		}
		writeJSON(map[string]any{
			"keys":        keys,
			"keys_base64": keys,
			"root_token":  f.rootToken,
		})

	case p == "/v1/sys/seal" && r.Method == http.MethodPut:
		f.sealed = true
		f.progress = 0
		w.WriteHeader(http.StatusNoContent)

	case p == "/v1/sys/unseal" && r.Method == http.MethodPut:
		var body struct {
			Key   string `json:"key"`
			Reset bool   `json:"reset"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Reset {
			f.progress = 0
			writeJSON(f.sealStateJSON())
			return
		}
		f.progress++
		if f.threshold > 0 && f.progress >= f.threshold {
			f.sealed = false
			f.progress = 0
		}
		writeJSON(f.sealStateJSON())

	case p == "/v1/sys/rekey/init" && r.Method == http.MethodDelete:
		f.rekeyActive = false
		f.rekeyProgress = 0
		w.WriteHeader(http.StatusNoContent)

	case p == "/v1/sys/rekey/init" && r.Method == http.MethodPut:
		var conf struct {
			Shares    int `json:"secret_shares"`
			Threshold int `json:"secret_threshold"`
		}
		_ = json.NewDecoder(r.Body).Decode(&conf)
		f.rekeyActive = true
		f.rekeyNonce = "rekey-nonce"
		f.rekeyProgress = 0
		f.rekeyShares = conf.Shares
		if f.rekeyRequired == 0 {
			f.rekeyRequired = f.threshold
		}
		w.WriteHeader(http.StatusNoContent)

	case p == "/v1/sys/rekey/init" && r.Method == http.MethodGet:
		writeJSON(map[string]any{
			"started":  f.rekeyActive,
			"nonce":    f.rekeyNonce,
			"t":        f.threshold,
			"n":        f.rekeyShares,
			"progress": f.rekeyProgress,
			"required": f.rekeyRequired,
			"backup":   false,
		})

	case p == "/v1/sys/rekey/update" && r.Method == http.MethodPut:
		f.rekeyUpdateCalls++
		f.rekeyProgress++
		if f.rekeyProgress >= f.rekeyRequired {
			keys := f.rekeyNewKeys
			if keys == nil {
				keys = make([]string, f.rekeyShares)
				for i := range keys {
					keys[i] = "rekey-key-" + string(rune('A'+i))
				}
			}
			f.rekeyActive = false
			f.rekeyProgress = 0
			writeJSON(map[string]any{
				"complete":    true,
				"keys":        keys,
				"keys_base64": keys,
				"nonce":       f.rekeyNonce,
			})
			return
		}
		writeJSON(map[string]any{
			"started":  true,
			"nonce":    f.rekeyNonce,
			"progress": f.rekeyProgress,
			"required": f.rekeyRequired,
		})

	default:
		jsonErr(w, http.StatusNotFound, "unhandled sys path: "+p)
	}
}

// fakeRootToken is the plaintext root token generate-root hands out when a
// test does not choose one. It is 16 bytes because vaultkv's OTP is, and
// the fake encodes the token by XOR against that OTP.
const fakeRootToken = "0123456789abcdef"

// handleTokenRenewSelf models auth/token/renew-self, which RenewLease posts
// to with no body worth speaking of.
func (f *fakeVault) handleTokenRenewSelf(w http.ResponseWriter) {
	f.mu.RLock()
	fails := f.renewFails
	f.mu.RUnlock()
	if fails {
		jsonErr(w, http.StatusForbidden, "permission denied")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"auth":{"client_token":"test-token"}}`))
}

// handleGenerateRoot models the generate-root flow the way a Vault old
// enough to accept the client's OTP ran it: the attempt stores the OTP the
// client made up, each update submits one key, and reaching the unseal
// threshold answers with the token XORed against that OTP. vaultkv then
// undoes the XOR and formats the 16 bytes as a UUID.
func (f *fakeVault) handleGenerateRoot(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	stateJSON := func(complete bool, encodedToken string) map[string]any {
		return map[string]any{
			"started":       true,
			"nonce":         "genroot-nonce",
			"progress":      f.genRootProgress,
			"required":      f.threshold,
			"complete":      complete,
			"encoded_token": encodedToken,
		}
	}

	switch {
	case r.URL.Path == "/v1/sys/generate-root/attempt" && r.Method == http.MethodDelete:
		f.genRootActive = false
		f.genRootProgress = 0
		w.WriteHeader(http.StatusNoContent)

	case r.URL.Path == "/v1/sys/generate-root/attempt" && r.Method == http.MethodPut:
		var body struct {
			OTP string `json:"otp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		otp, err := base64.StdEncoding.DecodeString(body.OTP)
		if err != nil || len(otp) == 0 {
			jsonErr(w, http.StatusBadRequest, "otp must be base64")
			return
		}
		f.genRootActive = true
		f.genRootProgress = 0
		f.genRootOTP = otp
		writeJSON(stateJSON(false, ""))

	case r.URL.Path == "/v1/sys/generate-root/update" && r.Method == http.MethodPut:
		if !f.genRootActive {
			jsonErr(w, http.StatusBadRequest, "no root generation in progress")
			return
		}
		var body struct {
			Key   string `json:"key"`
			Nonce string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if body.Nonce != "genroot-nonce" {
			jsonErr(w, http.StatusBadRequest, "incorrect nonce supplied")
			return
		}
		f.genRootProgress++
		if f.genRootProgress < f.threshold {
			writeJSON(stateJSON(false, ""))
			return
		}

		token := f.genRootToken
		if token == nil {
			token = []byte(fakeRootToken)
		}
		encoded := make([]byte, len(token))
		for i := range token {
			encoded[i] = token[i] ^ f.genRootOTP[i]
		}
		f.genRootActive = false
		writeJSON(stateJSON(true, base64.StdEncoding.EncodeToString(encoded)))

	default:
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// newTestVault creates a fake Vault HTTP server and returns a configured
// *vault.Vault pointing at it, plus the fakeVault for state inspection.
// The server is closed at the end of t.
func newTestVault(t *testing.T) (*vault.Vault, *fakeVault) {
	t.Helper()
	fv := newFakeVault()
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	v, err := vault.NewVault(vault.VaultConfig{
		URL:   u.String(),
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	// Point the client at the test server URL exactly (NewVault may add a port).
	if err := v.SetURL(u.String()); err != nil {
		t.Fatalf("SetURL: %v", err)
	}

	return v, fv
}

// mustGetSecret calls fv.get and fatals if the path is absent.
func mustGetSecret(t *testing.T, fv *fakeVault, path string) map[string]string {
	t.Helper()
	kv := fv.get(path)
	if kv == nil {
		t.Fatalf("mustGetSecret: no secret at %q", path)
	}
	return kv
}

// secretAbsent fatals if a secret exists at path.
func secretAbsent(t *testing.T, fv *fakeVault, path string) {
	t.Helper()
	if kv := fv.get(path); kv != nil {
		t.Fatalf("secretAbsent: unexpected secret at %q: %v", path, kv)
	}
}

// assertSecretNotFound fatals if err is not a SecretNotFound error.
func assertSecretNotFound(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected SecretNotFound error, got nil")
	}
	if !vault.IsSecretNotFound(err) {
		t.Fatalf("expected SecretNotFound error, got: %v", err)
	}
}

// assertKeyNotFound fatals if err is not a KeyNotFound error.
func assertKeyNotFound(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected KeyNotFound error, got nil")
	}
	if !vault.IsKeyNotFound(err) {
		t.Fatalf("expected KeyNotFound error, got: %v", err)
	}
}

// suppress vaultkv import used only for type reference
var _ = vaultkv.KVVersion{}
