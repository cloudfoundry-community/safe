// The typed half of the fake Vault server in httptest_helper_test.go. The
// rest of the fake keeps every value as a string, which is all safe itself
// ever writes. Vault does not: an auth role answers with objects, lists,
// numbers, and booleans, and a KV secret written by the vault CLI or by
// Terraform can hold the same. An endpoint added here serves a read with
// whatever JSON it was seeded with and records the body of every write
// verbatim, so a test can see the type each value went back as.
//
// An endpoint is matched on its whole path before any mount is, and comes
// in three kinds:
//
//	endpointRole -- an auth role. A write merges into what is there, and a
//	                string sent for a field that holds an object is refused
//	                the way Vault 1.21.3 and later refuse one for
//	                alias_metadata, with: invalid key pair "<value>"
//	endpointKV1  -- a KV v1 secret. A write replaces what is there.
//	endpointKV2  -- the data/ path of a KV v2 secret on a mount added with
//	                mountV2. A read carries version metadata, and a write
//	                checks its cas option, replaces the data, and adds a
//	                version.
package vault_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type endpointKind int

const (
	endpointRole endpointKind = iota
	endpointKV1
	endpointKV2
)

// fakeEndpoint is one typed path. data is what a read answers with, key by
// key, as raw JSON; writes holds the data object of every write accepted,
// key by key, in arrival order.
type fakeEndpoint struct {
	kind    endpointKind
	data    map[string]json.RawMessage
	version uint // KV v2 only: the current version
	writes  []map[string]json.RawMessage

	// metaPath is, for a KV v2 endpoint only, the path whose version
	// history in f.v2data the metadata endpoint serves for it.
	metaPath string
}

// typedEndpoint serves path (what follows /v1/) as an endpoint of the given
// kind, seeded with the JSON object in data. A KV v2 endpoint starts at
// version 1. The test fails at once if data is not a JSON object.
func (f *fakeVault) typedEndpoint(t *testing.T, path string, kind endpointKind, data string) {
	t.Helper()
	seed := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(data), &seed); err != nil {
		t.Fatalf("typedEndpoint(%s): seed is not a JSON object: %v", path, err)
	}
	path = strings.Trim(path, "/")
	e := &fakeEndpoint{kind: kind, data: seed}
	f.mu.Lock()
	defer f.mu.Unlock()
	if kind == endpointKV2 {
		mount, sub, ok := strings.Cut(path, "/data/")
		if !ok {
			t.Fatalf("typedEndpoint(%s): a KV v2 endpoint is a <mount>/data/<path> path", path)
		}
		//The version history lives with the string-valued v2 secrets, so
		// the metadata endpoint answers for this one too. Its versions hold
		// no data; reads of the data come here.
		e.metaPath = mount + "/" + sub
		e.version = f.appendV2Locked(e.metaPath, nil)
	}
	f.endpoints[path] = e
}

// endpointWrites returns the data each accepted write to path carried,
// oldest first.
func (f *fakeVault) endpointWrites(path string) []map[string]json.RawMessage {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e := f.endpoints[strings.Trim(path, "/")]
	if e == nil {
		return nil
	}
	out := make([]map[string]json.RawMessage, len(e.writes))
	copy(out, e.writes)
	return out
}

// endpointFor returns the endpoint registered at path, or nil.
func (f *fakeVault) endpointFor(path string) *fakeEndpoint {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.endpoints[strings.Trim(path, "/")]
}

func (f *fakeVault) serveEndpoint(w http.ResponseWriter, r *http.Request, e *fakeEndpoint) {
	f.mu.Lock()
	defer f.mu.Unlock()

	//An endpoint is a leaf, so a listing of it finds nothing, the way a
	// listing of any secret does.
	if r.Method == "LIST" || r.URL.Query().Get("list") == "true" {
		jsonErr(w, http.StatusNotFound, "")
		return
	}

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		if e.kind == endpointKV2 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data":     e.data,
					"metadata": v2VersionJSON(&fakeV2Version{}, e.version),
				},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": e.data})

	case http.MethodPut, http.MethodPost:
		body := map[string]json.RawMessage{}
		if e.kind == endpointKV2 {
			var wrapped struct {
				Data    map[string]json.RawMessage `json:"data"`
				Options struct {
					CAS *uint `json:"cas"`
				} `json:"options"`
			}
			if err := json.NewDecoder(r.Body).Decode(&wrapped); err != nil {
				jsonErr(w, http.StatusBadRequest, "invalid json")
				return
			}
			if wrapped.Options.CAS != nil && *wrapped.Options.CAS != e.version {
				jsonErr(w, http.StatusBadRequest, "check-and-set parameter did not match the current version")
				return
			}
			body = wrapped.Data
		} else if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json")
			return
		}

		if e.kind == endpointRole {
			for k, sent := range body {
				if !isJSONObject(e.data[k]) {
					continue
				}
				var s string
				if json.Unmarshal(sent, &s) == nil {
					jsonErr(w, http.StatusBadRequest, `invalid key pair "`+s+`"`)
					return
				}
			}
		}

		e.writes = append(e.writes, body)
		if e.kind == endpointRole {
			for k, v := range body {
				e.data[k] = v
			}
		} else {
			e.data = body
		}

		if e.kind == endpointKV2 {
			e.version = f.appendV2Locked(e.metaPath, nil)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": v2VersionJSON(&fakeV2Version{}, e.version),
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// isJSONObject reports whether raw holds a JSON object.
func isJSONObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return len(raw) > 0 && json.Unmarshal(raw, &m) == nil && m != nil
}
