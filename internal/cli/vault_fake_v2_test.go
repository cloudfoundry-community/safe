package cli

// The version 2 half of cliFakeVault. Version 2 splits one logical secret into
// several endpoints — data, metadata, delete, undelete, destroy — and keeps a
// version history rather than a single value, which is what makes versions,
// undelete, revert, and a versioned get reachable at all.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeEpoch is the creation time of the first version any test writes. Times
// are derived from it by version number so that output is stable across runs.
var fakeEpoch = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

// newCLIFakeV2 starts a fake Vault whose secret/ mount is KV version 2, and
// points VAULT_ADDR and VAULT_TOKEN at it. Call it after isolateHome.
func newCLIFakeV2(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := &cliFakeVault{
		data:     map[string]map[string]string{},
		versions: map[string][]*fakeVersion{},
		v2:       true,
		t:        t,
	}
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")
	return fv
}

// denyMetadataGet makes a metadata GET (not list) for path answer 403,
// simulating a token that can list and read a secret's data but was never
// granted read on its metadata.
func (f *cliFakeVault) denyMetadataGet(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forbidMetadataGet == nil {
		f.forbidMetadataGet = map[string]bool{}
	}
	f.forbidMetadataGet[path] = true
}

// setV2 appends one version per map given, oldest first, at a literal Vault
// path. Calling it twice on the same path keeps appending.
func (f *cliFakeVault) setV2(path string, values ...map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, kv := range values {
		f.appendVersionLocked(path, kv)
	}
}

// appendVersionLocked adds a version. Callers hold f.mu.
func (f *cliFakeVault) appendVersionLocked(path string, kv map[string]string) *fakeVersion {
	n := len(f.versions[path]) + 1
	v := &fakeVersion{
		data:      kv,
		createdAt: fakeEpoch.Add(time.Duration(n) * time.Minute),
	}
	f.versions[path] = append(f.versions[path], v)
	return v
}

// deleteV2 marks versions deleted, which is reversible.
func (f *cliFakeVault) deleteV2(path string, versions ...uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range versions {
		if v := f.versionLocked(path, n); v != nil {
			at := fakeEpoch.Add(time.Duration(n) * time.Hour)
			v.deletedAt = &at
		}
	}
}

// destroyV2 marks versions destroyed, which is not.
func (f *cliFakeVault) destroyV2(path string, versions ...uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range versions {
		if v := f.versionLocked(path, n); v != nil {
			v.destroyed = true
		}
	}
}

// versionStates reports each version of a path as one of "alive", "deleted"
// or "destroyed", oldest first, for assertions.
func (f *cliFakeVault) versionStates(path string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, v := range f.versions[path] {
		switch {
		case v.destroyed:
			out = append(out, "destroyed")
		case v.deletedAt != nil:
			out = append(out, "deleted")
		default:
			out = append(out, "alive")
		}
	}
	return out
}

// versionLocked returns version n of a path, or nil. Callers hold f.mu.
func (f *cliFakeVault) versionLocked(path string, n uint) *fakeVersion {
	history := f.versions[path]
	if n == 0 || int(n) > len(history) {
		return nil
	}
	return history[n-1]
}

// latestLocked returns the highest-numbered version and its number, or nil.
// Callers hold f.mu.
func (f *cliFakeVault) latestLocked(path string) (*fakeVersion, uint) {
	history := f.versions[path]
	if len(history) == 0 {
		return nil, 0
	}
	return history[len(history)-1], uint(len(history))
}

// serveV2 routes /v1/secret/<verb>/<path> to the version 2 handlers.
//
// The subpath is optional: a listing of the mount root arrives as
// /v1/secret/metadata?list=true with nothing after the verb, which is what
// every tree walk starts with.
func (f *cliFakeVault) serveV2(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/secret/")
	verb, subpath, _ := strings.Cut(rest, "/")
	if verb == "" {
		notFound(w)
		return
	}
	path := "secret"
	if subpath != "" {
		path += "/" + subpath
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch verb {
	case "data":
		f.serveV2Data(w, r, path)
	case "metadata":
		f.serveV2Metadata(w, r, path)
	case "delete":
		f.applyVersions(w, r, path, func(v *fakeVersion, n uint) {
			at := fakeEpoch.Add(time.Duration(n) * time.Hour)
			v.deletedAt = &at
		})
	case "undelete":
		f.applyVersions(w, r, path, func(v *fakeVersion, _ uint) {
			//A destroyed version is gone for good and undelete cannot
			// resurrect it, which is what Vault does too.
			if !v.destroyed {
				v.deletedAt = nil
			}
		})
	case "destroy":
		f.applyVersions(w, r, path, func(v *fakeVersion, _ uint) {
			v.destroyed = true
		})
	default:
		notFound(w)
	}
}

func (f *cliFakeVault) serveV2Data(w http.ResponseWriter, r *http.Request, path string) {
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var body struct {
			Data map[string]string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":["malformed body"]}`))
			return
		}
		v := f.appendVersionLocked(path, body.Data)
		writeJSON(w, map[string]any{"data": versionJSON(v, uint(len(f.versions[path])))})

	case http.MethodDelete:
		//No version given deletes the latest.
		if v, n := f.latestLocked(path); v != nil {
			at := fakeEpoch.Add(time.Duration(n) * time.Hour)
			v.deletedAt = &at
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		number := uint(0)
		if q := r.URL.Query().Get("version"); q != "" {
			parsed, err := strconv.ParseUint(q, 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["invalid version"]}`))
				return
			}
			number = uint(parsed)
		}

		v := (*fakeVersion)(nil)
		if number == 0 {
			v, number = f.latestLocked(path)
		} else {
			v = f.versionLocked(path, number)
		}
		if v == nil {
			notFound(w)
			return
		}
		//A deleted or destroyed version still has metadata, but its data is
		// gone; Vault answers 404 with the metadata attached.
		if v.destroyed || v.deletedAt != nil {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"data": map[string]any{
				"data":     nil,
				"metadata": versionJSON(v, number),
			}})
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{
			"data":     v.data,
			"metadata": versionJSON(v, number),
		}})
	}
}

func (f *cliFakeVault) serveV2Metadata(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.Query().Get("list") == "true" {
		keys := f.childrenOfV2(path)
		if len(keys) == 0 {
			notFound(w)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"keys": keys}})
		return
	}

	if r.Method == http.MethodGet && f.forbidMetadataGet[path] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}

	if r.Method == http.MethodDelete {
		delete(f.versions, path)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	history := f.versions[path]
	if len(history) == 0 {
		notFound(w)
		return
	}

	versions := map[string]any{}
	for i, v := range history {
		versions[strconv.Itoa(i+1)] = versionJSON(v, uint(i+1))
	}
	writeJSON(w, map[string]any{"data": map[string]any{
		"created_time":    history[0].createdAt.Format(time.RFC3339Nano),
		"updated_time":    history[len(history)-1].createdAt.Format(time.RFC3339Nano),
		"current_version": len(history),
		"oldest_version":  1,
		"max_versions":    0,
		"versions":        versions,
	}})
}

// applyVersions runs fn over every version named in the request body. An empty
// list is a no-op rather than an error, matching Vault.
func (f *cliFakeVault) applyVersions(w http.ResponseWriter, r *http.Request, path string, fn func(*fakeVersion, uint)) {
	var body struct {
		Versions []uint `json:"versions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":["malformed body"]}`))
		return
	}
	for _, n := range body.Versions {
		if v := f.versionLocked(path, n); v != nil {
			fn(v, n)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// childrenOfV2 returns the immediate children of a directory in the version 2
// store, with a trailing slash on those that are themselves directories.
// Callers hold f.mu.
func (f *cliFakeVault) childrenOfV2(dir string) []string {
	seen := map[string]bool{}
	keys := []string{}
	for stored := range f.versions {
		rest, ok := strings.CutPrefix(stored, dir+"/")
		if !ok {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i+1]
		}
		if !seen[rest] {
			seen[rest] = true
			keys = append(keys, rest)
		}
	}
	//Vault does not promise an order, but a stable one keeps test output
	// readable.
	sort.Strings(keys)
	return keys
}

func versionJSON(v *fakeVersion, number uint) map[string]any {
	deletion := ""
	if v.deletedAt != nil {
		deletion = v.deletedAt.Format(time.RFC3339Nano)
	}
	return map[string]any{
		"created_time":  v.createdAt.Format(time.RFC3339Nano),
		"deletion_time": deletion,
		"destroyed":     v.destroyed,
		"version":       number,
	}
}

func writeJSON(w http.ResponseWriter, body any) {
	_ = json.NewEncoder(w).Encode(body)
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"errors":[]}`))
}
