// The KV v2 half of the fake Vault server in httptest_helper_test.go. A v2
// mount answers on data/, metadata/, delete/, undelete/, and destroy/ paths
// and keeps a version history per secret rather than a single value, which
// is what makes DeleteVersions, Undelete, and the version explanations of
// ExplainNotFound reachable in a test at all.
//
// Version numbers count from fakeV2History.first, normally 1. trimV2 raises
// it the way Vault's max_versions trimming drops the oldest versions from
// the metadata, which is the one way a real history starts above 1.
//
// Endpoints handled, all under a mount added with mountV2:
//
//	GET    /v1/<mount>/data/<path>     — read a version (?version=0 is latest)
//	PUT    /v1/<mount>/data/<path>     — write a new version
//	DELETE /v1/<mount>/data/<path>     — mark the latest version deleted
//	GET    /v1/<mount>/metadata/<path> — version history
//	POST   /v1/<mount>/delete/<path>   — mark named versions deleted
//	POST   /v1/<mount>/undelete/<path> — unmark named versions
//	POST   /v1/<mount>/destroy/<path>  — mark named versions destroyed
package vault_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// fakeV2Version is one version of a secret on a KV v2 mount.
type fakeV2Version struct {
	data      map[string]string
	deleted   bool
	destroyed bool
}

// fakeV2History is the version history of one secret on a v2 mount.
type fakeV2History struct {
	first    uint // number of versions[0]; 1 until trimV2 raises it
	versions []*fakeV2Version
}

// mountV2 adds a KV version 2 mount. Secrets under it live in f.v2data and
// are seeded with setV2 rather than set.
func (f *fakeVault) mountV2(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mounts[strings.Trim(name, "/")] = fakeMount{typ: "kv", version: 2}
}

// setV2 appends one version per map given, oldest first, at a literal Vault
// path. Calling it twice on the same path keeps appending.
func (f *fakeVault) setV2(path string, values ...map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, kv := range values {
		f.appendV2Locked(path, kv)
	}
}

// appendV2Locked adds a version. Callers hold f.mu.
func (f *fakeVault) appendV2Locked(path string, kv map[string]string) uint {
	h := f.v2data[path]
	if h == nil {
		h = &fakeV2History{first: 1}
		f.v2data[path] = h
	}
	cp := make(map[string]string, len(kv))
	for k, v := range kv {
		cp[k] = v
	}
	h.versions = append(h.versions, &fakeV2Version{data: cp})
	return h.first + uint(len(h.versions)) - 1
}

// deleteV2 marks versions deleted, which is reversible.
func (f *fakeVault) deleteV2(path string, versions ...uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range versions {
		if v := f.v2VersionLocked(path, n); v != nil {
			v.deleted = true
		}
	}
}

// destroyV2 marks versions destroyed, which is not.
func (f *fakeVault) destroyV2(path string, versions ...uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range versions {
		if v := f.v2VersionLocked(path, n); v != nil {
			v.destroyed = true
		}
	}
}

// trimV2 drops every version numbered below newFirst, the way Vault's
// max_versions setting trims the oldest versions out of the metadata.
func (f *fakeVault) trimV2(path string, newFirst uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.v2data[path]
	if h == nil || newFirst <= h.first {
		return
	}
	drop := newFirst - h.first
	if int(drop) >= len(h.versions) {
		h.versions = nil
	} else {
		h.versions = h.versions[drop:]
	}
	h.first = newFirst
}

// v2States reports each version of a path as "alive", "deleted", or
// "destroyed", oldest first, for assertions.
func (f *fakeVault) v2States(path string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	h := f.v2data[path]
	if h == nil {
		return nil
	}
	var out []string
	for _, v := range h.versions {
		switch {
		case v.destroyed:
			out = append(out, "destroyed")
		case v.deleted:
			out = append(out, "deleted")
		default:
			out = append(out, "alive")
		}
	}
	return out
}

// v2VersionLocked returns version n of a path, or nil. Callers hold f.mu.
func (f *fakeVault) v2VersionLocked(path string, n uint) *fakeV2Version {
	h := f.v2data[path]
	if h == nil || n < h.first {
		return nil
	}
	idx := int(n - h.first)
	if idx >= len(h.versions) {
		return nil
	}
	return h.versions[idx]
}

// v2LatestLocked returns the newest version and its number. Callers hold f.mu.
func (f *fakeVault) v2LatestLocked(path string) (*fakeV2Version, uint) {
	h := f.v2data[path]
	if h == nil || len(h.versions) == 0 {
		return nil, 0
	}
	return h.versions[len(h.versions)-1], h.first + uint(len(h.versions)) - 1
}

// handleKVv2 routes /v1/<mount>/<verb>/<path> for a version 2 mount.
func (f *fakeVault) handleKVv2(w http.ResponseWriter, r *http.Request, mount, subpath string) {
	verb, rest, _ := strings.Cut(subpath, "/")
	path := mount
	if rest != "" {
		path += "/" + strings.Trim(rest, "/")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch verb {
	case "data":
		f.serveV2Data(w, r, path)
	case "metadata":
		if r.URL.Query().Get("list") == "true" {
			f.serveV2List(w, r, path)
			return
		}
		f.serveV2Metadata(w, r, path)
	case "delete":
		f.applyToVersions(w, r, path, func(v *fakeV2Version) {
			if !v.destroyed {
				v.deleted = true
			}
		})
	case "undelete":
		f.applyToVersions(w, r, path, func(v *fakeV2Version) {
			//A destroyed version is gone for good and undelete cannot
			// resurrect it, which is what Vault does too.
			if !v.destroyed {
				v.deleted = false
			}
		})
	case "destroy":
		f.applyToVersions(w, r, path, func(v *fakeV2Version) {
			v.destroyed = true
		})
	default:
		jsonErr(w, http.StatusNotFound, "")
	}
}

// serveV2List answers a directory listing over a v2 mount's metadata
// endpoint (the request that vaultkv's V2List sends, ?list=true). It mirrors
// listUnder, but walks the v2 secret keys rather than the v1 ones. Callers
// hold f.mu.
func (f *fakeVault) serveV2List(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if f.forbidden[path] {
		jsonErr(w, http.StatusForbidden, "permission denied")
		return
	}

	children := f.listUnderV2Locked(path)
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
}

// listUnderV2Locked returns immediate children under prefix (relative
// paths), the v2 counterpart of listUnder. Callers hold f.mu.
func (f *fakeVault) listUnderV2Locked(prefix string) []string {
	prefix = strings.TrimRight(prefix, "/") + "/"
	seen := map[string]bool{}
	var out []string
	for p, h := range f.v2data {
		if h == nil || len(h.versions) == 0 {
			continue
		}
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rel := strings.TrimPrefix(p, prefix)
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

// serveV2Data answers reads, writes, and the versionless delete. A GET
// (secret read) on a path marked forbidden 403s, modeling a policy that
// grants list/metadata on a subtree but denies the data read -- the case
// workGet has to skip and count rather than aborting the whole walk.
// Callers hold f.mu.
func (f *fakeVault) serveV2Data(w http.ResponseWriter, r *http.Request, path string) {
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var body struct {
			Data map[string]string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		n := f.appendV2Locked(path, body.Data)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": v2VersionJSON(&fakeV2Version{}, n),
		})

	case http.MethodDelete:
		//No version named deletes the latest.
		if v, _ := f.v2LatestLocked(path); v != nil && !v.destroyed {
			v.deleted = true
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodGet:
		if f.forbidden[path] {
			jsonErr(w, http.StatusForbidden, "permission denied")
			return
		}
		number := uint(0)
		if q := r.URL.Query().Get("version"); q != "" {
			parsed, err := strconv.ParseUint(q, 10, 64)
			if err != nil {
				jsonErr(w, http.StatusBadRequest, "invalid version")
				return
			}
			number = uint(parsed)
		}

		var v *fakeV2Version
		if number == 0 {
			v, number = f.v2LatestLocked(path)
		} else {
			v = f.v2VersionLocked(path, number)
		}
		//A deleted or destroyed version still has metadata, but its data is
		// gone; Vault answers 404, and vaultkv discards the body of any
		// non-2xx response, so a bare 404 carries the same signal.
		if v == nil || v.deleted || v.destroyed {
			jsonErr(w, http.StatusNotFound, "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     v.data,
				"metadata": v2VersionJSON(v, number),
			},
		})

	default:
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// serveV2Metadata answers the version history read that Versions and the
// not-found explanations rely on. Callers hold f.mu.
func (f *fakeVault) serveV2Metadata(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	h := f.v2data[path]
	if h == nil || len(h.versions) == 0 {
		jsonErr(w, http.StatusNotFound, "")
		return
	}

	versions := map[string]any{}
	for i, v := range h.versions {
		n := h.first + uint(i)
		versions[strconv.FormatUint(uint64(n), 10)] = v2VersionJSON(v, n)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"created_time":    fakeV2Time,
			"updated_time":    fakeV2Time,
			"current_version": h.first + uint(len(h.versions)) - 1,
			"oldest_version":  h.first,
			"max_versions":    0,
			"versions":        versions,
		},
	})
}

// applyToVersions runs fn over every version named in the request body. An
// empty list is a no-op rather than an error, matching Vault. Callers hold
// f.mu.
func (f *fakeVault) applyToVersions(w http.ResponseWriter, r *http.Request, path string, fn func(*fakeV2Version)) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Versions []uint `json:"versions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	for _, n := range body.Versions {
		if v := f.v2VersionLocked(path, n); v != nil {
			fn(v)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// fakeV2Time is the timestamp every version reports. Times are not what any
// of the tests assert on; the string only has to parse as RFC3339.
const fakeV2Time = "2020-01-01T00:00:00Z"

// v2VersionJSON renders one version the way the metadata and data endpoints
// carry it. A deleted version reports a deletion_time, which is how vaultkv
// tells deletion apart from life.
func v2VersionJSON(v *fakeV2Version, number uint) map[string]any {
	deletion := ""
	if v.deleted {
		deletion = fakeV2Time
	}
	return map[string]any{
		"created_time":  fakeV2Time,
		"deletion_time": deletion,
		"destroyed":     v.destroyed,
		"version":       number,
	}
}
