// workVersions truncating to the last-seen version assumes at least one
// version came back. A KV v2 metadata read that answers 200 with no versions
// at all -- a secret whose history was fully trimmed or destroyed but whose
// metadata record is still there -- breaks that assumption. This is package
// vault (not vault_test) so workVersions can be called directly against a
// single-purpose fake server, without going through the tree walk's
// discovery path, which normalizes an empty-but-present metadata record to
// SecretNotFound before a child node like this is ever reached.
package vault

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestWorkVersionsHandlesAnEmptyMetadataResponse(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/internal/ui/mounts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"secret": map[string]any{
					"kv2/": map[string]any{
						"type":    "kv",
						"options": map[string]any{"version": "2"},
					},
				},
			},
		})
	})
	mux.HandleFunc("/v1/kv2/metadata/drained", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"created_time":    "2020-01-01T00:00:00Z",
				"updated_time":    "2020-01-01T00:00:00Z",
				"current_version": 0,
				"oldest_version":  0,
				"max_versions":    0,
				"versions":        map[string]any{},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	v, err := NewVault(VaultConfig{URL: u.String(), Token: "test-token"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if err := v.SetURL(u.String()); err != nil {
		t.Fatalf("SetURL: %v", err)
	}

	w := treeWorker{vault: v, opts: TreeOpts{}}
	got, err := w.workVersions(secretTree{Name: "kv2/drained", MountVersion: 2})
	if err != nil {
		t.Fatalf("workVersions: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("workVersions returned %d nodes, want 0", len(got))
	}
}
