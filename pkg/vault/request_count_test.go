package vault_test

import "testing"

// The request log is the measuring instrument for every request-count
// regression test in this suite: it records "METHOD /v1/<path>[?query]"
// per request.
func TestFakeVaultCountsRequests(t *testing.T) {
	v, fv := newTestVault(t)
	fv.set("secret/a", map[string]string{"k": "v"})

	if _, err := v.Read("secret/a"); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if _, err := v.List("secret"); err != nil {
		t.Fatalf("List: %v", err)
	}

	if got := fv.requestCount(`^GET /v1/secret/a$`); got != 1 {
		t.Errorf("data reads = %d, want 1", got)
	}
	if got := fv.requestCount(`^GET /v1/sys/internal/ui/mounts`); got != 1 {
		t.Errorf("mount lookups = %d, want 1", got)
	}
	// v1 LIST arrives as ?list=true; the query must be visible in the log.
	if got := fv.requestCount(`^GET /v1/secret\?list=true$`); got != 1 {
		t.Errorf("list requests with query = %d, want 1", got)
	}

	fv.resetRequestLog()
	if got := fv.requestCount(`.`); got != 0 {
		t.Errorf("after reset, %d requests logged, want 0", got)
	}
}
