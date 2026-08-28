package vault_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// scriptedResponse is one canned failure a scriptedServer injects before
// letting the wrapped fake Vault answer.
type scriptedResponse struct {
	status     int
	retryAfter string
}

// scriptedServer wraps the fake Vault handler and injects canned failure
// responses, popped in order, for specific "METHOD /path" keys. Requests
// with no remaining injections pass through to the fake. counts records
// every wire request per key, injected or passed through, which is the
// measuring instrument for "how many requests actually left the client".
type scriptedServer struct {
	mu     sync.Mutex
	inner  http.Handler
	inject map[string][]scriptedResponse
	counts map[string]int
}

func newScriptedServer(inner http.Handler) *scriptedServer {
	return &scriptedServer{
		inner:  inner,
		inject: map[string][]scriptedResponse{},
		counts: map[string]int{},
	}
}

func (s *scriptedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	s.mu.Lock()
	s.counts[key]++
	var injected *scriptedResponse
	if queue := s.inject[key]; len(queue) > 0 {
		injected = &queue[0]
		s.inject[key] = queue[1:]
	}
	s.mu.Unlock()

	if injected == nil {
		s.inner.ServeHTTP(w, r)
		return
	}
	if injected.retryAfter != "" {
		w.Header().Set("Retry-After", injected.retryAfter)
	}
	w.WriteHeader(injected.status)
	_, _ = w.Write([]byte(`{"errors":["scripted failure"]}`))
}

func (s *scriptedServer) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[key]
}

// newRetryTestVault stands up the fake Vault behind a scriptedServer and
// returns a *Vault pointed at it, alongside the script and the fake.
func newRetryTestVault(t *testing.T) (*vault.Vault, *scriptedServer, *fakeVault) {
	t.Helper()
	fv := newFakeVault()
	fv.t = t
	script := newScriptedServer(fv)
	srv := httptest.NewServer(script)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	v, err := vault.NewVault(vault.VaultConfig{URL: u.String(), Token: "test-token"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if err := v.SetURL(u.String()); err != nil {
		t.Fatalf("SetURL: %v", err)
	}
	return v, script, fv
}

// recordSleeps replaces v's retry backoff sleep with a recorder so tests
// assert on requested waits instead of actually waiting.
func recordSleeps(t *testing.T, v *vault.Vault) *[]time.Duration {
	t.Helper()
	var sleeps []time.Duration
	if !vault.SetRetrySleepForTest(v, func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}) {
		t.Fatal("SetRetrySleepForTest: transport is not the retrying round tripper")
	}
	return &sleeps
}

// A single 429 on a read must be absorbed: one logical GET succeeds after
// exactly two wire requests, with one jittered backoff in between.
func TestReadRetriesThrottledGet(t *testing.T) {
	v, script, fv := newRetryTestVault(t)
	sleeps := recordSleeps(t, v)
	fv.set("secret/a", map[string]string{"k": "v"})
	script.inject["GET /v1/secret/a"] = []scriptedResponse{{status: 429}}

	s, err := v.Read("secret/a")
	if err != nil {
		t.Fatalf("Read after one 429: %v", err)
	}
	if got := s.Get("k"); got != "v" {
		t.Errorf("read value = %q, want %q", got, "v")
	}
	if got := script.count("GET /v1/secret/a"); got != 2 {
		t.Errorf("wire GETs = %d, want 2", got)
	}
	if len(*sleeps) != 1 {
		t.Fatalf("backoff sleeps = %d, want 1", len(*sleeps))
	}
	if d := (*sleeps)[0]; d < 100*time.Millisecond || d >= 200*time.Millisecond {
		t.Errorf("first backoff = %v, want in [100ms, 200ms)", d)
	}
}

// Sustained throttling surfaces: three wire attempts, two backoffs (the
// second doubled), then the 429 error reaches the caller.
func TestReadSurfacesPersistentThrottling(t *testing.T) {
	v, script, fv := newRetryTestVault(t)
	sleeps := recordSleeps(t, v)
	fv.set("secret/a", map[string]string{"k": "v"})
	script.inject["GET /v1/secret/a"] = []scriptedResponse{
		{status: 429}, {status: 429}, {status: 429},
	}

	if _, err := v.Read("secret/a"); err == nil {
		t.Fatal("Read under sustained 429s succeeded, want error")
	}
	if got := script.count("GET /v1/secret/a"); got != 3 {
		t.Errorf("wire GETs = %d, want 3", got)
	}
	if len(*sleeps) != 2 {
		t.Fatalf("backoff sleeps = %d, want 2", len(*sleeps))
	}
	if d := (*sleeps)[1]; d < 200*time.Millisecond || d >= 400*time.Millisecond {
		t.Errorf("second backoff = %v, want in [200ms, 400ms)", d)
	}
}

// Writes are never retried at this layer: a 429 on a PUT/POST surfaces
// after exactly one wire request. Replaying writes belongs to a
// check-and-set loop that can see conflicts, not to the transport.
func TestWriteNotRetriedAfterThrottle(t *testing.T) {
	v, script, _ := newRetryTestVault(t)
	sleeps := recordSleeps(t, v)
	script.inject["PUT /v1/secret/a"] = []scriptedResponse{{status: 429}}
	script.inject["POST /v1/secret/a"] = []scriptedResponse{{status: 429}}

	s := vault.NewSecret()
	if err := s.Set("k", "v", false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := v.Write("secret/a", s); err == nil {
		t.Fatal("Write after 429 succeeded, want error")
	}
	if got := script.count("PUT /v1/secret/a") + script.count("POST /v1/secret/a"); got != 1 {
		t.Errorf("wire writes = %d, want 1", got)
	}
	if len(*sleeps) != 0 {
		t.Errorf("backoff sleeps = %d, want 0", len(*sleeps))
	}
}

// A Retry-After header overrides the computed backoff for that attempt.
func TestRetryAfterHeaderHonored(t *testing.T) {
	v, script, fv := newRetryTestVault(t)
	sleeps := recordSleeps(t, v)
	fv.set("secret/a", map[string]string{"k": "v"})
	script.inject["GET /v1/secret/a"] = []scriptedResponse{{status: 429, retryAfter: "2"}}

	if _, err := v.Read("secret/a"); err != nil {
		t.Fatalf("Read after 429 with Retry-After: %v", err)
	}
	if len(*sleeps) != 1 {
		t.Fatalf("backoff sleeps = %d, want 1", len(*sleeps))
	}
	if d := (*sleeps)[0]; d != 2*time.Second {
		t.Errorf("backoff = %v, want 2s from Retry-After", d)
	}
}

// A Retry-After far larger than the client timeout leaves room for must
// not be honored into a hang: the retry has to recognize there is no time
// left for another attempt and return the 429 as-is, fast, with the real
// backoff sleep in play -- a stubbed sleep would prove nothing about the
// deadline race this guards against.
func TestRetryAfterBeyondDeadlineFailsFast(t *testing.T) {
	v, script, fv := newRetryTestVault(t)
	fv.set("secret/a", map[string]string{"k": "v"})
	script.inject["GET /v1/secret/a"] = []scriptedResponse{{status: 429, retryAfter: "30"}}

	start := time.Now()
	_, err := v.Read("secret/a")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Read against an unpayable Retry-After succeeded, want the 429 surfaced")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Read took %v honoring an unpayable Retry-After, want well under the client timeout", elapsed)
	}
	if !strings.Contains(err.Error(), "scripted failure") {
		t.Errorf("error = %q, want Vault's own message surfaced immediately", err)
	}
	if strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("error = %q, want the 429 surfaced rather than a deadline timeout", err)
	}
}

// A Retry-After header whose seconds cannot fit in a Duration must be
// treated as absent, not let the seconds-to-Duration multiplication
// overflow into an arbitrary -- and possibly negative -- wait.
func TestRetryAfterOverflowTreatedAsAbsent(t *testing.T) {
	v, script, fv := newRetryTestVault(t)
	sleeps := recordSleeps(t, v)
	fv.set("secret/a", map[string]string{"k": "v"})
	script.inject["GET /v1/secret/a"] = []scriptedResponse{{status: 429, retryAfter: "9223372036854775807"}}

	if _, err := v.Read("secret/a"); err != nil {
		t.Fatalf("Read after one 429 with an unrepresentable Retry-After: %v", err)
	}
	if len(*sleeps) != 1 {
		t.Fatalf("backoff sleeps = %d, want 1", len(*sleeps))
	}
	if d := (*sleeps)[0]; d < 100*time.Millisecond || d >= 200*time.Millisecond {
		t.Errorf("backoff = %v, want the ordinary jittered [100ms, 200ms) range, not the overflowed header", d)
	}
}

// A 503 means a sealed (or otherwise unavailable) Vault; masking that
// behind sleeps would be wrong, so it must surface after one request.
func TestSealedVaultNotRetried(t *testing.T) {
	v, script, fv := newRetryTestVault(t)
	sleeps := recordSleeps(t, v)
	fv.set("secret/a", map[string]string{"k": "v"})
	script.inject["GET /v1/secret/a"] = []scriptedResponse{{status: 503}}

	if _, err := v.Read("secret/a"); err == nil {
		t.Fatal("Read against a 503 succeeded, want error")
	}
	if got := script.count("GET /v1/secret/a"); got != 1 {
		t.Errorf("wire GETs = %d, want 1", got)
	}
	if len(*sleeps) != 0 {
		t.Errorf("backoff sleeps = %d, want 0", len(*sleeps))
	}
}

// A refused connection essentially never resolves inside the backoff
// window: nothing is listening at all, which a wrong or unset VAULT_ADDR
// produces on every dial. Retrying it only adds three dials and a couple
// of sleeps to what should be an immediate, diagnosable failure.
func TestConnectionRefusedFailsFast(t *testing.T) {
	// Port 1 answers nothing on any sane machine; every dial is refused.
	v, err := vault.NewVault(vault.VaultConfig{URL: "http://127.0.0.1:1", Token: "test-token"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	sleeps := recordSleeps(t, v)

	if _, err := v.Read("secret/a"); err == nil {
		t.Fatal("Read against a refused connection succeeded, want error")
	}
	if len(*sleeps) != 0 {
		t.Errorf("backoff sleeps = %d, want 0: a refused connection must fail on the first attempt", len(*sleeps))
	}
}

// A connection reset happens after Vault (or whatever is in front of it)
// already accepted the TCP handshake, which is the genuinely transient
// case worth another attempt: three tries, two backoffs, then the error
// surfaces.
func TestConnectionResetRetried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read whatever the client sent, then reset rather than
			// close cleanly: SetLinger(0) makes the kernel send an RST
			// instead of a FIN, which is what surfaces as ECONNRESET on
			// the client side rather than a clean EOF.
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = conn.Close()
		}
	}()

	v, err := vault.NewVault(vault.VaultConfig{URL: "http://" + ln.Addr().String(), Token: "test-token"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	sleeps := recordSleeps(t, v)

	if _, err := v.Read("secret/a"); err == nil {
		t.Fatal("Read against a reset connection succeeded, want error")
	}
	if len(*sleeps) != 2 {
		t.Errorf("backoff sleeps = %d, want 2 (three attempts)", len(*sleeps))
	}
}

// The retry must not cost the client its keep-alive connection: the 429
// body has to be drained and closed before the retry, so the second
// attempt reuses the same TCP connection. Same ConnState-counter pattern
// as TestSafeKeepsConnectionAliveAcrossNotFound; the real backoff sleep
// runs here (one jittered 100-200 ms wait) because connection reuse under
// a stubbed sleep would prove nothing about the drain.
func TestRetryKeepsConnectionAlive(t *testing.T) {
	fv := newFakeVault()
	fv.t = t
	fv.set("secret/a", map[string]string{"k": "v"})
	script := newScriptedServer(fv)
	script.inject["GET /v1/secret/a"] = []scriptedResponse{{status: 429}}

	srv := httptest.NewUnstartedServer(script)
	var newConns atomic.Int64
	base := srv.Config.ConnState
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			newConns.Add(1)
		}
		if base != nil {
			base(c, s)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	v, err := vault.NewVault(vault.VaultConfig{URL: u.String(), Token: "test-token"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if err := v.SetURL(u.String()); err != nil {
		t.Fatalf("SetURL: %v", err)
	}

	if _, err := v.Read("secret/a"); err != nil {
		t.Fatalf("Read after one 429: %v", err)
	}
	if got := script.count("GET /v1/secret/a"); got != 2 {
		t.Errorf("wire GETs = %d, want 2", got)
	}
	if got := newConns.Load(); got != 1 {
		t.Errorf("retry used %d connections, want 1", got)
	}
}
