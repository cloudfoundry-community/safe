package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/vaultkv"
)

// tokenStatusJSON is the JSON shape emitted by MarshalJSON.
type tokenStatusJSON struct {
	Valid        bool     `json:"valid"`
	CreationTime int64    `json:"creation_time"`
	ExpireTime   int64    `json:"expire_time"`
	Renewable    bool     `json:"renewable"`
	Policies     []string `json:"policies"`
	TTL          int64    `json:"ttl"`
}

func TestTokenStatus_MarshalJSON_Invalid(t *testing.T) {
	ts := TokenStatus{valid: false}
	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("MarshalJSON: unexpected error: %v", err)
	}

	var got tokenStatusJSON
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.Valid {
		t.Errorf("valid: got true, want false")
	}
	if got.CreationTime != 0 {
		t.Errorf("creation_time: got %d, want 0", got.CreationTime)
	}
	if got.ExpireTime != 0 {
		t.Errorf("expire_time: got %d, want 0", got.ExpireTime)
	}
	if got.TTL != 0 {
		t.Errorf("ttl: got %d, want 0", got.TTL)
	}
	if len(got.Policies) != 0 {
		t.Errorf("policies: got %v, want empty", got.Policies)
	}
}

func TestTokenStatus_MarshalJSON_Valid(t *testing.T) {
	creation := time.Unix(1700000000, 0)
	expire := time.Unix(1700003600, 0)
	ttl := time.Hour

	ts := TokenStatus{
		valid: true,
		info: vaultkv.TokenInfo{
			CreationTime: creation,
			ExpireTime:   expire,
			TTL:          ttl,
			Renewable:    true,
			Policies:     []string{"default", "admin"},
		},
	}

	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var got tokenStatusJSON
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !got.Valid {
		t.Errorf("valid: got false, want true")
	}
	if got.CreationTime != creation.Unix() {
		t.Errorf("creation_time: got %d, want %d", got.CreationTime, creation.Unix())
	}
	if got.ExpireTime != expire.Unix() {
		t.Errorf("expire_time: got %d, want %d", got.ExpireTime, expire.Unix())
	}
	if got.TTL != int64(ttl.Seconds()) {
		t.Errorf("ttl: got %d, want %d", got.TTL, int64(ttl.Seconds()))
	}
	if !got.Renewable {
		t.Errorf("renewable: got false, want true")
	}
	if len(got.Policies) != 2 || got.Policies[0] != "default" || got.Policies[1] != "admin" {
		t.Errorf("policies: got %v, want [default admin]", got.Policies)
	}
}

func TestTokenStatus_MarshalJSON_FloorZeroNegativeTimes(t *testing.T) {
	// CreationTime and ExpireTime at zero value (Unix epoch 0) — floorZero clamps negatives.
	// time.Time{} is the zero value; Unix() returns a large negative number.
	// Verify the floorZero clamp: both fields must be >= 0.
	ts := TokenStatus{
		valid: true,
		info: vaultkv.TokenInfo{
			// Zero time.Time{} has Unix() == -62135596800 (before epoch).
			// floorZero must clamp it to 0.
			CreationTime: time.Time{},
			ExpireTime:   time.Time{},
			TTL:          0,
		},
	}

	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var got tokenStatusJSON
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.CreationTime < 0 {
		t.Errorf("creation_time should be >= 0 after floorZero, got %d", got.CreationTime)
	}
	if got.ExpireTime < 0 {
		t.Errorf("expire_time should be >= 0 after floorZero, got %d", got.ExpireTime)
	}
	if got.TTL < 0 {
		t.Errorf("ttl should be >= 0 after floorZero, got %d", got.TTL)
	}
}

func TestTokenStatus_MarshalJSON_JSONKeys(t *testing.T) {
	ts := TokenStatus{valid: false}
	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	s := string(b)
	for _, key := range []string{`"valid"`, `"creation_time"`, `"expire_time"`, `"renewable"`, `"policies"`, `"ttl"`} {
		if !strings.Contains(s, key) {
			t.Errorf("JSON output missing key %s: %s", key, s)
		}
	}
}

func TestTokenStatus_String_Invalid(t *testing.T) {
	ts := TokenStatus{valid: false}
	got := ts.String()
	// ansi.Sprintf strips ANSI codes on non-tty; the text "Token is invalid" must appear.
	if !strings.Contains(got, "Token is invalid") {
		t.Errorf("String() for invalid token: got %q, want substring 'Token is invalid'", got)
	}
}

func TestTokenStatus_String_Valid_NoExpiry(t *testing.T) {
	creation := time.Unix(1700000000, 0)
	ts := TokenStatus{
		valid: true,
		info: vaultkv.TokenInfo{
			CreationTime: creation,
			TTL:          0, // no expiry
			Renewable:    false,
			Policies:     []string{},
		},
	}
	got := ts.String()

	if !strings.Contains(got, "Token is valid") {
		t.Errorf("String(): missing 'Token is valid', got: %q", got)
	}
	if !strings.Contains(got, "no expiry") {
		t.Errorf("String(): missing 'no expiry', got: %q", got)
	}
	if !strings.Contains(got, "not renewable") {
		t.Errorf("String(): missing 'not renewable', got: %q", got)
	}
	if !strings.Contains(got, "no policies") {
		t.Errorf("String(): missing 'no policies', got: %q", got)
	}
}

func TestTokenStatus_String_Valid_SinglePolicy(t *testing.T) {
	ts := TokenStatus{
		valid: true,
		info: vaultkv.TokenInfo{
			CreationTime: time.Unix(1700000000, 0),
			TTL:          time.Hour,
			Renewable:    true,
			Policies:     []string{"default"},
		},
	}
	got := ts.String()

	if !strings.Contains(got, "Token is valid") {
		t.Errorf("String(): missing 'Token is valid', got: %q", got)
	}
	if !strings.Contains(got, "renewable") {
		t.Errorf("String(): missing 'renewable', got: %q", got)
	}
	// Single policy uses singular "policy"
	if !strings.Contains(got, "policy") {
		t.Errorf("String(): missing 'policy' (singular), got: %q", got)
	}
	if !strings.Contains(got, "default") {
		t.Errorf("String(): missing policy name 'default', got: %q", got)
	}
}

func TestTokenStatus_String_Valid_MultiplePolicies(t *testing.T) {
	ts := TokenStatus{
		valid: true,
		info: vaultkv.TokenInfo{
			CreationTime: time.Unix(1700000000, 0),
			TTL:          time.Hour,
			Renewable:    true,
			Policies:     []string{"default", "admin", "read-only"},
		},
	}
	got := ts.String()

	// Multiple policies uses plural "policies"
	if !strings.Contains(got, "policies") {
		t.Errorf("String(): missing 'policies' (plural), got: %q", got)
	}
	if !strings.Contains(got, "default") {
		t.Errorf("String(): missing policy 'default', got: %q", got)
	}
	if !strings.Contains(got, "admin") {
		t.Errorf("String(): missing policy 'admin', got: %q", got)
	}
	if !strings.Contains(got, "read-only") {
		t.Errorf("String(): missing policy 'read-only', got: %q", got)
	}
}

func TestRandomName_Format(t *testing.T) {
	// RandomName uses crypto/rand — not deterministic. Verify format only.
	for range 20 {
		name := RandomName()
		parts := strings.SplitN(name, "-", 2)
		if len(parts) != 2 {
			t.Errorf("RandomName() %q: expected 'adjective-noun' format", name)
			continue
		}
		adj, noun := parts[0], parts[1]
		if adj == "" {
			t.Errorf("RandomName() %q: adjective part is empty", name)
		}
		if noun == "" {
			t.Errorf("RandomName() %q: noun part is empty", name)
		}
	}
}

func TestRandomName_UsesKnownWordlists(t *testing.T) {
	// Verify generated names draw from the known adjective and noun lists.
	adjSet := make(map[string]bool, len(Adjectives))
	for _, a := range Adjectives {
		adjSet[a] = true
	}
	nounSet := make(map[string]bool, len(Nouns))
	for _, n := range Nouns {
		nounSet[n] = true
	}

	for range 50 {
		name := RandomName()
		parts := strings.SplitN(name, "-", 2)
		if len(parts) != 2 {
			t.Errorf("RandomName() %q: bad format", name)
			continue
		}
		if !adjSet[parts[0]] {
			t.Errorf("RandomName() %q: adjective %q not in Adjectives list", name, parts[0])
		}
		if !nounSet[parts[1]] {
			t.Errorf("RandomName() %q: noun %q not in Nouns list", name, parts[1])
		}
	}
}
