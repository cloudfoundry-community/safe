// White-box tests for random()'s batched entropy draw (random.go): the
// rejection-sampling contract over whole bytes, the refill loop, and the
// memoized policy regexps. The scripted reader drives randomFrom directly,
// which is the seam random() wraps crypto/rand.Reader with.
package vault

import (
	"strings"
	"testing"
)

// scriptedReader hands out its script bytes once, then repeats fill forever.
// It never errors, so a sampling loop that wrongly rejects every byte spins
// against fill instead of masking the bug with a read failure.
type scriptedReader struct {
	script []byte
	pos    int
	fill   byte
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	for i := range p {
		if r.pos < len(r.script) {
			p[i] = r.script[r.pos]
			r.pos++
		} else {
			p[i] = r.fill
		}
	}
	return len(p), nil
}

// TestRandomOutputStaysInKeepSet is the property test for the sampler: every
// output character is in the policy's keep set, across keep sizes that do
// not divide 256 and one that does. The 64-character policy is the one that
// makes the threshold arithmetic dangerous: 256 - 256%64 is 256, which
// truncated to byte width is 0 and would reject every byte forever, so this
// case passing at all proves the threshold is compared as an int.
func TestRandomOutputStaysInKeepSet(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		policy  string
		allowed string
	}{
		{"keep 10", "0-9", "0123456789"},
		{"keep 26", "a-z", "abcdefghijklmnopqrstuvwxyz"},
		{"keep 62", "a-zA-Z0-9",
			"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
		{"keep 64 divides 256", "a-zA-Z0-9+/",
			"+/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"},
		{"keep 94 full charset", "!-~", chars},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.name == "keep 64 divides 256" && len(tc.allowed)%64 != 0 {
				t.Fatalf("allowed set has %d chars, want a multiple of 64", len(tc.allowed))
			}
			const n = 4096
			got, err := random(n, tc.policy)
			if err != nil {
				t.Fatalf("random(%d, %q): %v", n, tc.policy, err)
			}
			if len(got) != n {
				t.Fatalf("length = %d, want %d", len(got), n)
			}
			for i, ch := range got {
				if !strings.ContainsRune(tc.allowed, ch) {
					t.Fatalf("char[%d] = %q not in keep set for policy %q", i, ch, tc.policy)
				}
			}
		})
	}
}

// TestRandomDiscardsBytesAtOrAboveThreshold proves rejected bytes are
// dropped, never folded with modulo. For the ten-character 0-9 policy the
// threshold is 250; a byte of 250 folded with modulo would come out as '0',
// so scripting six rejectable bytes ahead of an acceptable 7 distinguishes
// discarding (answer "7") from folding (answer "0").
func TestRandomDiscardsBytesAtOrAboveThreshold(t *testing.T) {
	r := &scriptedReader{script: []byte{250, 251, 252, 253, 254, 255, 7}, fill: 255}
	got, err := randomFrom(r, 1, "0-9")
	if err != nil {
		t.Fatalf("randomFrom: %v", err)
	}
	if got != "7" {
		t.Fatalf("randomFrom = %q, want %q (a rejected byte was folded into range instead of discarded)", got, "7")
	}
}

// TestRandomRefillsAfterExhaustingABuffer scripts enough rejected bytes to
// exhaust any first read in full, so finishing at all means the sampler went
// back to the reader for more entropy rather than giving up or recycling
// what it had.
func TestRandomRefillsAfterExhaustingABuffer(t *testing.T) {
	script := make([]byte, 0, 4098)
	for range 4096 {
		script = append(script, 255)
	}
	script = append(script, 4, 2)
	r := &scriptedReader{script: script, fill: 255}
	got, err := randomFrom(r, 2, "0-9")
	if err != nil {
		t.Fatalf("randomFrom: %v", err)
	}
	if got != "42" {
		t.Fatalf("randomFrom = %q, want %q", got, "42")
	}
}

// TestPolicyRegexpMemoizes pins the compile-once behavior: the same policy
// answers with the same compiled regexp, and distinct policies do not share
// one.
func TestPolicyRegexpMemoizes(t *testing.T) {
	a1, err := policyRegexp("a-zA-Z0-9#TestPolicyRegexpMemoizes")
	if err != nil {
		t.Fatalf("policyRegexp: %v", err)
	}
	a2, err := policyRegexp("a-zA-Z0-9#TestPolicyRegexpMemoizes")
	if err != nil {
		t.Fatalf("policyRegexp: %v", err)
	}
	if a1 != a2 {
		t.Error("same policy compiled twice; want the memoized regexp back")
	}
	b, err := policyRegexp("0-9#TestPolicyRegexpMemoizes")
	if err != nil {
		t.Fatalf("policyRegexp: %v", err)
	}
	if b == a1 {
		t.Error("distinct policies answered with the same regexp")
	}
}

func BenchmarkRandom(b *testing.B) {
	for b.Loop() {
		if _, err := random(64, "a-zA-Z0-9"); err != nil {
			b.Fatal(err)
		}
	}
}
