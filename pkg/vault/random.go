package vault

import (
	"crypto/rand"
	"fmt"
	"io"
	"regexp"
	"sync"
)

var (
	chars = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

// policyRegexps memoizes compiled character-policy regexps by policy string.
// At least two policies are live in one process -- the user's --policy and
// the fixed a-zA-Z crypt-salt policy the fmt command draws salts with -- so
// the cache is a map rather than a single entry, which those two would
// thrash. Policies come from command-line flags, so the map stays small.
var (
	policyRegexpsMu sync.Mutex
	policyRegexps   = map[string]*regexp.Regexp{}
)

func policyRegexp(policy string) (*regexp.Regexp, error) {
	policyRegexpsMu.Lock()
	defer policyRegexpsMu.Unlock()
	if re, ok := policyRegexps[policy]; ok {
		return re, nil
	}
	re, err := regexp.Compile("[^" + policy + "]")
	if err != nil {
		return nil, err
	}
	policyRegexps[policy] = re
	return re, nil
}

func random(n int, policy string) (string, error) {
	return randomFrom(rand.Reader, n, policy)
}

func randomFrom(entropy io.Reader, n int, policy string) (string, error) {
	//No characters is not a password. `safe gen 0 secret/db pw' used to store
	// the empty string under pw and report success, leaving something that
	// reads like a generated credential and is not one.
	if n < 1 {
		return "", fmt.Errorf("cannot generate a password of %d characters: a length of at least one is needed", n)
	}

	//A policy is whatever was typed after --policy, and it is put inside a
	// character class to say which characters to keep. Not every string is one:
	// compiling it with MustCompile answered a mistyped policy with a panic and
	// a stack trace, and an unset $POLICY, which arrives here empty, with the
	// same.
	if policy == "" {
		return "", fmt.Errorf("no character policy to generate from: a policy goes inside a character class, as in a-zA-Z0-9")
	}
	re, err := policyRegexp(policy)
	if err != nil {
		return "", fmt.Errorf("`%s' is not a usable character policy: it goes inside a character class, as in a-zA-Z0-9 (%s)", policy, err)
	}

	keep := re.ReplaceAllString(chars, "")
	//A policy can be a character class and still name none of the characters a
	// password is made of, which left nothing to pick from and panicked in
	// crypto/rand instead.
	if keep == "" {
		return "", fmt.Errorf("the character policy `%s' keeps none of the characters a password can be made of", policy)
	}

	//One block read supplies the whole password instead of one entropy draw
	// per character. Each byte below the threshold indexes into keep; bytes at
	// or above it are discarded, never folded with modulo, which would favor
	// the low end of keep. The threshold lives in an int on purpose: it is 256
	// whenever len(keep) divides 256 (a 64-character policy does), where every
	// byte is fair -- squeezed into a byte that 256 becomes 0 and rejects
	// everything, and the refill loop never finishes.
	threshold := 256 - 256%len(keep)
	out := make([]byte, 0, n)
	buf := make([]byte, n+n/2+16)
	for len(out) < n {
		if _, err := io.ReadFull(entropy, buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= threshold {
				continue
			}
			out = append(out, keep[int(b)%len(keep)])
			if len(out) == n {
				break
			}
		}
	}

	return string(out), nil
}
