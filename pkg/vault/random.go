package vault

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
)

var (
	chars = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

func random(n int, policy string) (string, error) {
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
	re, err := regexp.Compile("[^" + policy + "]")
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

	var buffer bytes.Buffer

	for range n {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(keep))))
		if err != nil {
			return "", err
		}
		indexInt := index.Int64()
		buffer.WriteString(string(keep[indexInt]))
	}

	return buffer.String(), nil
}
