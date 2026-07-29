package vault

import (
	"errors"
	"fmt"
)

type secretNotFound struct {
	message string
}

func (e secretNotFound) Error() string {
	return e.message
}

type keyNotFound struct {
	secret string
	key    string
}

func (e keyNotFound) Error() string {
	return fmt.Sprintf("no key `%s` exists in secret `%s`", e.key, e.secret)
}

// IsNotFound returns true if the given error is a SecretNotFound error
//
//	or a KeyNotFound error. Returns false otherwise.
func IsNotFound(err error) bool {
	return IsSecretNotFound(err) || IsKeyNotFound(err)
}

// NewSecretNotFoundError returns an error with a message descibing the path
// which could not be found in the secret backend.
func NewSecretNotFoundError(path string) error {
	return secretNotFound{message: fmt.Sprintf("no secret exists at path `%s`", path)}
}

// NewVersionNotFoundError returns an error describing a version that could not
// be read from a secret which does itself exist. state names why, in the
// vocabulary `safe versions` prints — "deleted" or "destroyed" — or is empty
// if the version was simply never created.
//
// The result is the same kind of error as NewSecretNotFoundError, since the
// secret is still what could not be read; only the wording narrows. Callers
// testing IsSecretNotFound or IsNotFound are unaffected.
func NewVersionNotFoundError(path string, version uint64, state string) error {
	if state != "" {
		return secretNotFound{message: fmt.Sprintf(
			"version %d of secret `%s` has been %s", version, path, state)}
	}
	return secretNotFound{message: fmt.Sprintf(
		"no version %d of secret `%s` exists", version, path)}
}

// IsSecretNotFound returns true if the given error was created with
// NewSecretNotFoundError(), including when the error is wrapped with %w.
// False otherwise.
func IsSecretNotFound(err error) bool {
	var e secretNotFound
	return errors.As(err, &e)
}

// NewKeyNotFoundError returns an error object describing the key that could not
// be located within the secret it was searched for in. Returning a KeyNotFound
// error should semantically mean that the secret it would've been contained in
// was located in the vault.
func NewKeyNotFoundError(path, key string) error {
	return keyNotFound{secret: path, key: key}
}

// IsKeyNotFound returns true if the given error was created with
// NewKeyNotFoundError(), including when the error is wrapped with %w.
// False otherwise.
func IsKeyNotFound(err error) bool {
	var e keyNotFound
	return errors.As(err, &e)
}
