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

// SecretNotFoundMessage returns the sentence safe uses for a secret it could
// not read. See VersionNotFoundMessage for why the wording is available apart
// from the error that usually carries it.
func SecretNotFoundMessage(path string) string {
	return fmt.Sprintf("no secret exists at path `%s`", path)
}

// VersionNotFoundMessage returns the sentence safe uses for a version it could
// not read from a secret that does itself exist. state names why, in the
// vocabulary `safe versions` prints — "deleted" or "destroyed" — or is empty
// if the version was simply never created.
//
// revert and undelete report these same conditions, but they find them by
// walking version metadata rather than by failing a read, and their errors
// reach the tree walk, where anything answering to IsNotFound is discarded by
// the skip-if-exists check in MoveCopyTree. They take the wording from here
// and keep their own error kind.
func VersionNotFoundMessage(path string, version uint64, state string) string {
	if state == "" {
		return fmt.Sprintf("no version %d of secret `%s` exists", version, path)
	}
	return fmt.Sprintf("version %d of secret `%s` has been %s", version, path, state)
}

// NewSecretNotFoundError returns an error with a message descibing the path
// which could not be found in the secret backend.
func NewSecretNotFoundError(path string) error {
	return secretNotFound{message: SecretNotFoundMessage(path)}
}

// NewVersionNotFoundError returns VersionNotFoundMessage as an error of the
// same kind as NewSecretNotFoundError, since the secret is still what could
// not be read; only the wording narrows. Callers testing IsSecretNotFound or
// IsNotFound are unaffected.
func NewVersionNotFoundError(path string, version uint64, state string) error {
	return secretNotFound{message: VersionNotFoundMessage(path, version, state)}
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
