package command

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/vault"
)

// ReadSecretCmd creates a command to read a secret from the vault
func ReadSecretCmd(vaultAdapter *adapter.VaultAdapter, path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := vaultAdapter.Read(path)
		if err != nil {
			return SecretReadErrorMsg{
				Path: path,
				Err:  err,
			}
		}
		return SecretReadMsg{
			Path:   path,
			Secret: secret,
		}
	}
}

// WriteSecretCmd creates a command to write a secret to the vault
func WriteSecretCmd(vaultAdapter *adapter.VaultAdapter, path string, secret *vault.Secret) tea.Cmd {
	return func() tea.Msg {
		err := vaultAdapter.Write(path, secret)
		if err != nil {
			return SecretWriteErrorMsg{
				Path: path,
				Err:  err,
			}
		}
		return SecretWrittenMsg{
			Path: path,
		}
	}
}

// WriteSecretDataCmd creates a command to write key-value pairs to a secret
func WriteSecretDataCmd(vaultAdapter *adapter.VaultAdapter, path string, data map[string]string) tea.Cmd {
	return func() tea.Msg {
		secret := vault.NewSecret()
		for k, v := range data {
			if err := secret.Set(k, v, false); err != nil {
				return SecretWriteErrorMsg{
					Path: path,
					Err:  err,
				}
			}
		}

		err := vaultAdapter.Write(path, secret)
		if err != nil {
			return SecretWriteErrorMsg{
				Path: path,
				Err:  err,
			}
		}
		return SecretWrittenMsg{
			Path: path,
		}
	}
}

// DeleteSecretCmd creates a command to delete a secret from the vault
func DeleteSecretCmd(vaultAdapter *adapter.VaultAdapter, path string) tea.Cmd {
	return func() tea.Msg {
		err := vaultAdapter.Delete(path, vault.DeleteOpts{})
		if err != nil {
			return SecretDeleteErrorMsg{
				Path: path,
				Err:  err,
			}
		}
		return SecretDeletedMsg{
			Path: path,
		}
	}
}

// DeleteSecretRecursiveCmd creates a command to delete a secret and its children
func DeleteSecretRecursiveCmd(vaultAdapter *adapter.VaultAdapter, path string) tea.Cmd {
	return func() tea.Msg {
		opts := vault.DeleteOpts{
			Destroy: false,
		}
		err := vaultAdapter.Delete(path, opts)
		if err != nil {
			return SecretDeleteErrorMsg{
				Path: path,
				Err:  err,
			}
		}
		return SecretDeletedMsg{
			Path: path,
		}
	}
}

// GeneratePasswordCmd creates a command to generate a random password
func GeneratePasswordCmd(length int, policy string) tea.Cmd {
	return func() tea.Msg {
		secret := vault.NewSecret()
		err := secret.Password("generated", length, policy, false)
		if err != nil {
			return GeneratePasswordErrorMsg{
				Err: err,
			}
		}
		return GeneratedPasswordMsg{
			Password: secret.Get("generated"),
		}
	}
}

// GeneratePasswordWithOptionsCmd creates a command to generate a password with specific options
func GeneratePasswordWithOptionsCmd(length int, includeSymbols, includeNumbers, includeLowercase, includeUppercase bool) tea.Cmd {
	return func() tea.Msg {
		// Build policy string based on options
		policy := ""
		if includeLowercase {
			policy += "a-z"
		}
		if includeUppercase {
			policy += "A-Z"
		}
		if includeNumbers {
			policy += "0-9"
		}
		if includeSymbols {
			policy += "!@#$%^&*()_+-=[]{}|;:,.<>?"
		}

		// Default to alphanumeric if nothing selected
		if policy == "" {
			policy = "a-zA-Z0-9"
		}

		secret := vault.NewSecret()
		err := secret.Password("generated", length, policy, false)
		if err != nil {
			return GeneratePasswordErrorMsg{
				Err: err,
			}
		}
		return GeneratedPasswordMsg{
			Password: secret.Get("generated"),
		}
	}
}

// CopySecretCmd creates a command to copy a secret to a new path
func CopySecretCmd(vaultAdapter *adapter.VaultAdapter, srcPath, dstPath string) tea.Cmd {
	return func() tea.Msg {
		// Read source secret
		secret, err := vaultAdapter.Read(srcPath)
		if err != nil {
			return SecretCopyErrorMsg{
				SrcPath: srcPath,
				DstPath: dstPath,
				Err:     err,
			}
		}

		// Write to destination
		err = vaultAdapter.Write(dstPath, secret)
		if err != nil {
			return SecretCopyErrorMsg{
				SrcPath: srcPath,
				DstPath: dstPath,
				Err:     err,
			}
		}

		return SecretCopiedMsg{
			SrcPath: srcPath,
			DstPath: dstPath,
		}
	}
}

// MoveSecretCmd creates a command to move a secret to a new path
func MoveSecretCmd(vaultAdapter *adapter.VaultAdapter, srcPath, dstPath string) tea.Cmd {
	return func() tea.Msg {
		// Read source secret
		secret, err := vaultAdapter.Read(srcPath)
		if err != nil {
			return SecretMoveErrorMsg{
				SrcPath: srcPath,
				DstPath: dstPath,
				Err:     err,
			}
		}

		// Write to destination
		err = vaultAdapter.Write(dstPath, secret)
		if err != nil {
			return SecretMoveErrorMsg{
				SrcPath: srcPath,
				DstPath: dstPath,
				Err:     err,
			}
		}

		// Delete source
		err = vaultAdapter.Delete(srcPath, vault.DeleteOpts{})
		if err != nil {
			return SecretMoveErrorMsg{
				SrcPath: srcPath,
				DstPath: dstPath,
				Err:     err,
			}
		}

		return SecretMovedMsg{
			SrcPath: srcPath,
			DstPath: dstPath,
		}
	}
}

// RenameSecretKeyCmd creates a command to rename a key within a secret
func RenameSecretKeyCmd(vaultAdapter *adapter.VaultAdapter, path, oldKey, newKey string) tea.Cmd {
	return func() tea.Msg {
		// Read secret
		secret, err := vaultAdapter.Read(path)
		if err != nil {
			return SecretKeyRenameErrorMsg{
				Path:   path,
				OldKey: oldKey,
				NewKey: newKey,
				Err:    err,
			}
		}

		// Check if old key exists
		if !secret.Has(oldKey) {
			return SecretKeyRenameErrorMsg{
				Path:   path,
				OldKey: oldKey,
				NewKey: newKey,
				Err:    vault.NewSecretNotFoundError(oldKey),
			}
		}

		// Get value and create new secret with renamed key
		value := secret.Get(oldKey)
		newSecret := vault.NewSecret()

		// Copy all keys except the old one
		for _, k := range secret.Keys() {
			if k == oldKey {
				if err := newSecret.Set(newKey, value, false); err != nil {
					return SecretKeyRenameErrorMsg{
						Path:   path,
						OldKey: oldKey,
						NewKey: newKey,
						Err:    err,
					}
				}
			} else {
				if err := newSecret.Set(k, secret.Get(k), false); err != nil {
					return SecretKeyRenameErrorMsg{
						Path:   path,
						OldKey: oldKey,
						NewKey: newKey,
						Err:    err,
					}
				}
			}
		}

		// Write back
		err = vaultAdapter.Write(path, newSecret)
		if err != nil {
			return SecretKeyRenameErrorMsg{
				Path:   path,
				OldKey: oldKey,
				NewKey: newKey,
				Err:    err,
			}
		}

		return SecretKeyRenamedMsg{
			Path:   path,
			OldKey: oldKey,
			NewKey: newKey,
		}
	}
}

// AddSecretKeyCmd creates a command to add a key to a secret
func AddSecretKeyCmd(vaultAdapter *adapter.VaultAdapter, path, key, value string) tea.Cmd {
	return func() tea.Msg {
		// Read existing secret
		secret, err := vaultAdapter.Read(path)
		if err != nil {
			// If secret doesn't exist, create new one
			secret = vault.NewSecret()
		}

		// Add new key
		if err := secret.Set(key, value, false); err != nil {
			return SecretKeyAddErrorMsg{
				Path: path,
				Key:  key,
				Err:  err,
			}
		}

		// Write back
		err = vaultAdapter.Write(path, secret)
		if err != nil {
			return SecretKeyAddErrorMsg{
				Path: path,
				Key:  key,
				Err:  err,
			}
		}

		return SecretKeyAddedMsg{
			Path: path,
			Key:  key,
		}
	}
}

// DeleteSecretKeyCmd creates a command to delete a key from a secret
func DeleteSecretKeyCmd(vaultAdapter *adapter.VaultAdapter, path, key string) tea.Cmd {
	return func() tea.Msg {
		// Read secret
		secret, err := vaultAdapter.Read(path)
		if err != nil {
			return SecretKeyDeleteErrorMsg{
				Path: path,
				Key:  key,
				Err:  err,
			}
		}

		// Delete key
		if !secret.Delete(key) {
			return SecretKeyDeleteErrorMsg{
				Path: path,
				Key:  key,
				Err:  vault.NewSecretNotFoundError(key),
			}
		}

		// Write back (or delete if empty)
		if secret.Empty() {
			err = vaultAdapter.Delete(path, vault.DeleteOpts{})
		} else {
			err = vaultAdapter.Write(path, secret)
		}
		if err != nil {
			return SecretKeyDeleteErrorMsg{
				Path: path,
				Key:  key,
				Err:  err,
			}
		}

		return SecretKeyDeletedMsg{
			Path:        path,
			Key:         key,
			SecretEmpty: secret.Empty(),
		}
	}
}

// Message types for secret operations

// SecretReadMsg indicates a secret was read successfully
type SecretReadMsg struct {
	Path   string
	Secret *vault.Secret
}

// SecretReadErrorMsg indicates a read failure
type SecretReadErrorMsg struct {
	Path string
	Err  error
}

// SecretWrittenMsg indicates a secret was written successfully
type SecretWrittenMsg struct {
	Path string
}

// SecretWriteErrorMsg indicates a write failure
type SecretWriteErrorMsg struct {
	Path string
	Err  error
}

// SecretDeletedMsg indicates a secret was deleted successfully
type SecretDeletedMsg struct {
	Path string
}

// SecretDeleteErrorMsg indicates a deletion failure
type SecretDeleteErrorMsg struct {
	Path string
	Err  error
}

// GeneratedPasswordMsg contains a generated password
type GeneratedPasswordMsg struct {
	Password string
}

// GeneratePasswordErrorMsg indicates password generation failed
type GeneratePasswordErrorMsg struct {
	Err error
}

// SecretCopiedMsg indicates a secret was copied successfully
type SecretCopiedMsg struct {
	SrcPath string
	DstPath string
}

// SecretCopyErrorMsg indicates a copy failure
type SecretCopyErrorMsg struct {
	SrcPath string
	DstPath string
	Err     error
}

// SecretMovedMsg indicates a secret was moved successfully
type SecretMovedMsg struct {
	SrcPath string
	DstPath string
}

// SecretMoveErrorMsg indicates a move failure
type SecretMoveErrorMsg struct {
	SrcPath string
	DstPath string
	Err     error
}

// SecretKeyRenamedMsg indicates a key was renamed successfully
type SecretKeyRenamedMsg struct {
	Path   string
	OldKey string
	NewKey string
}

// SecretKeyRenameErrorMsg indicates a key rename failure
type SecretKeyRenameErrorMsg struct {
	Path   string
	OldKey string
	NewKey string
	Err    error
}

// SecretKeyAddedMsg indicates a key was added successfully
type SecretKeyAddedMsg struct {
	Path string
	Key  string
}

// SecretKeyAddErrorMsg indicates a key add failure
type SecretKeyAddErrorMsg struct {
	Path string
	Key  string
	Err  error
}

// SecretKeyDeletedMsg indicates a key was deleted successfully
type SecretKeyDeletedMsg struct {
	Path        string
	Key         string
	SecretEmpty bool
}

// SecretKeyDeleteErrorMsg indicates a key deletion failure
type SecretKeyDeleteErrorMsg struct {
	Path string
	Key  string
	Err  error
}
