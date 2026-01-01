package adapter

import (
	"crypto/x509"
	"fmt"
	"log"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cloudfoundry-community/safe/rc"
	"github.com/cloudfoundry-community/safe/vault"
	"github.com/cloudfoundry-community/vaultkv"
)

// VaultAdapter wraps vault.Vault for TUI operations
type VaultAdapter struct {
	vault      *vault.Vault
	config     *rc.Vault
	targetName string
	connected  bool
}

// NewVaultAdapter creates a new vault adapter
func NewVaultAdapter(name string, cfg *rc.Vault) *VaultAdapter {
	return &VaultAdapter{
		config:     cfg,
		targetName: name,
	}
}

// Connect establishes a connection to the vault
func (a *VaultAdapter) Connect() error {
	var caCerts *x509.CertPool

	// Load CA certificates if specified
	if len(a.config.CACerts) > 0 {
		caCerts = x509.NewCertPool()
		for _, cert := range a.config.CACerts {
			caCerts.AppendCertsFromPEM([]byte(cert))
		}
	}

	v, err := vault.NewVault(vault.VaultConfig{
		URL:        a.config.URL,
		Token:      a.config.Token,
		Namespace:  a.config.Namespace,
		CACerts:    caCerts,
		SkipVerify: a.config.SkipVerify,
	})
	if err != nil {
		return err
	}

	a.vault = v
	a.connected = true
	return nil
}

// IsConnected returns whether the adapter is connected
func (a *VaultAdapter) IsConnected() bool {
	return a.connected && a.vault != nil
}

// Vault returns the underlying vault instance
func (a *VaultAdapter) Vault() *vault.Vault {
	return a.vault
}

// TargetName returns the target name
func (a *VaultAdapter) TargetName() string {
	return a.targetName
}

// Read reads a secret at the given path
func (a *VaultAdapter) Read(path string) (*vault.Secret, error) {
	if !a.IsConnected() {
		return nil, ErrNotConnected
	}
	return a.vault.Read(path)
}

// Write writes a secret to the given path
func (a *VaultAdapter) Write(path string, secret *vault.Secret) error {
	if !a.IsConnected() {
		return ErrNotConnected
	}
	return a.vault.Write(path, secret)
}

// Delete deletes a secret at the given path
func (a *VaultAdapter) Delete(path string, opts vault.DeleteOpts) error {
	if !a.IsConnected() {
		return ErrNotConnected
	}
	return a.vault.Delete(path, opts)
}

// DeleteTree recursively deletes all secrets under a path (for directories)
func (a *VaultAdapter) DeleteTree(path string, opts vault.DeleteOpts) error {
	if !a.IsConnected() {
		return ErrNotConnected
	}
	return a.vault.DeleteTree(path, opts)
}

// List lists secrets at the given path
func (a *VaultAdapter) List(path string) ([]string, error) {
	if !a.IsConnected() {
		return nil, ErrNotConnected
	}
	return a.vault.List(path)
}

// ListAlive lists only alive (non-deleted) secrets at the given path
// This filters out soft-deleted secrets and empty directories in KV v2
func (a *VaultAdapter) ListAlive(path string) ([]string, error) {
	if !a.IsConnected() {
		return nil, ErrNotConnected
	}

	// Get all children first
	allChildren, err := a.vault.List(path)
	if err != nil {
		return nil, err
	}

	// Filter: check both secrets and directories for alive content
	alive := make([]string, 0, len(allChildren))
	for _, child := range allChildren {
		childPath := strings.TrimSuffix(path, "/") + "/" + strings.TrimSuffix(child, "/")

		if strings.HasSuffix(child, "/") {
			// Directory - check if it has any alive descendants
			hasAlive := a.hasAliveDescendants(childPath)
			if hasAlive {
				alive = append(alive, child)
			}
		} else {
			// Secret - check if it's alive by trying to read it
			_, err := a.vault.Read(childPath)
			if err == nil {
				// Secret is readable (alive), include it
				alive = append(alive, child)
			}
			// If error (e.g., "is deleted"), skip this secret
		}
	}

	return alive, nil
}

// hasAliveDescendants checks if a directory path has any alive secrets underneath
func (a *VaultAdapter) hasAliveDescendants(path string) bool {
	children, err := a.vault.List(path)
	if err != nil {
		return false
	}

	for _, child := range children {
		childPath := strings.TrimSuffix(path, "/") + "/" + strings.TrimSuffix(child, "/")

		if strings.HasSuffix(child, "/") {
			// Subdirectory - recurse
			if a.hasAliveDescendants(childPath) {
				return true
			}
		} else {
			// Secret - check if alive
			_, err := a.vault.Read(childPath)
			if err == nil {
				return true
			}
		}
	}

	return false
}

// Mounts returns all mounts of the given type
func (a *VaultAdapter) Mounts(typ string) ([]string, error) {
	if !a.IsConnected() {
		return nil, ErrNotConnected
	}
	return a.vault.Mounts(typ)
}

// Sealed returns whether the vault is sealed
func (a *VaultAdapter) Sealed() (bool, error) {
	if !a.IsConnected() {
		return true, ErrNotConnected
	}
	return a.vault.Sealed()
}

// ConstructSecrets builds the secret tree
func (a *VaultAdapter) ConstructSecrets(path string, opts vault.TreeOpts) (vault.Secrets, error) {
	if !a.IsConnected() {
		return nil, ErrNotConnected
	}
	return a.vault.ConstructSecrets(path, opts)
}

// ReadKeyValue reads a specific key from a secret
func (a *VaultAdapter) ReadKeyValue(path, key string) (string, error) {
	if !a.IsConnected() {
		return "", ErrNotConnected
	}
	secret, err := a.vault.Read(path)
	if err != nil {
		return "", err
	}
	return secret.Get(key), nil
}

// GetKeyVersions returns version history for a secret (KV v2 only)
func (a *VaultAdapter) GetKeyVersions(path string) ([]vaultkv.KVVersion, error) {
	if !a.IsConnected() {
		return nil, ErrNotConnected
	}
	return a.vault.Versions(path)
}

// ReadKeyValueAtVersion reads a key value at a specific version
func (a *VaultAdapter) ReadKeyValueAtVersion(path, key string, version uint) (string, error) {
	if !a.IsConnected() {
		return "", ErrNotConnected
	}
	fullPath := fmt.Sprintf("%s^%d", path, version)
	secret, err := a.vault.Read(fullPath)
	if err != nil {
		return "", err
	}
	return secret.Get(key), nil
}

// MountVersion returns the KV version (1 or 2) for a path
func (a *VaultAdapter) MountVersion(path string) (uint, error) {
	if !a.IsConnected() {
		return 0, ErrNotConnected
	}
	return a.vault.MountVersion(path)
}

// ErrNotConnected is returned when operations are attempted without a connection
var ErrNotConnected = &NotConnectedError{}

// NotConnectedError indicates no vault connection
type NotConnectedError struct{}

func (e *NotConnectedError) Error() string {
	return "not connected to vault"
}

// Command builders for async operations

// ConnectCmd creates a command to connect to a vault
func ConnectCmd(name string, cfg *rc.Vault) tea.Cmd {
	return func() tea.Msg {
		adapter := NewVaultAdapter(name, cfg)
		err := adapter.Connect()
		if err != nil {
			return ConnectionErrorMsg{
				TargetName: name,
				Err:        err,
			}
		}
		return ConnectedMsg{
			TargetName: name,
			Adapter:    adapter,
		}
	}
}

// ListPathCmd creates a command to list a path
func ListPathCmd(adapter *VaultAdapter, path string) tea.Cmd {
	return func() tea.Msg {
		children, err := adapter.List(path)
		if err != nil {
			return ListErrorMsg{
				Path: path,
				Err:  err,
			}
		}
		return PathListedMsg{
			Path:     path,
			Children: children,
		}
	}
}

// ReadSecretCmd creates a command to read a secret
func ReadSecretCmd(adapter *VaultAdapter, path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := adapter.Read(path)
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

// WriteSecretCmd creates a command to write a secret
func WriteSecretCmd(adapter *VaultAdapter, path string, secret *vault.Secret) tea.Cmd {
	return func() tea.Msg {
		err := adapter.Write(path, secret)
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

// DeleteSecretCmd creates a command to delete a secret
func DeleteSecretCmd(adapter *VaultAdapter, path string) tea.Cmd {
	return func() tea.Msg {
		err := adapter.Delete(path, vault.DeleteOpts{})
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

// Message types for vault operations

// ConnectedMsg indicates successful vault connection
type ConnectedMsg struct {
	TargetName string
	Adapter    *VaultAdapter
}

// ConnectionErrorMsg indicates a connection failure
type ConnectionErrorMsg struct {
	TargetName string
	Err        error
}

// PathListedMsg contains the result of a list operation
type PathListedMsg struct {
	Path     string
	Children []string
}

// ListErrorMsg indicates a list operation failure
type ListErrorMsg struct {
	Path string
	Err  error
}

// SecretReadMsg contains a read secret
type SecretReadMsg struct {
	Path   string
	Secret *vault.Secret
}

// SecretReadErrorMsg indicates a read failure
type SecretReadErrorMsg struct {
	Path string
	Err  error
}

// SecretWrittenMsg indicates successful write
type SecretWrittenMsg struct {
	Path string
}

// SecretWriteErrorMsg indicates a write failure
type SecretWriteErrorMsg struct {
	Path string
	Err  error
}

// SecretDeletedMsg indicates successful deletion
type SecretDeletedMsg struct {
	Path string
}

// SecretDeleteErrorMsg indicates a deletion failure
type SecretDeleteErrorMsg struct {
	Path string
	Err  error
}

// Path prefetch messages and commands

// PathPrefetchCompleteMsg indicates prefetch completed successfully
type PathPrefetchCompleteMsg struct {
	MountPath string
	Paths     []string
}

// PathPrefetchErrorMsg indicates prefetch failed
type PathPrefetchErrorMsg struct {
	MountPath string
	Err       error
}

// PrefetchAllPathsCmd creates a command to prefetch all paths under a mount
// This uses the same mechanism as "safe paths" to recursively fetch all paths
func PrefetchAllPathsCmd(adapter *VaultAdapter, mountPath string, includeKeys bool) tea.Cmd {
	log.Printf("[DEBUG] PrefetchAllPathsCmd CREATED for mount=%s", mountPath)
	return func() tea.Msg {
		log.Printf("[DEBUG] PrefetchAllPathsCmd EXECUTING: mount=%s, includeKeys=%v", mountPath, includeKeys)

		// TEST: Return immediately with dummy data to verify message routing
		// TODO: Remove this test block after debugging
		testMode := false
		if testMode {
			log.Printf("[DEBUG] TEST MODE: Returning dummy PathPrefetchCompleteMsg immediately")
			return PathPrefetchCompleteMsg{
				MountPath: mountPath,
				Paths:     []string{mountPath + "/test/path", mountPath + "/test/path:key1"},
			}
		}

		secrets, err := adapter.ConstructSecrets(mountPath, vault.TreeOpts{
			FetchKeys:       includeKeys,
			SkipVersionInfo: true,
		})
		if err != nil {
			log.Printf("[DEBUG] PrefetchAllPathsCmd error: mount=%s, err=%v", mountPath, err)
			return PathPrefetchErrorMsg{MountPath: mountPath, Err: err}
		}

		log.Printf("[DEBUG] PrefetchAllPathsCmd: found %d secrets", len(secrets))

		// Collect paths - we need unescaped paths to match tree node paths
		// Don't use secrets.Paths() as it escapes colons and carets
		paths := make([]string, 0, len(secrets)*2)
		for _, entry := range secrets {
			// Add the path itself
			paths = append(paths, entry.Path)

			// Add path:key format for each key if we fetched keys
			if includeKeys && len(entry.Versions) > 0 {
				latestVersion := entry.Versions[len(entry.Versions)-1]
				for _, key := range latestVersion.Data.Keys() {
					paths = append(paths, entry.Path+":"+key)
				}
			}
		}

		log.Printf("[DEBUG] PrefetchAllPathsCmd RETURNING PathPrefetchCompleteMsg: mount=%s, paths=%d", mountPath, len(paths))
		return PathPrefetchCompleteMsg{
			MountPath: mountPath,
			Paths:     paths,
		}
	}
}
