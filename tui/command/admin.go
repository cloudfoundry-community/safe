package command

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/vault"
)

// =============================================================================
// Vault Status Command
// =============================================================================

// VaultStatusResult contains the result of a vault status query
type VaultStatusResult struct {
	Sealed       bool          `json:"sealed"`
	Initialized  bool          `json:"initialized"`
	Version      string        `json:"version,omitempty"`
	ClusterName  string        `json:"cluster_name,omitempty"`
	ClusterID    string        `json:"cluster_id,omitempty"`
	TokenTTL     time.Duration `json:"token_ttl,omitempty"`
	AuthMethod   string        `json:"auth_method,omitempty"`
	Progress     int           `json:"progress,omitempty"`
	Threshold    int           `json:"threshold,omitempty"`
	NumKeys      int           `json:"num_keys,omitempty"`
	RecoverySeal bool          `json:"recovery_seal,omitempty"`
}

// VaultStatusMsg is sent when vault status is retrieved
type VaultStatusMsg struct {
	Status VaultStatusResult
	Err    error
}

// StatusCmd creates a command to get vault status
func StatusCmd(va *adapter.VaultAdapter) tea.Cmd {
	return func() tea.Msg {
		if va == nil || !va.IsConnected() {
			return VaultStatusMsg{
				Err: fmt.Errorf("not connected to vault"),
			}
		}

		sealed, err := va.Sealed()
		if err != nil {
			return VaultStatusMsg{Err: err}
		}

		status := VaultStatusResult{
			Sealed:      sealed,
			Initialized: true, // If we can check sealed status, it's initialized
			AuthMethod:  "token",
		}

		return VaultStatusMsg{Status: status}
	}
}

// =============================================================================
// Init Vault Command
// =============================================================================

// InitVaultResult contains the result of vault initialization
type InitVaultResult struct {
	SealKeys  []string `json:"seal_keys"`
	RootToken string   `json:"root_token"`
	NumKeys   int      `json:"num_keys"`
	Threshold int      `json:"threshold"`
}

// InitVaultMsg is sent when vault initialization completes
type InitVaultMsg struct {
	Result InitVaultResult
	Err    error
}

// InitVaultCmd creates a command to initialize a vault
func InitVaultCmd(v *vault.Vault, nkeys, threshold int) tea.Cmd {
	return func() tea.Msg {
		if v == nil {
			return InitVaultMsg{Err: fmt.Errorf("vault connection not available")}
		}

		keys, token, err := v.Init(nkeys, threshold)
		if err != nil {
			return InitVaultMsg{Err: err}
		}

		return InitVaultMsg{
			Result: InitVaultResult{
				SealKeys:  keys,
				RootToken: token,
				NumKeys:   nkeys,
				Threshold: threshold,
			},
		}
	}
}

// FormatInitResult formats the init result for display
func FormatInitResult(result InitVaultResult, asJSON bool) string {
	if asJSON {
		out := struct {
			Keys  []string `json:"seal_keys"`
			Token string   `json:"root_token"`
		}{
			Keys:  result.SealKeys,
			Token: result.RootToken,
		}

		b, err := json.MarshalIndent(&out, "", "  ")
		if err != nil {
			return fmt.Sprintf("Error formatting JSON: %v", err)
		}
		return string(b)
	}

	var s strings.Builder
	s.WriteString("Vault initialized successfully!\n\n")
	s.WriteString("Root Token:\n")
	s.WriteString(fmt.Sprintf("  %s\n\n", result.RootToken))
	s.WriteString("Unseal Keys:\n")
	for i, key := range result.SealKeys {
		s.WriteString(fmt.Sprintf("  Key %d: %s\n", i+1, key))
	}
	s.WriteString("\n")
	s.WriteString(fmt.Sprintf("Keys: %d, Threshold: %d\n", result.NumKeys, result.Threshold))
	s.WriteString("\nIMPORTANT: Save these keys securely. They cannot be recovered!")
	return s.String()
}

// =============================================================================
// Seal Vault Command
// =============================================================================

// SealVaultMsg is sent when vault seal operation completes
type SealVaultMsg struct {
	Sealed bool
	Err    error
}

// SealVaultCmd creates a command to seal the vault
func SealVaultCmd(v *vault.Vault) tea.Cmd {
	return func() tea.Msg {
		if v == nil {
			return SealVaultMsg{Err: fmt.Errorf("vault connection not available")}
		}

		sealed, err := v.Seal()
		return SealVaultMsg{Sealed: sealed, Err: err}
	}
}

// =============================================================================
// Unseal Vault Command
// =============================================================================

// UnsealVaultResult contains the result of an unseal operation
type UnsealVaultResult struct {
	Sealed    bool `json:"sealed"`
	Progress  int  `json:"progress"`
	Threshold int  `json:"threshold"`
}

// UnsealVaultMsg is sent when vault unseal operation completes
type UnsealVaultMsg struct {
	Result UnsealVaultResult
	Err    error
}

// UnsealVaultCmd creates a command to unseal the vault
func UnsealVaultCmd(v *vault.Vault, keys []string) tea.Cmd {
	return func() tea.Msg {
		if v == nil {
			return UnsealVaultMsg{Err: fmt.Errorf("vault connection not available")}
		}

		err := v.Unseal(keys)
		if err != nil {
			return UnsealVaultMsg{Err: err}
		}

		// Check if vault is now unsealed
		sealed, err := v.Sealed()
		if err != nil {
			return UnsealVaultMsg{Err: err}
		}

		return UnsealVaultMsg{
			Result: UnsealVaultResult{
				Sealed: sealed,
			},
		}
	}
}

// UnsealProgress represents the current unseal progress
type UnsealProgress struct {
	KeysProvided int
	KeysRequired int
	Sealed       bool
}

// UnsealProgressMsg is sent to update unseal progress
type UnsealProgressMsg struct {
	Progress UnsealProgress
	Err      error
}

// =============================================================================
// Rekey Vault Command
// =============================================================================

// RekeyVaultResult contains the result of a rekey operation
type RekeyVaultResult struct {
	NewSealKeys []string `json:"new_seal_keys"`
	NumKeys     int      `json:"num_keys"`
	Threshold   int      `json:"threshold"`
}

// RekeyVaultMsg is sent when vault rekey operation completes
type RekeyVaultMsg struct {
	Result RekeyVaultResult
	Err    error
}

// RekeyVaultCmd creates a command to rekey the vault
// Note: The actual rekey operation in the vault package requires interactive input
// for existing unseal keys. This command is a placeholder for TUI integration.
func RekeyVaultCmd(v *vault.Vault, nkeys, threshold int, pgpKeys []string) tea.Cmd {
	return func() tea.Msg {
		if v == nil {
			return RekeyVaultMsg{Err: fmt.Errorf("vault connection not available")}
		}

		// Note: The vault.ReKey function expects to read unseal keys interactively
		// For TUI integration, we would need to modify the vault package or
		// provide keys differently
		newKeys, err := v.ReKey(nkeys, threshold, pgpKeys)
		if err != nil {
			return RekeyVaultMsg{Err: err}
		}

		return RekeyVaultMsg{
			Result: RekeyVaultResult{
				NewSealKeys: newKeys,
				NumKeys:     nkeys,
				Threshold:   threshold,
			},
		}
	}
}

// FormatRekeyResult formats the rekey result for display
func FormatRekeyResult(result RekeyVaultResult) string {
	var s strings.Builder
	s.WriteString("Vault rekeyed successfully!\n\n")
	s.WriteString("New Unseal Keys:\n")
	for i, key := range result.NewSealKeys {
		s.WriteString(fmt.Sprintf("  Key %d: %s\n", i+1, key))
	}
	s.WriteString("\n")
	s.WriteString(fmt.Sprintf("Keys: %d, Threshold: %d\n", result.NumKeys, result.Threshold))
	s.WriteString("\nIMPORTANT: The old unseal keys are no longer valid!")
	return s.String()
}

// =============================================================================
// Renew Token Command
// =============================================================================

// RenewTokenResult contains the result of token renewal
type RenewTokenResult struct {
	TTL       time.Duration `json:"ttl"`
	Renewable bool          `json:"renewable"`
}

// RenewTokenMsg is sent when token renewal completes
type RenewTokenMsg struct {
	Result RenewTokenResult
	Err    error
}

// RenewTokenCmd creates a command to renew the authentication token
// Note: This requires the Vault API client to expose token renewal
func RenewTokenCmd(va *adapter.VaultAdapter) tea.Cmd {
	return func() tea.Msg {
		// Token renewal would need to be implemented in the vault package
		// For now, return a not-implemented error
		return RenewTokenMsg{
			Err: fmt.Errorf("token renewal not yet implemented in TUI"),
		}
	}
}

// =============================================================================
// Seal Keys Query Command
// =============================================================================

// SealKeysResult contains seal key configuration
type SealKeysResult struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
	Progress  int `json:"progress"`
}

// SealKeysMsg is sent with seal key information
type SealKeysMsg struct {
	Result SealKeysResult
	Err    error
}

// SealKeysCmd creates a command to get seal key configuration
func SealKeysCmd(v *vault.Vault) tea.Cmd {
	return func() tea.Msg {
		if v == nil {
			return SealKeysMsg{Err: fmt.Errorf("vault connection not available")}
		}

		threshold, err := v.SealKeys()
		if err != nil {
			return SealKeysMsg{Err: err}
		}

		return SealKeysMsg{
			Result: SealKeysResult{
				Threshold: threshold,
			},
		}
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

// ValidateInitParams validates initialization parameters
func ValidateInitParams(nkeys, threshold int) error {
	if nkeys < 1 {
		return fmt.Errorf("number of keys must be at least 1")
	}
	if threshold < 1 {
		return fmt.Errorf("threshold must be at least 1")
	}
	if threshold > nkeys {
		return fmt.Errorf("threshold cannot be greater than number of keys")
	}
	return nil
}

// ValidateRekeyParams validates rekey parameters
func ValidateRekeyParams(nkeys, threshold int) error {
	return ValidateInitParams(nkeys, threshold)
}

// ValidateUnsealKeys validates unseal keys format
func ValidateUnsealKeys(keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("at least one unseal key is required")
	}
	for i, key := range keys {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("unseal key %d is empty", i+1)
		}
	}
	return nil
}

// =============================================================================
// Admin Action Enum
// =============================================================================

// AdminAction represents the type of admin action
type AdminAction int

const (
	AdminActionNone AdminAction = iota
	AdminActionInit
	AdminActionSeal
	AdminActionUnseal
	AdminActionRekey
	AdminActionRenewToken
	AdminActionStatus
)

// String returns a string representation of the admin action
func (a AdminAction) String() string {
	switch a {
	case AdminActionInit:
		return "initialize"
	case AdminActionSeal:
		return "seal"
	case AdminActionUnseal:
		return "unseal"
	case AdminActionRekey:
		return "rekey"
	case AdminActionRenewToken:
		return "renew-token"
	case AdminActionStatus:
		return "status"
	default:
		return "unknown"
	}
}

// =============================================================================
// Combined Admin Command
// =============================================================================

// AdminCommandParams holds parameters for admin commands
type AdminCommandParams struct {
	Action     AdminAction
	NumKeys    int
	Threshold  int
	UnsealKeys []string
	PGPKeys    []string
	JSONOutput bool
}

// AdminResultMsg is a generic result message for admin commands
type AdminResultMsg struct {
	Action  AdminAction
	Success bool
	Title   string
	Content string
	Data    interface{}
	Err     error
}

// ExecuteAdminCmd executes an admin command based on the action
func ExecuteAdminCmd(va *adapter.VaultAdapter, params AdminCommandParams) tea.Cmd {
	return func() tea.Msg {
		if va == nil || !va.IsConnected() {
			return AdminResultMsg{
				Action:  params.Action,
				Success: false,
				Err:     fmt.Errorf("not connected to vault"),
			}
		}

		v := va.Vault()
		if v == nil {
			return AdminResultMsg{
				Action:  params.Action,
				Success: false,
				Err:     fmt.Errorf("vault instance not available"),
			}
		}

		switch params.Action {
		case AdminActionStatus:
			return executeStatus(va)
		case AdminActionInit:
			return executeInit(v, params)
		case AdminActionSeal:
			return executeSeal(v)
		case AdminActionUnseal:
			return executeUnseal(v, params)
		case AdminActionRekey:
			return executeRekey(v, params)
		case AdminActionRenewToken:
			return executeRenewToken(va)
		default:
			return AdminResultMsg{
				Action:  params.Action,
				Success: false,
				Err:     fmt.Errorf("unknown admin action: %v", params.Action),
			}
		}
	}
}

func executeStatus(va *adapter.VaultAdapter) AdminResultMsg {
	sealed, err := va.Sealed()
	if err != nil {
		return AdminResultMsg{
			Action:  AdminActionStatus,
			Success: false,
			Err:     err,
		}
	}

	status := VaultStatusResult{
		Sealed:      sealed,
		Initialized: true,
		AuthMethod:  "token",
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("Sealed: %v\n", sealed))
	content.WriteString(fmt.Sprintf("Initialized: %v\n", status.Initialized))
	content.WriteString(fmt.Sprintf("Auth Method: %s\n", status.AuthMethod))

	return AdminResultMsg{
		Action:  AdminActionStatus,
		Success: true,
		Title:   "Vault Status",
		Content: content.String(),
		Data:    status,
	}
}

func executeInit(v *vault.Vault, params AdminCommandParams) AdminResultMsg {
	if err := ValidateInitParams(params.NumKeys, params.Threshold); err != nil {
		return AdminResultMsg{
			Action:  AdminActionInit,
			Success: false,
			Err:     err,
		}
	}

	keys, token, err := v.Init(params.NumKeys, params.Threshold)
	if err != nil {
		return AdminResultMsg{
			Action:  AdminActionInit,
			Success: false,
			Title:   "Initialization Failed",
			Err:     err,
		}
	}

	result := InitVaultResult{
		SealKeys:  keys,
		RootToken: token,
		NumKeys:   params.NumKeys,
		Threshold: params.Threshold,
	}

	return AdminResultMsg{
		Action:  AdminActionInit,
		Success: true,
		Title:   "Vault Initialized",
		Content: FormatInitResult(result, params.JSONOutput),
		Data:    result,
	}
}

func executeSeal(v *vault.Vault) AdminResultMsg {
	sealed, err := v.Seal()
	if err != nil {
		return AdminResultMsg{
			Action:  AdminActionSeal,
			Success: false,
			Title:   "Seal Failed",
			Err:     err,
		}
	}

	var content string
	if sealed {
		content = "The vault has been sealed successfully.\nAll access is now blocked until it is unsealed."
	} else {
		content = "Vault seal command executed, but vault may still be unsealed.\nThis can happen on standby nodes."
	}

	return AdminResultMsg{
		Action:  AdminActionSeal,
		Success: sealed,
		Title:   "Vault Sealed",
		Content: content,
		Data:    sealed,
	}
}

func executeUnseal(v *vault.Vault, params AdminCommandParams) AdminResultMsg {
	if err := ValidateUnsealKeys(params.UnsealKeys); err != nil {
		return AdminResultMsg{
			Action:  AdminActionUnseal,
			Success: false,
			Err:     err,
		}
	}

	err := v.Unseal(params.UnsealKeys)
	if err != nil {
		return AdminResultMsg{
			Action:  AdminActionUnseal,
			Success: false,
			Title:   "Unseal Failed",
			Err:     err,
		}
	}

	sealed, _ := v.Sealed()
	result := UnsealVaultResult{
		Sealed: sealed,
	}

	var content string
	if !sealed {
		content = "The vault has been unsealed successfully.\nYou can now access secrets."
	} else {
		content = "Keys submitted. More keys may be required to complete unseal."
	}

	return AdminResultMsg{
		Action:  AdminActionUnseal,
		Success: !sealed,
		Title:   "Unseal " + map[bool]string{true: "Complete", false: "In Progress"}[!sealed],
		Content: content,
		Data:    result,
	}
}

func executeRekey(v *vault.Vault, params AdminCommandParams) AdminResultMsg {
	if err := ValidateRekeyParams(params.NumKeys, params.Threshold); err != nil {
		return AdminResultMsg{
			Action:  AdminActionRekey,
			Success: false,
			Err:     err,
		}
	}

	newKeys, err := v.ReKey(params.NumKeys, params.Threshold, params.PGPKeys)
	if err != nil {
		return AdminResultMsg{
			Action:  AdminActionRekey,
			Success: false,
			Title:   "Rekey Failed",
			Err:     err,
		}
	}

	result := RekeyVaultResult{
		NewSealKeys: newKeys,
		NumKeys:     params.NumKeys,
		Threshold:   params.Threshold,
	}

	return AdminResultMsg{
		Action:  AdminActionRekey,
		Success: true,
		Title:   "Vault Rekeyed",
		Content: FormatRekeyResult(result),
		Data:    result,
	}
}

func executeRenewToken(_ *adapter.VaultAdapter) AdminResultMsg {
	return AdminResultMsg{
		Action:  AdminActionRenewToken,
		Success: false,
		Title:   "Token Renewal",
		Content: "Token renewal is not yet implemented in the TUI.\nUse 'safe auth token' from the command line.",
	}
}
