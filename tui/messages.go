package tui

import (
	"time"

	"github.com/cloudfoundry-community/safe/vault"
)

// Message types for async operations in Bubble Tea

// Connection messages
type (
	// ConnectingMsg indicates a connection attempt is starting
	ConnectingMsg struct {
		TargetAlias string
	}

	// ConnectedMsg indicates successful connection
	ConnectedMsg struct {
		TargetAlias string
		Vault       *vault.Vault
	}

	// ConnectionErrorMsg indicates a connection failure
	ConnectionErrorMsg struct {
		TargetAlias string
		Err         error
	}

	// DisconnectedMsg indicates disconnection from a target
	DisconnectedMsg struct {
		TargetAlias string
	}
)

// Tree/Path messages
type (
	// TreeLoadStartMsg indicates tree loading has started
	TreeLoadStartMsg struct {
		TargetAlias string
		Path        string
	}

	// TreeLoadedMsg indicates tree data was loaded successfully
	TreeLoadedMsg struct {
		TargetAlias string
		Path        string
		Children    []string
		IsSecret    bool
	}

	// TreeLoadErrorMsg indicates tree loading failed
	TreeLoadErrorMsg struct {
		TargetAlias string
		Path        string
		Err         error
	}

	// TreeRefreshMsg requests a tree refresh
	TreeRefreshMsg struct {
		TargetAlias string
		Path        string
	}
)

// Secret messages
type (
	// SecretLoadStartMsg indicates secret loading has started
	SecretLoadStartMsg struct {
		TargetAlias string
		Path        string
	}

	// SecretLoadedMsg indicates a secret was loaded successfully
	SecretLoadedMsg struct {
		TargetAlias string
		Path        string
		Secret      *vault.Secret
	}

	// SecretLoadErrorMsg indicates secret loading failed
	SecretLoadErrorMsg struct {
		TargetAlias string
		Path        string
		Err         error
	}

	// SecretSavedMsg indicates a secret was saved successfully
	SecretSavedMsg struct {
		TargetAlias string
		Path        string
	}

	// SecretSaveErrorMsg indicates secret save failed
	SecretSaveErrorMsg struct {
		TargetAlias string
		Path        string
		Err         error
	}

	// SecretDeletedMsg indicates a secret was deleted
	SecretDeletedMsg struct {
		TargetAlias string
		Path        string
	}

	// SecretDeleteErrorMsg indicates secret deletion failed
	SecretDeleteErrorMsg struct {
		TargetAlias string
		Path        string
		Err         error
	}
)

// Navigation messages
type (
	// NavigateToPathMsg requests navigation to a specific path
	NavigateToPathMsg struct {
		Path string
	}

	// SelectTargetMsg requests switching to a specific target
	SelectTargetMsg struct {
		TargetAlias string
	}

	// ChangeViewMsg requests a view change
	ChangeViewMsg struct {
		View ViewType
	}
)

// ViewType represents different views in the TUI
type ViewType int

const (
	ViewTargets ViewType = iota
	ViewBrowser
	ViewEditor
	ViewAdmin
	ViewCompare
)

// UI messages
type (
	// StatusMsg updates the status bar message
	StatusMsg struct {
		Message   string
		Level     StatusLevel
		Temporary bool
		Duration  time.Duration
	}

	// ClearStatusMsg clears the status message
	ClearStatusMsg struct{}

	// TickMsg is used for timed operations
	TickMsg struct {
		Time time.Time
	}

	// ErrorMsg represents an error to display
	ErrorMsg struct {
		Err error
	}

	// CopiedToClipboardMsg indicates successful clipboard copy
	CopiedToClipboardMsg struct {
		Content string
	}
)

// StatusLevel indicates the severity of a status message
type StatusLevel int

const (
	StatusInfo StatusLevel = iota
	StatusSuccess
	StatusWarning
	StatusError
)

// Modal messages
type (
	// ShowModalMsg requests showing a modal
	ShowModalMsg struct {
		Title   string
		Content string
		Actions []ModalAction
	}

	// CloseModalMsg requests closing the current modal
	CloseModalMsg struct{}

	// ModalActionMsg indicates a modal action was selected
	ModalActionMsg struct {
		ActionID string
	}
)

// ModalAction represents an action button in a modal
type ModalAction struct {
	ID     string
	Label  string
	Key    string
	Danger bool
}

// Command palette messages
type (
	// OpenPaletteMsg requests opening the command palette
	OpenPaletteMsg struct{}

	// ClosePaletteMsg requests closing the command palette
	ClosePaletteMsg struct{}

	// CommandSelectedMsg indicates a command was selected from the palette
	CommandSelectedMsg struct {
		CommandID string
	}
)

// Tab messages
type (
	// NewTabMsg requests opening a new tab
	NewTabMsg struct {
		TargetAlias string
	}

	// CloseTabMsg requests closing a tab
	CloseTabMsg struct {
		TabIndex int
	}

	// SwitchTabMsg requests switching to a tab
	SwitchTabMsg struct {
		TabIndex int
	}
)

// External editor messages
type (
	// EditorOpenedMsg indicates external editor was opened
	EditorOpenedMsg struct {
		Path     string
		TempFile string
	}

	// EditorClosedMsg indicates external editor was closed
	EditorClosedMsg struct {
		Path    string
		Content map[string]string
		Err     error
	}
)

// Admin messages
type (
	// VaultSealedMsg indicates vault is sealed
	VaultSealedMsg struct {
		TargetAlias string
	}

	// VaultUnsealedMsg indicates vault is unsealed
	VaultUnsealedMsg struct {
		TargetAlias string
	}

	// TokenRenewedMsg indicates token was renewed
	TokenRenewedMsg struct {
		TargetAlias string
		TTL         time.Duration
	}

	// TokenExpiredMsg indicates token has expired
	TokenExpiredMsg struct {
		TargetAlias string
	}
)
