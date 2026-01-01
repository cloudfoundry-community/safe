package view

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/tui/adapter"
)

// AdminOperation represents an admin operation type
type AdminOperation int

const (
	AdminOpNone AdminOperation = iota
	AdminOpInit
	AdminOpSeal
	AdminOpUnseal
	AdminOpRenew
	AdminOpRekey
	AdminOpExport
	AdminOpImport
)

// AdminState represents the current admin panel state
type AdminState int

const (
	AdminStateMenu AdminState = iota
	AdminStateInitForm
	AdminStateUnsealForm
	AdminStateRekeyForm
	AdminStateConfirm
	AdminStateProcessing
	AdminStateResult
)

// VaultStatus holds the current vault status information
type VaultStatus struct {
	Sealed       bool
	Version      string
	ClusterName  string
	ClusterID    string
	TokenTTL     time.Duration
	TokenExpiry  time.Time
	AuthMethod   string
	Initialized  bool
	Progress     int  // Unseal progress
	Threshold    int  // Keys needed to unseal
	NumKeys      int  // Total unseal keys
	RecoverySeal bool // Whether recovery keys are used
}

// AdminModel is the model for the admin panel view
type AdminModel struct {
	target string
	vault  *adapter.VaultAdapter
	status VaultStatus
	state  AdminState

	// Menu state
	menuCursor int
	menuItems  []adminMenuItem

	// Form state
	initForm   *AdminInitForm
	unsealForm *AdminUnsealForm
	rekeyForm  *AdminRekeyForm

	// Confirmation state
	confirmOp     AdminOperation
	confirmMsg    string
	confirmCursor int

	// Result state
	resultTitle   string
	resultContent string
	resultSuccess bool

	// Layout
	width  int
	height int

	// Key bindings
	keys adminKeyMap

	// Loading state
	loading bool
	err     error
}

type adminMenuItem struct {
	key       string
	label     string
	operation AdminOperation
	enabled   bool
	danger    bool
}

type adminKeyMap struct {
	Up      key.Binding
	Down    key.Binding
	Select  key.Binding
	Back    key.Binding
	Confirm key.Binding
	Cancel  key.Binding
	Help    key.Binding
}

func defaultAdminKeyMap() adminKeyMap {
	return adminKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/up", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/down", "down"),
		),
		Select: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		Confirm: key.NewBinding(
			key.WithKeys("y"),
			key.WithHelp("y", "confirm"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("n", "esc"),
			key.WithHelp("n/esc", "cancel"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
	}
}

// NewAdminModel creates a new admin model
func NewAdminModel(target string, vault *adapter.VaultAdapter) AdminModel {
	m := AdminModel{
		target:     target,
		vault:      vault,
		state:      AdminStateMenu,
		menuCursor: 0,
		keys:       defaultAdminKeyMap(),
		width:      80, // Default until WindowSizeMsg
		height:     24,
	}
	m.buildMenu()
	return m
}

// buildMenu builds the menu items based on current state
func (m *AdminModel) buildMenu() {
	m.menuItems = []adminMenuItem{
		{key: "i", label: "Initialize Vault", operation: AdminOpInit, enabled: !m.status.Initialized},
		{key: "s", label: "Seal Vault", operation: AdminOpSeal, enabled: m.status.Initialized && !m.status.Sealed, danger: true},
		{key: "u", label: "Unseal Vault", operation: AdminOpUnseal, enabled: m.status.Sealed},
		{key: "r", label: "Renew Token", operation: AdminOpRenew, enabled: m.status.Initialized && !m.status.Sealed},
		{key: "k", label: "Rekey Vault", operation: AdminOpRekey, enabled: m.status.Initialized && !m.status.Sealed, danger: true},
		{key: "e", label: "Export Secrets", operation: AdminOpExport, enabled: m.status.Initialized && !m.status.Sealed},
		{key: "I", label: "Import Secrets", operation: AdminOpImport, enabled: m.status.Initialized && !m.status.Sealed},
	}
}

// Init initializes the admin model
func (m AdminModel) Init() tea.Cmd {
	return m.loadStatus()
}

// loadStatus loads the vault status
func (m *AdminModel) loadStatus() tea.Cmd {
	return func() tea.Msg {
		if m.vault == nil || !m.vault.IsConnected() {
			return AdminStatusLoadedMsg{
				Status: VaultStatus{
					Sealed:      true,
					Initialized: false,
				},
			}
		}

		sealed, err := m.vault.Sealed()
		if err != nil {
			return AdminErrorMsg{Err: err}
		}

		status := VaultStatus{
			Sealed:      sealed,
			Initialized: true, // If we can connect, it's initialized
			Version:     "unknown",
			AuthMethod:  "token",
		}

		return AdminStatusLoadedMsg{Status: status}
	}
}

// Update handles messages
func (m AdminModel) Update(msg tea.Msg) (AdminModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case AdminStatusLoadedMsg:
		m.status = msg.Status
		m.loading = false
		m.buildMenu()
		return m, nil

	case AdminErrorMsg:
		m.err = msg.Err
		m.loading = false
		return m, nil

	case AdminOperationCompleteMsg:
		m.state = AdminStateResult
		m.resultTitle = msg.Title
		m.resultContent = msg.Content
		m.resultSuccess = msg.Success
		m.loading = false
		return m, nil

	case tea.KeyMsg:
		switch m.state {
		case AdminStateMenu:
			return m.updateMenu(msg)
		case AdminStateInitForm:
			return m.updateInitForm(msg)
		case AdminStateUnsealForm:
			return m.updateUnsealForm(msg)
		case AdminStateRekeyForm:
			return m.updateRekeyForm(msg)
		case AdminStateConfirm:
			return m.updateConfirm(msg)
		case AdminStateResult:
			return m.updateResult(msg)
		}
	}

	// Forward to active form
	switch m.state {
	case AdminStateInitForm:
		if m.initForm != nil {
			var cmd tea.Cmd
			*m.initForm, cmd = m.initForm.Update(msg)
			cmds = append(cmds, cmd)
		}
	case AdminStateUnsealForm:
		if m.unsealForm != nil {
			var cmd tea.Cmd
			*m.unsealForm, cmd = m.unsealForm.Update(msg)
			cmds = append(cmds, cmd)
		}
	case AdminStateRekeyForm:
		if m.rekeyForm != nil {
			var cmd tea.Cmd
			*m.rekeyForm, cmd = m.rekeyForm.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return m, tea.Batch(cmds...)
}

// updateMenu handles input in menu state
func (m AdminModel) updateMenu(msg tea.KeyMsg) (AdminModel, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back):
		return m, func() tea.Msg {
			return BackToTargetsMsg{}
		}

	case key.Matches(msg, m.keys.Up):
		m.menuCursor--
		if m.menuCursor < 0 {
			m.menuCursor = len(m.menuItems) - 1
		}

	case key.Matches(msg, m.keys.Down):
		m.menuCursor++
		if m.menuCursor >= len(m.menuItems) {
			m.menuCursor = 0
		}

	case key.Matches(msg, m.keys.Select):
		if m.menuCursor < len(m.menuItems) {
			item := m.menuItems[m.menuCursor]
			if item.enabled {
				return m.startOperation(item.operation)
			}
		}

	default:
		// Check for hotkey
		keyStr := msg.String()
		for _, item := range m.menuItems {
			if item.key == keyStr && item.enabled {
				return m.startOperation(item.operation)
			}
		}
	}

	return m, nil
}

// startOperation initiates an admin operation
func (m AdminModel) startOperation(op AdminOperation) (AdminModel, tea.Cmd) {
	switch op {
	case AdminOpInit:
		m.state = AdminStateInitForm
		form := NewAdminInitForm()
		m.initForm = &form
		return m, m.initForm.Init()

	case AdminOpSeal:
		m.state = AdminStateConfirm
		m.confirmOp = AdminOpSeal
		m.confirmMsg = "Are you sure you want to seal the vault? This will prevent all access until it is unsealed."
		m.confirmCursor = 1 // Default to "No"
		return m, nil

	case AdminOpUnseal:
		m.state = AdminStateUnsealForm
		form := NewAdminUnsealForm(m.status.Threshold)
		m.unsealForm = &form
		return m, m.unsealForm.Init()

	case AdminOpRenew:
		// Renew token immediately
		m.loading = true
		return m, m.renewToken()

	case AdminOpRekey:
		m.state = AdminStateRekeyForm
		form := NewAdminRekeyForm()
		m.rekeyForm = &form
		return m, m.rekeyForm.Init()

	case AdminOpExport:
		m.state = AdminStateConfirm
		m.confirmOp = AdminOpExport
		m.confirmMsg = "Export all secrets? This will output secrets to stdout."
		m.confirmCursor = 1
		return m, nil

	case AdminOpImport:
		m.state = AdminStateConfirm
		m.confirmOp = AdminOpImport
		m.confirmMsg = "Import secrets from a file?"
		m.confirmCursor = 1
		return m, nil
	}

	return m, nil
}

// updateConfirm handles input in confirm state
func (m AdminModel) updateConfirm(msg tea.KeyMsg) (AdminModel, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back), msg.String() == "n":
		m.state = AdminStateMenu
		return m, nil

	case msg.String() == "y":
		return m.executeOperation(m.confirmOp)

	case key.Matches(msg, m.keys.Select):
		if m.confirmCursor == 0 {
			return m.executeOperation(m.confirmOp)
		}
		m.state = AdminStateMenu
		return m, nil

	case msg.String() == "left", msg.String() == "h":
		m.confirmCursor = 0

	case msg.String() == "right", msg.String() == "l":
		m.confirmCursor = 1
	}

	return m, nil
}

// executeOperation executes the confirmed operation
func (m AdminModel) executeOperation(op AdminOperation) (AdminModel, tea.Cmd) {
	m.loading = true
	m.state = AdminStateProcessing

	switch op {
	case AdminOpSeal:
		return m, m.sealVault()
	case AdminOpExport:
		return m, m.exportSecrets()
	case AdminOpImport:
		return m, m.importSecrets()
	}

	return m, nil
}

// updateInitForm handles init form updates
func (m AdminModel) updateInitForm(msg tea.KeyMsg) (AdminModel, tea.Cmd) {
	if key.Matches(msg, m.keys.Back) {
		m.state = AdminStateMenu
		m.initForm = nil
		return m, nil
	}

	if m.initForm != nil && m.initForm.IsSubmitted() {
		m.loading = true
		m.state = AdminStateProcessing
		return m, m.initVault(m.initForm.NumKeys(), m.initForm.Threshold(), m.initForm.JSONOutput())
	}

	return m, nil
}

// updateUnsealForm handles unseal form updates
func (m AdminModel) updateUnsealForm(msg tea.KeyMsg) (AdminModel, tea.Cmd) {
	if key.Matches(msg, m.keys.Back) {
		m.state = AdminStateMenu
		m.unsealForm = nil
		return m, nil
	}

	if m.unsealForm != nil && m.unsealForm.IsComplete() {
		m.loading = true
		m.state = AdminStateProcessing
		return m, m.unsealVault(m.unsealForm.Keys())
	}

	return m, nil
}

// updateRekeyForm handles rekey form updates
func (m AdminModel) updateRekeyForm(msg tea.KeyMsg) (AdminModel, tea.Cmd) {
	if key.Matches(msg, m.keys.Back) {
		m.state = AdminStateMenu
		m.rekeyForm = nil
		return m, nil
	}

	if m.rekeyForm != nil && m.rekeyForm.IsSubmitted() {
		m.loading = true
		m.state = AdminStateProcessing
		return m, m.rekeyVault(m.rekeyForm.NumKeys(), m.rekeyForm.Threshold(), m.rekeyForm.GPGRecipients())
	}

	return m, nil
}

// updateResult handles result screen
func (m AdminModel) updateResult(msg tea.KeyMsg) (AdminModel, tea.Cmd) {
	if key.Matches(msg, m.keys.Back) || key.Matches(msg, m.keys.Select) {
		m.state = AdminStateMenu
		return m, m.loadStatus()
	}
	return m, nil
}

// Command functions

func (m *AdminModel) initVault(nkeys, threshold int, jsonOutput bool) tea.Cmd {
	return func() tea.Msg {
		if m.vault == nil {
			return AdminErrorMsg{Err: fmt.Errorf("not connected to vault")}
		}

		v := m.vault.Vault()
		if v == nil {
			return AdminErrorMsg{Err: fmt.Errorf("vault connection not available")}
		}

		keys, token, err := v.Init(nkeys, threshold)
		if err != nil {
			return AdminOperationCompleteMsg{
				Title:   "Initialization Failed",
				Content: fmt.Sprintf("Error: %v", err),
				Success: false,
			}
		}

		var content strings.Builder
		if jsonOutput {
			content.WriteString(fmt.Sprintf("{\n  \"root_token\": \"%s\",\n  \"seal_keys\": [\n", token))
			for i, k := range keys {
				if i > 0 {
					content.WriteString(",\n")
				}
				content.WriteString(fmt.Sprintf("    \"%s\"", k))
			}
			content.WriteString("\n  ]\n}")
		} else {
			content.WriteString("Vault initialized successfully!\n\n")
			content.WriteString("Root Token:\n")
			content.WriteString(fmt.Sprintf("  %s\n\n", token))
			content.WriteString("Unseal Keys:\n")
			for i, k := range keys {
				content.WriteString(fmt.Sprintf("  Key %d: %s\n", i+1, k))
			}
			content.WriteString("\n")
			content.WriteString(fmt.Sprintf("Keys: %d, Threshold: %d\n", nkeys, threshold))
			content.WriteString("\nSave these keys securely. They cannot be recovered!")
		}

		return AdminOperationCompleteMsg{
			Title:   "Vault Initialized",
			Content: content.String(),
			Success: true,
		}
	}
}

func (m *AdminModel) sealVault() tea.Cmd {
	return func() tea.Msg {
		if m.vault == nil {
			return AdminErrorMsg{Err: fmt.Errorf("not connected to vault")}
		}

		v := m.vault.Vault()
		if v == nil {
			return AdminErrorMsg{Err: fmt.Errorf("vault connection not available")}
		}

		sealed, err := v.Seal()
		if err != nil {
			return AdminOperationCompleteMsg{
				Title:   "Seal Failed",
				Content: fmt.Sprintf("Error: %v", err),
				Success: false,
			}
		}

		if sealed {
			return AdminOperationCompleteMsg{
				Title:   "Vault Sealed",
				Content: "The vault has been sealed successfully.\nAll access is now blocked until it is unsealed.",
				Success: true,
			}
		}

		return AdminOperationCompleteMsg{
			Title:   "Seal Status",
			Content: "Vault seal command executed, but vault is still unsealed.\nThis may happen on standby nodes.",
			Success: true,
		}
	}
}

func (m *AdminModel) unsealVault(keys []string) tea.Cmd {
	return func() tea.Msg {
		if m.vault == nil {
			return AdminErrorMsg{Err: fmt.Errorf("not connected to vault")}
		}

		v := m.vault.Vault()
		if v == nil {
			return AdminErrorMsg{Err: fmt.Errorf("vault connection not available")}
		}

		err := v.Unseal(keys)
		if err != nil {
			return AdminOperationCompleteMsg{
				Title:   "Unseal Failed",
				Content: fmt.Sprintf("Error: %v", err),
				Success: false,
			}
		}

		sealed, _ := v.Sealed()
		if !sealed {
			return AdminOperationCompleteMsg{
				Title:   "Vault Unsealed",
				Content: "The vault has been unsealed successfully.\nYou can now access secrets.",
				Success: true,
			}
		}

		return AdminOperationCompleteMsg{
			Title:   "Unseal Progress",
			Content: "Keys submitted. More keys may be required to complete unseal.",
			Success: true,
		}
	}
}

func (m *AdminModel) rekeyVault(nkeys, threshold int, pgpKeys []string) tea.Cmd {
	return func() tea.Msg {
		if m.vault == nil {
			return AdminErrorMsg{Err: fmt.Errorf("not connected to vault")}
		}

		v := m.vault.Vault()
		if v == nil {
			return AdminErrorMsg{Err: fmt.Errorf("vault connection not available")}
		}

		newKeys, err := v.ReKey(nkeys, threshold, pgpKeys)
		if err != nil {
			return AdminOperationCompleteMsg{
				Title:   "Rekey Failed",
				Content: fmt.Sprintf("Error: %v", err),
				Success: false,
			}
		}

		var content strings.Builder
		content.WriteString("Vault rekeyed successfully!\n\n")
		content.WriteString("New Unseal Keys:\n")
		for i, k := range newKeys {
			content.WriteString(fmt.Sprintf("  Key %d: %s\n", i+1, k))
		}
		content.WriteString(fmt.Sprintf("\nKeys: %d, Threshold: %d\n", nkeys, threshold))
		content.WriteString("\nSave these keys securely. The old keys are no longer valid!")

		return AdminOperationCompleteMsg{
			Title:   "Vault Rekeyed",
			Content: content.String(),
			Success: true,
		}
	}
}

func (m *AdminModel) renewToken() tea.Cmd {
	return func() tea.Msg {
		// Token renewal would typically be done through vault API
		// For now, return a placeholder
		return AdminOperationCompleteMsg{
			Title:   "Token Renewed",
			Content: "Token renewal is not yet implemented in the TUI.\nUse 'safe auth token' from the command line.",
			Success: false,
		}
	}
}

func (m *AdminModel) exportSecrets() tea.Cmd {
	return func() tea.Msg {
		return AdminOperationCompleteMsg{
			Title:   "Export Secrets",
			Content: "Secret export is not yet implemented in the TUI.\nUse 'safe export' from the command line.",
			Success: false,
		}
	}
}

func (m *AdminModel) importSecrets() tea.Cmd {
	return func() tea.Msg {
		return AdminOperationCompleteMsg{
			Title:   "Import Secrets",
			Content: "Secret import is not yet implemented in the TUI.\nUse 'safe import' from the command line.",
			Success: false,
		}
	}
}

// View renders the admin panel
func (m AdminModel) View() string {
	switch m.state {
	case AdminStateMenu:
		return m.renderMenu()
	case AdminStateInitForm:
		return m.renderInitForm()
	case AdminStateUnsealForm:
		return m.renderUnsealForm()
	case AdminStateRekeyForm:
		return m.renderRekeyForm()
	case AdminStateConfirm:
		return m.renderConfirm()
	case AdminStateProcessing:
		return m.renderProcessing()
	case AdminStateResult:
		return m.renderResult()
	default:
		return m.renderMenu()
	}
}

func (m AdminModel) renderMenu() string {
	var s strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("VAULT ADMINISTRATION"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 50))
	s.WriteString("\n\n")

	// Status section
	s.WriteString(m.renderStatus())
	s.WriteString("\n")

	// Operations section
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Bold(true)

	s.WriteString(headerStyle.Render("Operations"))
	s.WriteString("\n")

	for i, item := range m.menuItems {
		s.WriteString(m.renderMenuItem(item, i == m.menuCursor))
		s.WriteString("\n")
	}

	// Help hints
	s.WriteString("\n")
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	s.WriteString(hintStyle.Render("[j/k] navigate  [Enter] select  [Esc] back  [?] help"))
	s.WriteString("\n")

	return s.String()
}

func (m AdminModel) renderStatus() string {
	var s strings.Builder

	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Bold(true)

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Width(16)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))

	successStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6E3A1"))

	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F38BA8"))

	s.WriteString(headerStyle.Render("Status"))
	s.WriteString("\n")

	// Seal Status
	s.WriteString("├─ ")
	s.WriteString(labelStyle.Render("Seal Status:"))
	if m.status.Sealed {
		s.WriteString(errorStyle.Render("  Sealed"))
	} else {
		s.WriteString(successStyle.Render("  Unsealed"))
	}
	s.WriteString("\n")

	// Version
	s.WriteString("├─ ")
	s.WriteString(labelStyle.Render("Version:"))
	s.WriteString(valueStyle.Render("  " + m.status.Version))
	s.WriteString("\n")

	// Cluster
	s.WriteString("├─ ")
	s.WriteString(labelStyle.Render("Cluster:"))
	cluster := m.status.ClusterName
	if cluster == "" {
		cluster = m.status.ClusterID
	}
	if cluster == "" {
		cluster = "unknown"
	}
	s.WriteString(valueStyle.Render("  " + cluster))
	s.WriteString("\n")

	// Token TTL
	s.WriteString("├─ ")
	s.WriteString(labelStyle.Render("Token TTL:"))
	if m.status.TokenTTL > 0 {
		s.WriteString(valueStyle.Render("  " + formatDuration(m.status.TokenTTL)))
	} else {
		s.WriteString(valueStyle.Render("  unknown"))
	}
	s.WriteString("\n")

	// Auth Method
	s.WriteString("└─ ")
	s.WriteString(labelStyle.Render("Auth Method:"))
	s.WriteString(valueStyle.Render("  " + m.status.AuthMethod))
	s.WriteString("\n")

	return s.String()
}

func (m AdminModel) renderMenuItem(item adminMenuItem, selected bool) string {
	var s strings.Builder

	prefix := "  "
	if selected {
		prefix = "  "
	}
	s.WriteString(prefix)

	// Key indicator
	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA")).
		Bold(true)

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))

	disabledStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	dangerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F38BA8"))

	selectedStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("#45475A")).
		Foreground(lipgloss.Color("#FFFFFF")).
		Bold(true)

	content := fmt.Sprintf("[%s] %s", item.key, item.label)

	if !item.enabled {
		s.WriteString(disabledStyle.Render(content))
	} else if selected {
		paddedContent := content + strings.Repeat(" ", 40-len(content))
		s.WriteString(selectedStyle.Render(paddedContent))
	} else if item.danger {
		s.WriteString(keyStyle.Render("[" + item.key + "] "))
		s.WriteString(dangerStyle.Render(item.label))
	} else {
		s.WriteString(keyStyle.Render("[" + item.key + "] "))
		s.WriteString(labelStyle.Render(item.label))
	}

	return s.String()
}

func (m AdminModel) renderInitForm() string {
	if m.initForm == nil {
		return "Loading..."
	}
	return m.initForm.View()
}

func (m AdminModel) renderUnsealForm() string {
	if m.unsealForm == nil {
		return "Loading..."
	}
	return m.unsealForm.View()
}

func (m AdminModel) renderRekeyForm() string {
	if m.rekeyForm == nil {
		return "Loading..."
	}
	return m.rekeyForm.View()
}

func (m AdminModel) renderConfirm() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF")).
		Bold(true).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("CONFIRM"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 50))
	s.WriteString("\n\n")

	msgStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))
	s.WriteString(msgStyle.Render(m.confirmMsg))
	s.WriteString("\n\n")

	// Buttons
	activeStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("#7C6FE0")).
		Foreground(lipgloss.Color("#FFFFFF")).
		Padding(0, 2).
		Bold(true)

	inactiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4")).
		Padding(0, 2)

	if m.confirmCursor == 0 {
		s.WriteString(activeStyle.Render("Yes"))
		s.WriteString("  ")
		s.WriteString(inactiveStyle.Render("No"))
	} else {
		s.WriteString(inactiveStyle.Render("Yes"))
		s.WriteString("  ")
		s.WriteString(activeStyle.Render("No"))
	}
	s.WriteString("\n\n")

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	s.WriteString(hintStyle.Render("[y] confirm  [n/Esc] cancel"))

	return s.String()
}

func (m AdminModel) renderProcessing() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("PROCESSING"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 50))
	s.WriteString("\n\n")

	loadingStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA")).
		Italic(true)
	s.WriteString(loadingStyle.Render("Please wait..."))

	return s.String()
}

func (m AdminModel) renderResult() string {
	var s strings.Builder

	var titleStyle lipgloss.Style
	if m.resultSuccess {
		titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")).
			Bold(true).
			Padding(1, 0)
	} else {
		titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Bold(true).
			Padding(1, 0)
	}

	s.WriteString(titleStyle.Render(m.resultTitle))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 50))
	s.WriteString("\n\n")

	contentStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))
	s.WriteString(contentStyle.Render(m.resultContent))
	s.WriteString("\n\n")

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	s.WriteString(hintStyle.Render("[Enter/Esc] continue"))

	return s.String()
}

// Helper functions

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm remaining", hours, minutes)
	}
	return fmt.Sprintf("%dm remaining", minutes)
}

// Messages

// AdminStatusLoadedMsg is sent when vault status is loaded
type AdminStatusLoadedMsg struct {
	Status VaultStatus
}

// AdminErrorMsg is sent when an error occurs
type AdminErrorMsg struct {
	Err error
}

// AdminOperationCompleteMsg is sent when an operation completes
type AdminOperationCompleteMsg struct {
	Title   string
	Content string
	Success bool
}

// AdminBackMsg is sent to go back from admin view
type AdminBackMsg struct{}

// =============================================================================
// Admin Init Form
// =============================================================================

// AdminInitForm is the form for initializing a vault
type AdminInitForm struct {
	numKeysInput   textinput.Model
	thresholdInput textinput.Model
	jsonOutput     bool
	focusIndex     int
	submitted      bool
	cancelled      bool
	width          int
	height         int
}

// NewAdminInitForm creates a new init form
func NewAdminInitForm() AdminInitForm {
	numKeys := textinput.New()
	numKeys.Placeholder = "5"
	numKeys.CharLimit = 2
	numKeys.Width = 10
	numKeys.Focus()

	threshold := textinput.New()
	threshold.Placeholder = "3"
	threshold.CharLimit = 2
	threshold.Width = 10

	return AdminInitForm{
		numKeysInput:   numKeys,
		thresholdInput: threshold,
		jsonOutput:     false,
		focusIndex:     0,
	}
}

// Init initializes the form
func (f AdminInitForm) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles form updates
func (f AdminInitForm) Update(msg tea.Msg) (AdminInitForm, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.width = msg.Width
		f.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			f.focusIndex++
			if f.focusIndex > 2 {
				f.focusIndex = 0
			}
			f.updateFocus()

		case "shift+tab", "up":
			f.focusIndex--
			if f.focusIndex < 0 {
				f.focusIndex = 2
			}
			f.updateFocus()

		case "enter":
			if f.focusIndex == 2 {
				// Toggle JSON output
				f.jsonOutput = !f.jsonOutput
			}

		case "ctrl+s":
			f.submitted = true
			return f, nil

		case "esc":
			f.cancelled = true
			return f, nil

		case " ":
			if f.focusIndex == 2 {
				f.jsonOutput = !f.jsonOutput
			}
		}
	}

	// Update focused input
	switch f.focusIndex {
	case 0:
		var cmd tea.Cmd
		f.numKeysInput, cmd = f.numKeysInput.Update(msg)
		cmds = append(cmds, cmd)
	case 1:
		var cmd tea.Cmd
		f.thresholdInput, cmd = f.thresholdInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return f, tea.Batch(cmds...)
}

func (f *AdminInitForm) updateFocus() {
	f.numKeysInput.Blur()
	f.thresholdInput.Blur()

	switch f.focusIndex {
	case 0:
		f.numKeysInput.Focus()
	case 1:
		f.thresholdInput.Focus()
	}
}

// View renders the form
func (f AdminInitForm) View() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("INITIALIZE VAULT"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 40))
	s.WriteString("\n\n")

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Width(16)

	focusedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0"))

	// Number of keys
	s.WriteString(labelStyle.Render("Unseal Keys:"))
	if f.focusIndex == 0 {
		s.WriteString(focusedStyle.Render(f.numKeysInput.View()))
	} else {
		s.WriteString(f.numKeysInput.View())
	}
	s.WriteString("\n\n")

	// Threshold
	s.WriteString(labelStyle.Render("Threshold:"))
	if f.focusIndex == 1 {
		s.WriteString(focusedStyle.Render(f.thresholdInput.View()))
	} else {
		s.WriteString(f.thresholdInput.View())
	}
	s.WriteString("\n\n")

	// JSON output toggle
	checkboxStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA"))

	s.WriteString(labelStyle.Render("JSON Output:"))
	checkbox := "[ ]"
	if f.jsonOutput {
		checkbox = "[x]"
	}
	if f.focusIndex == 2 {
		s.WriteString(focusedStyle.Render(checkbox))
	} else {
		s.WriteString(checkboxStyle.Render(checkbox))
	}
	s.WriteString("\n\n")

	// Help
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	s.WriteString(hintStyle.Render("[Tab] next field  [Ctrl+S] submit  [Esc] cancel"))

	return s.String()
}

// NumKeys returns the number of keys
func (f *AdminInitForm) NumKeys() int {
	val := f.numKeysInput.Value()
	if val == "" {
		return 5
	}
	var n int
	_, _ = fmt.Sscanf(val, "%d", &n)
	if n <= 0 {
		return 5
	}
	return n
}

// Threshold returns the threshold
func (f *AdminInitForm) Threshold() int {
	val := f.thresholdInput.Value()
	if val == "" {
		nkeys := f.NumKeys()
		if nkeys > 3 {
			return nkeys - 2
		}
		return nkeys
	}
	var n int
	_, _ = fmt.Sscanf(val, "%d", &n)
	if n <= 0 {
		return 3
	}
	return n
}

// JSONOutput returns whether to output JSON
func (f *AdminInitForm) JSONOutput() bool {
	return f.jsonOutput
}

// IsSubmitted returns whether the form was submitted
func (f *AdminInitForm) IsSubmitted() bool {
	return f.submitted
}

// IsCancelled returns whether the form was cancelled
func (f *AdminInitForm) IsCancelled() bool {
	return f.cancelled
}

// =============================================================================
// Admin Unseal Form
// =============================================================================

// AdminUnsealForm is the form for unsealing a vault
type AdminUnsealForm struct {
	keyInputs  []textinput.Model
	threshold  int
	currentKey int
	keys       []string
	complete   bool
	cancelled  bool
	width      int
	height     int
}

// NewAdminUnsealForm creates a new unseal form
func NewAdminUnsealForm(threshold int) AdminUnsealForm {
	if threshold <= 0 {
		threshold = 3
	}

	inputs := make([]textinput.Model, threshold)
	for i := range inputs {
		inputs[i] = textinput.New()
		inputs[i].Placeholder = fmt.Sprintf("Unseal key %d", i+1)
		inputs[i].Width = 60
		inputs[i].EchoMode = textinput.EchoPassword
		inputs[i].EchoCharacter = '*'
	}
	inputs[0].Focus()

	return AdminUnsealForm{
		keyInputs:  inputs,
		threshold:  threshold,
		currentKey: 0,
		keys:       make([]string, 0, threshold),
	}
}

// Init initializes the form
func (f AdminUnsealForm) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles form updates
func (f AdminUnsealForm) Update(msg tea.Msg) (AdminUnsealForm, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.width = msg.Width
		f.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if f.currentKey < len(f.keyInputs) {
				key := f.keyInputs[f.currentKey].Value()
				if key != "" {
					f.keys = append(f.keys, key)
					f.keyInputs[f.currentKey].Blur()
					f.currentKey++
					if f.currentKey < len(f.keyInputs) {
						f.keyInputs[f.currentKey].Focus()
					} else {
						f.complete = true
					}
				}
			}

		case "esc":
			f.cancelled = true
			return f, nil

		case "ctrl+v":
			// Toggle visibility of current key
			if f.currentKey < len(f.keyInputs) {
				if f.keyInputs[f.currentKey].EchoMode == textinput.EchoPassword {
					f.keyInputs[f.currentKey].EchoMode = textinput.EchoNormal
				} else {
					f.keyInputs[f.currentKey].EchoMode = textinput.EchoPassword
				}
			}
		}
	}

	// Update current input
	if f.currentKey < len(f.keyInputs) {
		var cmd tea.Cmd
		f.keyInputs[f.currentKey], cmd = f.keyInputs[f.currentKey].Update(msg)
		cmds = append(cmds, cmd)
	}

	return f, tea.Batch(cmds...)
}

// View renders the form
func (f AdminUnsealForm) View() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("UNSEAL VAULT"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 40))
	s.WriteString("\n\n")

	// Progress
	progressStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA"))
	s.WriteString(progressStyle.Render(fmt.Sprintf("Progress: %d/%d keys", len(f.keys), f.threshold)))
	s.WriteString("\n\n")

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Width(16)

	completedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6E3A1"))

	for i := range f.keyInputs {
		label := fmt.Sprintf("Key %d:", i+1)
		s.WriteString(labelStyle.Render(label))

		if i < len(f.keys) {
			s.WriteString(completedStyle.Render(strings.Repeat("*", 20) + " "))
		} else if i == f.currentKey {
			s.WriteString(f.keyInputs[i].View())
		} else {
			s.WriteString("(pending)")
		}
		s.WriteString("\n\n")
	}

	// Help
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	s.WriteString(hintStyle.Render("[Enter] submit key  [Ctrl+V] toggle visibility  [Esc] cancel"))

	return s.String()
}

// Keys returns the entered keys
func (f *AdminUnsealForm) Keys() []string {
	return f.keys
}

// IsComplete returns whether all keys have been entered
func (f *AdminUnsealForm) IsComplete() bool {
	return f.complete
}

// IsCancelled returns whether the form was cancelled
func (f *AdminUnsealForm) IsCancelled() bool {
	return f.cancelled
}

// =============================================================================
// Admin Rekey Form
// =============================================================================

// AdminRekeyForm is the form for rekeying a vault
type AdminRekeyForm struct {
	numKeysInput   textinput.Model
	thresholdInput textinput.Model
	gpgInput       textinput.Model
	focusIndex     int
	submitted      bool
	cancelled      bool
	width          int
	height         int
}

// NewAdminRekeyForm creates a new rekey form
func NewAdminRekeyForm() AdminRekeyForm {
	numKeys := textinput.New()
	numKeys.Placeholder = "5"
	numKeys.CharLimit = 2
	numKeys.Width = 10
	numKeys.Focus()

	threshold := textinput.New()
	threshold.Placeholder = "3"
	threshold.CharLimit = 2
	threshold.Width = 10

	gpg := textinput.New()
	gpg.Placeholder = "email@example.com (optional)"
	gpg.Width = 40

	return AdminRekeyForm{
		numKeysInput:   numKeys,
		thresholdInput: threshold,
		gpgInput:       gpg,
		focusIndex:     0,
	}
}

// Init initializes the form
func (f AdminRekeyForm) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles form updates
func (f AdminRekeyForm) Update(msg tea.Msg) (AdminRekeyForm, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.width = msg.Width
		f.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			f.focusIndex++
			if f.focusIndex > 2 {
				f.focusIndex = 0
			}
			f.updateFocus()

		case "shift+tab", "up":
			f.focusIndex--
			if f.focusIndex < 0 {
				f.focusIndex = 2
			}
			f.updateFocus()

		case "ctrl+s":
			f.submitted = true
			return f, nil

		case "esc":
			f.cancelled = true
			return f, nil
		}
	}

	// Update focused input
	switch f.focusIndex {
	case 0:
		var cmd tea.Cmd
		f.numKeysInput, cmd = f.numKeysInput.Update(msg)
		cmds = append(cmds, cmd)
	case 1:
		var cmd tea.Cmd
		f.thresholdInput, cmd = f.thresholdInput.Update(msg)
		cmds = append(cmds, cmd)
	case 2:
		var cmd tea.Cmd
		f.gpgInput, cmd = f.gpgInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return f, tea.Batch(cmds...)
}

func (f *AdminRekeyForm) updateFocus() {
	f.numKeysInput.Blur()
	f.thresholdInput.Blur()
	f.gpgInput.Blur()

	switch f.focusIndex {
	case 0:
		f.numKeysInput.Focus()
	case 1:
		f.thresholdInput.Focus()
	case 2:
		f.gpgInput.Focus()
	}
}

// View renders the form
func (f AdminRekeyForm) View() string {
	var s strings.Builder

	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F38BA8")).
		Bold(true).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("REKEY VAULT"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 40))
	s.WriteString("\n\n")

	warningStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF"))
	s.WriteString(warningStyle.Render("Warning: This will invalidate all existing unseal keys!"))
	s.WriteString("\n\n")

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Width(16)

	focusedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0"))

	// Number of keys
	s.WriteString(labelStyle.Render("New Key Count:"))
	if f.focusIndex == 0 {
		s.WriteString(focusedStyle.Render(f.numKeysInput.View()))
	} else {
		s.WriteString(f.numKeysInput.View())
	}
	s.WriteString("\n\n")

	// Threshold
	s.WriteString(labelStyle.Render("Threshold:"))
	if f.focusIndex == 1 {
		s.WriteString(focusedStyle.Render(f.thresholdInput.View()))
	} else {
		s.WriteString(f.thresholdInput.View())
	}
	s.WriteString("\n\n")

	// GPG recipients
	s.WriteString(labelStyle.Render("GPG Recipients:"))
	if f.focusIndex == 2 {
		s.WriteString(focusedStyle.Render(f.gpgInput.View()))
	} else {
		s.WriteString(f.gpgInput.View())
	}
	s.WriteString("\n\n")

	// Help
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	s.WriteString(hintStyle.Render("[Tab] next field  [Ctrl+S] submit  [Esc] cancel"))

	return s.String()
}

// NumKeys returns the number of keys
func (f *AdminRekeyForm) NumKeys() int {
	val := f.numKeysInput.Value()
	if val == "" {
		return 5
	}
	var n int
	_, _ = fmt.Sscanf(val, "%d", &n)
	if n <= 0 {
		return 5
	}
	return n
}

// Threshold returns the threshold
func (f *AdminRekeyForm) Threshold() int {
	val := f.thresholdInput.Value()
	if val == "" {
		nkeys := f.NumKeys()
		if nkeys > 3 {
			return nkeys - 2
		}
		return nkeys
	}
	var n int
	_, _ = fmt.Sscanf(val, "%d", &n)
	if n <= 0 {
		return 3
	}
	return n
}

// GPGRecipients returns the GPG recipients
func (f *AdminRekeyForm) GPGRecipients() []string {
	val := strings.TrimSpace(f.gpgInput.Value())
	if val == "" {
		return nil
	}
	// Split by comma or space
	parts := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || r == ' '
	})
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// IsSubmitted returns whether the form was submitted
func (f *AdminRekeyForm) IsSubmitted() bool {
	return f.submitted
}

// IsCancelled returns whether the form was cancelled
func (f *AdminRekeyForm) IsCancelled() bool {
	return f.cancelled
}
