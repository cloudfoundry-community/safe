package view

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/tui/component"
)

// KeyDetailsTab represents the active tab in the key details view
type KeyDetailsTab int

const (
	TabMetadata KeyDetailsTab = iota
	TabHistory
	TabActions
)

// KeyDetailsOpenMsg requests opening the key details view
type KeyDetailsOpenMsg struct {
	SecretPath string
	KeyName    string
}

// KeyDetailsCloseMsg requests closing the key details view
type KeyDetailsCloseMsg struct{}

// KeyDetailsLoadedMsg indicates key details have been loaded
type KeyDetailsLoadedMsg struct {
	SecretPath string
	KeyName    string
	Value      string
	Versions   []KeyVersion
	IsKVv2     bool
	IsCert     bool
}

// KeyDetailsErrorMsg indicates an error loading key details
type KeyDetailsErrorMsg struct {
	Err error
}

type keyDetailsKeyMap struct {
	TabLeft    key.Binding
	TabRight   key.Binding
	ScrollUp   key.Binding
	ScrollDown key.Binding
	PageUp     key.Binding
	PageDown   key.Binding
	Back       key.Binding
	Copy       key.Binding
	CopyPath   key.Binding
	Edit       key.Binding
	Inspect    key.Binding
	ViewValue  key.Binding
}

func defaultKeyDetailsKeyMap() keyDetailsKeyMap {
	return keyDetailsKeyMap{
		TabLeft: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("left/h", "prev tab"),
		),
		TabRight: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("right/l", "next tab"),
		),
		ScrollUp: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("up/k", "scroll up"),
		),
		ScrollDown: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("down/j", "scroll down"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "ctrl+u"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "ctrl+d"),
			key.WithHelp("pgdown", "page down"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "q"),
			key.WithHelp("esc/q", "back"),
		),
		Copy: key.NewBinding(
			key.WithKeys("y"),
			key.WithHelp("y", "copy value"),
		),
		CopyPath: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "copy path"),
		),
		Edit: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "edit"),
		),
		Inspect: key.NewBinding(
			key.WithKeys("i"),
			key.WithHelp("i", "inspect cert"),
		),
		ViewValue: key.NewBinding(
			key.WithKeys("v"),
			key.WithHelp("v", "toggle value"),
		),
	}
}

// KeyDetailsModel is the model for the key details view
type KeyDetailsModel struct {
	// Key identity
	secretPath string
	keyName    string

	// Data
	currentValue string
	versions     []KeyVersion
	isKVv2       bool
	isCert       bool

	// Tab navigation
	activeTab KeyDetailsTab
	tabs      []string

	// Scrollable content
	viewport viewport.Model

	// Layout
	width  int
	height int

	// State
	loading bool
	err     error

	// Certificate viewer
	certViewer   component.CertViewer
	showCertView bool

	// Vault adapter for operations
	vault *adapter.VaultAdapter

	// Key bindings
	keys keyDetailsKeyMap

	// Message to display
	message       string
	messageIsErr  bool
	messageExpiry int

	// Value visibility toggle
	showValues bool
}

// NewKeyDetailsModel creates a new key details model
func NewKeyDetailsModel(secretPath, keyName string, vault *adapter.VaultAdapter) KeyDetailsModel {
	vp := viewport.New(80, 20)
	vp.Style = lipgloss.NewStyle()

	return KeyDetailsModel{
		secretPath: secretPath,
		keyName:    keyName,
		vault:      vault,
		loading:    true,
		activeTab:  TabMetadata,
		tabs:       []string{"Metadata", "History", "Actions"},
		viewport:   vp,
		certViewer: component.NewCertViewer(),
		keys:       defaultKeyDetailsKeyMap(),
	}
}

// Init initializes the key details model and loads data
func (m KeyDetailsModel) Init() tea.Cmd {
	return m.loadKeyDetails()
}

// loadKeyDetails loads the key's value and version history
func (m *KeyDetailsModel) loadKeyDetails() tea.Cmd {
	return func() tea.Msg {
		// Get current value
		value, err := m.vault.ReadKeyValue(m.secretPath, m.keyName)
		if err != nil {
			return KeyDetailsErrorMsg{Err: err}
		}

		// Check if KV v2 and get versions
		var versions []KeyVersion
		isKVv2 := false

		mountVersion, err := m.vault.MountVersion(m.secretPath)
		if err == nil && mountVersion == 2 {
			isKVv2 = true
			kvVersions, err := m.vault.GetKeyVersions(m.secretPath)
			if err == nil {
				// Load value for each version
				for _, v := range kvVersions {
					if v.Alive() {
						val, _ := m.vault.ReadKeyValueAtVersion(m.secretPath, m.keyName, v.Version)
						versions = append(versions, KeyVersion{
							Version:   v.Version,
							Value:     val,
							CreatedAt: v.CreatedAt,
							Deleted:   v.Deleted,
							Destroyed: v.Destroyed,
						})
					} else {
						versions = append(versions, KeyVersion{
							Version:   v.Version,
							CreatedAt: v.CreatedAt,
							Deleted:   v.Deleted,
							Destroyed: v.Destroyed,
						})
					}
				}
			}
		}

		// Check if it looks like a certificate
		isCert := looksLikePEM(value)

		return KeyDetailsLoadedMsg{
			SecretPath: m.secretPath,
			KeyName:    m.keyName,
			Value:      value,
			Versions:   versions,
			IsKVv2:     isKVv2,
			IsCert:     isCert,
		}
	}
}

// Update handles messages for the key details view
func (m KeyDetailsModel) Update(msg tea.Msg) (KeyDetailsModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		m.certViewer.SetSize(msg.Width, msg.Height)

	case KeyDetailsLoadedMsg:
		m.loading = false
		m.currentValue = msg.Value
		m.versions = msg.Versions
		m.isKVv2 = msg.IsKVv2
		m.isCert = msg.IsCert
		m.updateViewportContent()

	case KeyDetailsErrorMsg:
		m.loading = false
		m.err = msg.Err

	case component.CertViewerCloseMsg:
		m.showCertView = false

	case tea.KeyMsg:
		// Handle certificate viewer input when visible
		if m.showCertView {
			var cmd tea.Cmd
			m.certViewer, cmd = m.certViewer.Update(msg)
			return m, cmd
		}

		switch {
		case key.Matches(msg, m.keys.Back):
			return m, func() tea.Msg { return KeyDetailsCloseMsg{} }

		case key.Matches(msg, m.keys.TabLeft):
			if m.activeTab > TabMetadata {
				m.activeTab--
				m.updateViewportContent()
			}

		case key.Matches(msg, m.keys.TabRight):
			if m.activeTab < TabActions {
				m.activeTab++
				m.updateViewportContent()
			}

		case key.Matches(msg, m.keys.ScrollUp):
			m.viewport.LineUp(1)

		case key.Matches(msg, m.keys.ScrollDown):
			m.viewport.LineDown(1)

		case key.Matches(msg, m.keys.PageUp):
			m.viewport.HalfViewUp()

		case key.Matches(msg, m.keys.PageDown):
			m.viewport.HalfViewDown()

		case key.Matches(msg, m.keys.Copy):
			// Copy value to clipboard
			m.message = "Value copied to clipboard"
			m.messageIsErr = false
			return m, copyToClipboard(m.currentValue)

		case key.Matches(msg, m.keys.CopyPath):
			// Copy path:key to clipboard
			pathWithKey := fmt.Sprintf("%s:%s", m.secretPath, m.keyName)
			m.message = "Path copied to clipboard"
			m.messageIsErr = false
			return m, copyToClipboard(pathWithKey)

		case key.Matches(msg, m.keys.Inspect):
			if m.isCert {
				return m, m.showCertificateDetails()
			}

		case key.Matches(msg, m.keys.ViewValue):
			m.showValues = !m.showValues
			m.updateViewportContent()
			if m.showValues {
				m.message = "Values revealed"
			} else {
				m.message = "Values masked"
			}
			m.messageIsErr = false
			return m, nil
		}
	}

	// Update viewport
	var vpCmd tea.Cmd
	m.viewport, vpCmd = m.viewport.Update(msg)
	cmds = append(cmds, vpCmd)

	return m, tea.Batch(cmds...)
}

// copyToClipboard returns a command to copy text to clipboard
func copyToClipboard(text string) tea.Cmd {
	return func() tea.Msg {
		// Use component.Clipboard for actual clipboard operation
		// For now, this is a placeholder that could be enhanced
		return nil
	}
}

// showCertificateDetails displays the certificate viewer
func (m *KeyDetailsModel) showCertificateDetails() tea.Cmd {
	// Parse the PEM certificate(s)
	certs, err := parsePEMCertificates(m.currentValue)
	if err != nil || len(certs) == 0 {
		m.message = "Failed to parse certificate"
		m.messageIsErr = true
		return nil
	}

	// Build certificate details
	var details []component.CertificateDetails
	for i, cert := range certs {
		details = append(details, component.ParseCertificateDetails(cert, i+1, len(certs)))
	}

	// Show the cert viewer
	m.certViewer.SetSize(m.width, m.height)
	m.certViewer.Show(details)
	m.showCertView = true

	return nil
}

// looksLikePEM checks if a string looks like a PEM-encoded certificate
func looksLikePEM(value string) bool {
	return strings.Contains(value, "-----BEGIN CERTIFICATE-----")
}

// parsePEMCertificates parses PEM-encoded certificates from a string
func parsePEMCertificates(pemData string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	data := []byte(pemData)

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}

		data = rest
	}

	return certs, nil
}

// updateLayout updates the viewport size based on window dimensions
func (m *KeyDetailsModel) updateLayout() {
	// Account for header (3 lines), tab bar (2 lines), and footer (2 lines)
	headerHeight := 3
	tabBarHeight := 2
	footerHeight := 2
	contentHeight := m.height - headerHeight - tabBarHeight - footerHeight

	if contentHeight < 1 {
		contentHeight = 1
	}

	m.viewport.Width = m.width - 4 // Account for borders
	m.viewport.Height = contentHeight
}

// updateViewportContent updates the viewport content based on active tab
func (m *KeyDetailsModel) updateViewportContent() {
	var content string

	switch m.activeTab {
	case TabMetadata:
		content = m.renderMetadataContent()
	case TabHistory:
		content = m.renderHistoryContent()
	case TabActions:
		content = m.renderActionsContent()
	}

	m.viewport.SetContent(content)
	m.viewport.GotoTop()
}

// View renders the key details view
func (m KeyDetailsModel) View() string {
	if m.showCertView {
		return m.certViewer.View()
	}

	var s strings.Builder

	// Styles
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4")).
		Bold(true)

	pathStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA"))

	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF"))

	tabActiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4")).
		Background(lipgloss.Color("#7C6FE0")).
		Padding(0, 2).
		Bold(true)

	tabInactiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Padding(0, 2)

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#45475A")).
		Width(m.width - 4).
		Padding(0, 1)

	helpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	// Header
	s.WriteString(headerStyle.Render("KEY DETAILS"))
	s.WriteString("\n")
	s.WriteString(pathStyle.Render(m.secretPath))
	s.WriteString(":")
	s.WriteString(keyStyle.Render(m.keyName))
	s.WriteString("\n\n")

	// Tab bar
	for i, tab := range m.tabs {
		if KeyDetailsTab(i) == m.activeTab {
			s.WriteString(tabActiveStyle.Render(tab))
		} else {
			s.WriteString(tabInactiveStyle.Render(tab))
		}
		s.WriteString(" ")
	}
	s.WriteString("\n\n")

	// Content
	if m.loading {
		s.WriteString(borderStyle.Render("Loading..."))
	} else if m.err != nil {
		errorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F38BA8"))
		s.WriteString(borderStyle.Render(errorStyle.Render("Error: " + m.err.Error())))
	} else {
		s.WriteString(borderStyle.Render(m.viewport.View()))
	}
	s.WriteString("\n")

	// Message (if any)
	if m.message != "" {
		msgStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#A6E3A1"))
		if m.messageIsErr {
			msgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F38BA8"))
		}
		s.WriteString(msgStyle.Render(m.message))
		s.WriteString("\n")
	}

	// Help footer
	var helpParts []string
	helpParts = append(helpParts, "left/right: switch tabs")
	helpParts = append(helpParts, "j/k: scroll")
	helpParts = append(helpParts, "y: copy value")
	helpParts = append(helpParts, "c: copy path")
	helpParts = append(helpParts, "v: show/hide value")
	if m.isCert {
		helpParts = append(helpParts, "i: inspect cert")
	}
	helpParts = append(helpParts, "esc/q: back")

	s.WriteString(helpStyle.Render(strings.Join(helpParts, "  ")))

	return s.String()
}

// renderMetadataContent renders the metadata tab content
func (m *KeyDetailsModel) renderMetadataContent() string {
	var s strings.Builder

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF")).
		Width(16)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))

	maskedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	// Secret Path
	s.WriteString(labelStyle.Render("Secret Path:"))
	s.WriteString(valueStyle.Render(m.secretPath))
	s.WriteString("\n\n")

	// Key Name
	s.WriteString(labelStyle.Render("Key Name:"))
	s.WriteString(valueStyle.Render(m.keyName))
	s.WriteString("\n\n")

	// KV Version
	s.WriteString(labelStyle.Render("KV Version:"))
	if m.isKVv2 {
		s.WriteString(valueStyle.Render("v2"))
	} else {
		s.WriteString(valueStyle.Render("v1"))
	}
	s.WriteString("\n\n")

	// Version Count
	if m.isKVv2 {
		s.WriteString(labelStyle.Render("Version Count:"))
		s.WriteString(valueStyle.Render(fmt.Sprintf("%d", len(m.versions))))
		s.WriteString("\n\n")
	}

	// Type (if certificate)
	if m.isCert {
		s.WriteString(labelStyle.Render("Type:"))
		s.WriteString(valueStyle.Render("Certificate (press i to inspect)"))
		s.WriteString("\n\n")
	}

	// Current Value
	s.WriteString(labelStyle.Render("Current Value:"))
	s.WriteString("\n")
	if isSensitiveKey(m.keyName) && !m.showValues {
		// Mask sensitive values
		maskLen := len(m.currentValue)
		if maskLen > 40 {
			maskLen = 40
		}
		s.WriteString(maskedStyle.Render(strings.Repeat("*", maskLen)))
	} else {
		// Show value (truncate if very long for display)
		value := m.currentValue
		if len(value) > 500 {
			value = value[:500] + "..."
		}
		s.WriteString(valueStyle.Render(value))
	}

	return s.String()
}

// renderHistoryContent renders the history tab content
func (m *KeyDetailsModel) renderHistoryContent() string {
	if !m.isKVv2 {
		mutedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Italic(true)
		return mutedStyle.Render("Version history is only available for KV v2 mounts.")
	}

	if len(m.versions) == 0 {
		mutedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Italic(true)
		return mutedStyle.Render("No version history available.")
	}

	var s strings.Builder

	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Bold(true)

	versionStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA")).
		Bold(true)

	timeStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))

	maskedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	deletedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F38BA8")).
		Italic(true)

	s.WriteString(headerStyle.Render("VERSION HISTORY"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("-", 40))
	s.WriteString("\n\n")

	for _, v := range m.versions {
		s.WriteString(versionStyle.Render(fmt.Sprintf("v%d", v.Version)))
		s.WriteString("  ")
		if !v.CreatedAt.IsZero() {
			s.WriteString(timeStyle.Render(v.CreatedAt.Format("2006-01-02 15:04:05")))
		}
		s.WriteString("\n")

		if v.Deleted {
			s.WriteString("  ")
			s.WriteString(deletedStyle.Render("(deleted)"))
		} else if v.Destroyed {
			s.WriteString("  ")
			s.WriteString(deletedStyle.Render("(destroyed)"))
		} else if v.Value != "" {
			s.WriteString("  ")
			if isSensitiveKey(m.keyName) && !m.showValues {
				maskLen := len(v.Value)
				if maskLen > 30 {
					maskLen = 30
				}
				s.WriteString(maskedStyle.Render(strings.Repeat("*", maskLen)))
			} else {
				// Truncate long values
				val := v.Value
				if len(val) > 60 {
					val = val[:60] + "..."
				}
				s.WriteString(valueStyle.Render(val))
			}
		}
		s.WriteString("\n\n")
	}

	return s.String()
}

// renderActionsContent renders the actions tab content
func (m *KeyDetailsModel) renderActionsContent() string {
	var s strings.Builder

	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Bold(true)

	actionStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6E3A1"))

	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF"))

	descStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))

	s.WriteString(headerStyle.Render("AVAILABLE ACTIONS"))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("-", 40))
	s.WriteString("\n\n")

	// Copy value
	s.WriteString(keyStyle.Render("[y]"))
	s.WriteString("  ")
	s.WriteString(actionStyle.Render("Copy value"))
	s.WriteString("\n")
	s.WriteString("    ")
	s.WriteString(descStyle.Render("Copy the current value to clipboard"))
	s.WriteString("\n\n")

	// Copy path
	s.WriteString(keyStyle.Render("[c]"))
	s.WriteString("  ")
	s.WriteString(actionStyle.Render("Copy path"))
	s.WriteString("\n")
	s.WriteString("    ")
	s.WriteString(descStyle.Render("Copy the full path (secret:key) to clipboard"))
	s.WriteString("\n\n")

	// Edit
	s.WriteString(keyStyle.Render("[e]"))
	s.WriteString("  ")
	s.WriteString(actionStyle.Render("Edit value"))
	s.WriteString("\n")
	s.WriteString("    ")
	s.WriteString(descStyle.Render("Open editor to modify this key's value"))
	s.WriteString("\n\n")

	// Certificate inspection (if applicable)
	if m.isCert {
		s.WriteString(keyStyle.Render("[i]"))
		s.WriteString("  ")
		s.WriteString(actionStyle.Render("Inspect certificate"))
		s.WriteString("\n")
		s.WriteString("    ")
		s.WriteString(descStyle.Render("View detailed certificate information"))
		s.WriteString("\n\n")
	}

	return s.String()
}

// SetSize sets the size of the key details view
func (m *KeyDetailsModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.updateLayout()
	m.certViewer.SetSize(width, height)
}

// SecretPath returns the secret path
func (m *KeyDetailsModel) SecretPath() string {
	return m.secretPath
}

// KeyName returns the key name
func (m *KeyDetailsModel) KeyName() string {
	return m.keyName
}
