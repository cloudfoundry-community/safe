package view

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/tui/component"
	"github.com/cloudfoundry-community/safe/vault"
)

// X509ViewMode represents the current mode of the X509 view
type X509ViewMode int

const (
	X509ModeList X509ViewMode = iota
	X509ModeDetails
	X509ModeIssue
)

// CertificateInfo holds parsed certificate information
type CertificateInfo struct {
	Path          string
	Subject       string
	Issuer        string
	Serial        string
	NotBefore     time.Time
	NotAfter      time.Time
	KeySize       int
	SANs          []string
	KeyUsage      string
	IsCA          bool
	IsExpired     bool
	DaysRemaining int
	SignatureAlgo string
}

// X509Model is the model for the X509 management view
type X509Model struct {
	target      string
	vault       *adapter.VaultAdapter
	treeAdapter *adapter.TreeAdapter

	// View mode
	mode X509ViewMode

	// Tree component for certificate list
	tree component.Tree

	// Certificate details
	selectedPath    string
	selectedCert    *CertificateInfo
	detailsViewport viewport.Model

	// Certificate form (for issue mode)
	certForm *component.CertForm

	// Layout
	width      int
	height     int
	splitRatio float64

	// State
	loading    bool
	err        error
	message    string
	messageErr bool

	// Keys
	keys x509KeyMap
}

type x509KeyMap struct {
	Up       key.Binding
	Down     key.Binding
	Expand   key.Binding
	Collapse key.Binding
	Select   key.Binding
	Back     key.Binding
	Refresh  key.Binding
	Issue    key.Binding
	Revoke   key.Binding
	Renew    key.Binding
	Validate key.Binding
	Copy     key.Binding
	Help     key.Binding
}

func defaultX509KeyMap() x509KeyMap {
	return x509KeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/up", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/down", "down"),
		),
		Expand: key.NewBinding(
			key.WithKeys("enter", "l", "right"),
			key.WithHelp("enter/l", "expand/select"),
		),
		Collapse: key.NewBinding(
			key.WithKeys("h", "left"),
			key.WithHelp("h/left", "collapse/parent"),
		),
		Select: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r", "R"),
			key.WithHelp("r", "refresh"),
		),
		Issue: key.NewBinding(
			key.WithKeys("i"),
			key.WithHelp("i", "issue new"),
		),
		Revoke: key.NewBinding(
			key.WithKeys("v"),
			key.WithHelp("v", "revoke"),
		),
		Renew: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "renew"),
		),
		Validate: key.NewBinding(
			key.WithKeys("V"),
			key.WithHelp("V", "validate"),
		),
		Copy: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "copy PEM"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
	}
}

// NewX509Model creates a new X509 model
func NewX509Model(target string, vaultAdapter *adapter.VaultAdapter) X509Model {
	tree := component.NewTree()
	treeAdapter := adapter.NewTreeAdapter(vaultAdapter)

	return X509Model{
		target:          target,
		vault:           vaultAdapter,
		treeAdapter:     treeAdapter,
		tree:            tree,
		mode:            X509ModeList,
		splitRatio:      0.4,
		keys:            defaultX509KeyMap(),
		detailsViewport: viewport.New(0, 0),
		width:           80, // Default until WindowSizeMsg
		height:          24,
	}
}

// Init initializes the X509 view
func (m X509Model) Init() tea.Cmd {
	return m.loadRoot()
}

// loadRoot loads the root of the certificate tree
func (m *X509Model) loadRoot() tea.Cmd {
	return func() tea.Msg {
		root, err := m.treeAdapter.BuildRootNode()
		if err != nil {
			return X509ErrorMsg{Err: err}
		}
		return X509TreeLoadedMsg{Root: root}
	}
}

// Update handles messages
func (m X509Model) Update(msg tea.Msg) (X509Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()

	case X509TreeLoadedMsg:
		m.tree.SetRoot(msg.Root)
		m.loading = false
		m.tree.Expand("/")
		return m, nil

	case X509TreeChildrenLoadedMsg:
		m.tree.SetChildren(msg.Path, msg.Children)
		m.tree.SetLoading(msg.Path, false)
		return m, nil

	case X509CertLoadedMsg:
		m.selectedCert = msg.Cert
		m.updateDetailsViewport()
		return m, nil

	case X509ErrorMsg:
		m.err = msg.Err
		m.message = msg.Err.Error()
		m.messageErr = true
		m.loading = false
		return m, nil

	case X509CertIssuedMsg:
		m.message = fmt.Sprintf("Certificate issued at %s", msg.Path)
		m.messageErr = false
		m.mode = X509ModeList
		return m, m.loadRoot()

	case X509CertRevokedMsg:
		m.message = fmt.Sprintf("Certificate at %s revoked", msg.Path)
		m.messageErr = false
		return m, nil

	case X509CertRenewedMsg:
		m.message = fmt.Sprintf("Certificate at %s renewed", msg.Path)
		m.messageErr = false
		return m, m.loadCertificate(msg.Path)

	case X509CertValidatedMsg:
		if msg.Valid {
			m.message = fmt.Sprintf("Certificate at %s is valid", msg.Path)
			m.messageErr = false
		} else {
			m.message = fmt.Sprintf("Certificate validation failed: %s", msg.Error)
			m.messageErr = true
		}
		return m, nil

	case component.TreeExpandMsg:
		m.tree.SetLoading(msg.Path, true)
		return m, m.loadChildren(msg.Path)

	case component.TreeSelectMsg:
		if msg.IsSecret {
			m.selectedPath = msg.Path
			m.mode = X509ModeDetails
			return m, m.loadCertificate(msg.Path)
		}

	case component.CertFormSubmittedMsg:
		m.mode = X509ModeList
		return m, m.issueCertificate(msg.Values)

	case component.CertFormCancelledMsg:
		m.mode = X509ModeList
		m.certForm = nil
		return m, nil

	case tea.KeyMsg:
		// Handle mode-specific keys
		switch m.mode {
		case X509ModeList:
			return m.updateListMode(msg)
		case X509ModeDetails:
			return m.updateDetailsMode(msg)
		case X509ModeIssue:
			return m.updateIssueMode(msg)
		}
	}

	return m, tea.Batch(cmds...)
}

// updateListMode handles keys in list mode
func (m X509Model) updateListMode(msg tea.KeyMsg) (X509Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back):
		return m, func() tea.Msg {
			return BackToTargetsMsg{}
		}

	case key.Matches(msg, m.keys.Refresh):
		m.loading = true
		return m, m.loadRoot()

	case key.Matches(msg, m.keys.Issue):
		m.mode = X509ModeIssue
		certForm := component.NewCertForm()
		m.certForm = &certForm
		return m, nil
	}

	// Forward to tree
	var cmd tea.Cmd
	m.tree, cmd = m.tree.Update(msg)
	return m, cmd
}

// updateDetailsMode handles keys in details mode
func (m X509Model) updateDetailsMode(msg tea.KeyMsg) (X509Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back):
		m.mode = X509ModeList
		m.selectedCert = nil
		return m, nil

	case key.Matches(msg, m.keys.Renew):
		if m.selectedPath != "" {
			return m, m.renewCertificate(m.selectedPath)
		}

	case key.Matches(msg, m.keys.Revoke):
		if m.selectedPath != "" && m.selectedCert != nil {
			// Need to determine the CA that signed this cert
			return m, m.revokeCertificate(m.selectedPath)
		}

	case key.Matches(msg, m.keys.Validate):
		if m.selectedPath != "" {
			return m, m.validateCertificate(m.selectedPath)
		}

	case key.Matches(msg, m.keys.Copy):
		if m.selectedPath != "" {
			return m, func() tea.Msg {
				return X509CopyPEMMsg{Path: m.selectedPath}
			}
		}
	}

	// Handle viewport scrolling
	var cmd tea.Cmd
	m.detailsViewport, cmd = m.detailsViewport.Update(msg)
	return m, cmd
}

// updateIssueMode handles keys in issue mode
func (m X509Model) updateIssueMode(msg tea.KeyMsg) (X509Model, tea.Cmd) {
	if m.certForm != nil {
		var cmd tea.Cmd
		*m.certForm, cmd = m.certForm.Update(msg)
		return m, cmd
	}
	return m, nil
}

// loadChildren loads children for a path
func (m *X509Model) loadChildren(path string) tea.Cmd {
	return func() tea.Msg {
		children, err := m.treeAdapter.LoadChildren(path)
		if err != nil {
			return X509ErrorMsg{Err: err}
		}
		return X509TreeChildrenLoadedMsg{Path: path, Children: children}
	}
}

// loadCertificate loads a certificate for viewing
func (m *X509Model) loadCertificate(path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := m.vault.Read(path)
		if err != nil {
			return X509ErrorMsg{Err: err}
		}

		cert, err := parseCertificateInfo(path, secret)
		if err != nil {
			return X509ErrorMsg{Err: err}
		}

		return X509CertLoadedMsg{Cert: cert}
	}
}

// issueCertificate issues a new certificate
func (m *X509Model) issueCertificate(values component.CertFormValues) tea.Cmd {
	return func() tea.Msg {
		// Build the certificate using vault.NewCertificate
		cert, err := vault.NewCertificate(
			values.Subject(),
			values.SANs,
			values.KeyUsageList(),
			values.SignatureAlgorithm,
			values.KeyBits,
		)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to create certificate: %w", err)}
		}

		// Make it a CA if requested
		if values.IsCA {
			cert.MakeCA()
		}

		// Get the signing CA if specified
		var signingCA *vault.X509
		if values.SignedBy != "" {
			caSecret, err := m.vault.Read(values.SignedBy)
			if err != nil {
				return X509ErrorMsg{Err: fmt.Errorf("failed to read CA: %w", err)}
			}
			signingCA, err = caSecret.X509(true)
			if err != nil {
				return X509ErrorMsg{Err: fmt.Errorf("failed to parse CA: %w", err)}
			}
		} else {
			// Self-signed
			signingCA = cert
		}

		// Parse TTL
		ttl := parseTTL(values.TTL)

		// Sign the certificate
		err = signingCA.Sign(cert, ttl)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to sign certificate: %w", err)}
		}

		// Save to vault
		err = cert.SaveTo(m.vault.Vault(), values.OutputPath, false)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to save certificate: %w", err)}
		}

		// If we used an external CA, save its updated state (serial number)
		if values.SignedBy != "" {
			err = signingCA.SaveTo(m.vault.Vault(), values.SignedBy, false)
			if err != nil {
				return X509ErrorMsg{Err: fmt.Errorf("failed to update CA: %w", err)}
			}
		}

		return X509CertIssuedMsg{Path: values.OutputPath}
	}
}

// renewCertificate renews a certificate
func (m *X509Model) renewCertificate(path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := m.vault.Read(path)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to read certificate: %w", err)}
		}

		cert, err := secret.X509(true)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to parse certificate: %w", err)}
		}

		// Calculate original TTL from certificate dates
		originalTTL := cert.Certificate.NotAfter.Sub(cert.Certificate.NotBefore)

		// Re-sign with the same key
		if cert.IsCA() {
			// Self-signed CA - sign itself
			err = cert.Sign(cert, originalTTL)
		} else {
			// Need to find and use the signing CA
			// For now, we'll just self-sign if we can't determine the CA
			err = cert.Sign(cert, originalTTL)
		}

		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to renew certificate: %w", err)}
		}

		err = cert.SaveTo(m.vault.Vault(), path, false)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to save renewed certificate: %w", err)}
		}

		return X509CertRenewedMsg{Path: path}
	}
}

// revokeCertificate revokes a certificate
func (m *X509Model) revokeCertificate(path string) tea.Cmd {
	return func() tea.Msg {
		// Read the certificate to revoke
		certSecret, err := m.vault.Read(path)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to read certificate: %w", err)}
		}

		cert, err := certSecret.X509(false)
		if err != nil {
			return X509ErrorMsg{Err: fmt.Errorf("failed to parse certificate: %w", err)}
		}

		// We need the CA to revoke - for now, this is a simplified version
		// In a full implementation, we'd need to determine the CA path
		// or have it provided by the user
		return X509ErrorMsg{Err: fmt.Errorf("certificate revocation requires specifying the signing CA path (issuer: %s)", cert.Issuer())}
	}
}

// validateCertificate validates a certificate
func (m *X509Model) validateCertificate(path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := m.vault.Read(path)
		if err != nil {
			return X509CertValidatedMsg{Path: path, Valid: false, Error: err.Error()}
		}

		cert, err := secret.X509(true)
		if err != nil {
			return X509CertValidatedMsg{Path: path, Valid: false, Error: err.Error()}
		}

		// Validate key pair match
		err = cert.Validate()
		if err != nil {
			return X509CertValidatedMsg{Path: path, Valid: false, Error: err.Error()}
		}

		// Check expiration
		if cert.Expired() {
			return X509CertValidatedMsg{Path: path, Valid: false, Error: "certificate has expired"}
		}

		return X509CertValidatedMsg{Path: path, Valid: true}
	}
}

// updateLayout updates component sizes based on window size
func (m *X509Model) updateLayout() {
	treeWidth := int(float64(m.width) * m.splitRatio)
	detailsWidth := m.width - treeWidth - 3

	m.tree.SetSize(treeWidth, m.height-4)
	m.detailsViewport.Width = detailsWidth
	m.detailsViewport.Height = m.height - 6
}

// updateDetailsViewport updates the details viewport content
func (m *X509Model) updateDetailsViewport() {
	if m.selectedCert == nil {
		m.detailsViewport.SetContent("")
		return
	}

	content := m.renderCertificateDetails(m.selectedCert)
	m.detailsViewport.SetContent(content)
}

// View renders the X509 view
func (m X509Model) View() string {
	if m.loading {
		return m.renderLoading()
	}

	switch m.mode {
	case X509ModeList:
		return m.renderListView()
	case X509ModeDetails:
		return m.renderDetailsView()
	case X509ModeIssue:
		return m.renderIssueView()
	default:
		return m.renderListView()
	}
}

func (m X509Model) renderLoading() string {
	loadingStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)
	return loadingStyle.Render("  Loading certificates...")
}

func (m X509Model) renderListView() string {
	var s strings.Builder

	// Header
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true)

	s.WriteString(headerStyle.Render("X.509 CERTIFICATE MANAGER"))
	s.WriteString("  ")

	targetStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA"))
	s.WriteString(targetStyle.Render("[" + m.target + "]"))
	s.WriteString("\n")
	dividerWidth := m.width - 2
	if dividerWidth < 1 {
		dividerWidth = 1
	}
	s.WriteString(strings.Repeat("─", dividerWidth))
	s.WriteString("\n")

	// Message if any
	if m.message != "" {
		var msgStyle lipgloss.Style
		if m.messageErr {
			msgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F38BA8"))
		} else {
			msgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#A6E3A1"))
		}
		s.WriteString(msgStyle.Render(m.message))
		s.WriteString("\n")
	}

	// Main content: tree on left, preview on right
	treeWidth := int(float64(m.width) * m.splitRatio)
	previewWidth := m.width - treeWidth - 3

	// Tree pane
	treePane := lipgloss.NewStyle().
		Width(treeWidth).
		Height(m.height - 6).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#45475A"))

	// Preview pane
	previewPane := lipgloss.NewStyle().
		Width(previewWidth).
		Height(m.height - 6).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#45475A"))

	treeContent := m.tree.View()
	previewContent := m.renderQuickPreview()

	s.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Top,
		treePane.Render(treeContent),
		previewPane.Render(previewContent),
	))
	s.WriteString("\n")

	// Help hints
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	hints := "[j/k] navigate  [Enter] select  [i] issue  [r] refresh  [Esc] back"
	s.WriteString(hintStyle.Render(hints))

	return s.String()
}

func (m X509Model) renderQuickPreview() string {
	node := m.tree.SelectedNode()
	if node == nil || !node.IsSecret {
		mutedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Italic(true)
		return mutedStyle.Render("Select a certificate to preview")
	}

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6E3A1")).
		Render(fmt.Sprintf("Press Enter to view: %s", node.Name))
}

func (m X509Model) renderDetailsView() string {
	if m.selectedCert == nil {
		return m.renderLoading()
	}

	var s strings.Builder

	// Header
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true)

	s.WriteString(headerStyle.Render("CERTIFICATE: "))

	pathStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6E3A1"))
	s.WriteString(pathStyle.Render(m.selectedPath))
	s.WriteString("\n")
	detailsWidth := m.width - 2
	if detailsWidth < 1 {
		detailsWidth = 1
	}
	s.WriteString(strings.Repeat("─", detailsWidth))
	s.WriteString("\n\n")

	// Certificate details
	s.WriteString(m.renderCertificateDetails(m.selectedCert))
	s.WriteString("\n")

	// Action hints
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	hints := "[n] Renew   [v] Revoke   [c] Copy PEM   [V] Validate   [Esc] Back"
	s.WriteString(hintStyle.Render(hints))

	return s.String()
}

func (m X509Model) renderCertificateDetails(cert *CertificateInfo) string {
	var s strings.Builder

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Width(14)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))

	highlightStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF"))

	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F38BA8"))

	successStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6E3A1"))

	// Subject
	s.WriteString(labelStyle.Render("Subject:"))
	s.WriteString(valueStyle.Render(cert.Subject))
	s.WriteString("\n")

	// Issuer
	s.WriteString(labelStyle.Render("Issuer:"))
	s.WriteString(valueStyle.Render(cert.Issuer))
	s.WriteString("\n")

	// Serial
	s.WriteString(labelStyle.Render("Serial:"))
	s.WriteString(valueStyle.Render(cert.Serial))
	s.WriteString("\n")

	// Validity dates
	s.WriteString(labelStyle.Render("Not Before:"))
	s.WriteString(valueStyle.Render(cert.NotBefore.Format("2006-01-02 15:04:05 MST")))
	s.WriteString("\n")

	s.WriteString(labelStyle.Render("Not After:"))
	if cert.IsExpired {
		s.WriteString(errorStyle.Render(cert.NotAfter.Format("2006-01-02 15:04:05 MST") + " (EXPIRED)"))
	} else if cert.DaysRemaining <= 30 {
		s.WriteString(highlightStyle.Render(fmt.Sprintf("%s (%d days remaining)",
			cert.NotAfter.Format("2006-01-02 15:04:05 MST"), cert.DaysRemaining)))
	} else {
		s.WriteString(successStyle.Render(fmt.Sprintf("%s (%d days remaining)",
			cert.NotAfter.Format("2006-01-02 15:04:05 MST"), cert.DaysRemaining)))
	}
	s.WriteString("\n")

	// Key size
	s.WriteString(labelStyle.Render("Key Size:"))
	s.WriteString(valueStyle.Render(fmt.Sprintf("%d bits", cert.KeySize)))
	s.WriteString("\n")

	// CA status
	if cert.IsCA {
		s.WriteString(labelStyle.Render("CA:"))
		s.WriteString(highlightStyle.Render("Yes (Certificate Authority)"))
		s.WriteString("\n")
	}

	// Signature algorithm
	s.WriteString(labelStyle.Render("Algorithm:"))
	s.WriteString(valueStyle.Render(cert.SignatureAlgo))
	s.WriteString("\n")

	// SANs
	if len(cert.SANs) > 0 {
		s.WriteString("\n")
		s.WriteString(labelStyle.Render("SANs:"))
		s.WriteString("\n")
		for _, san := range cert.SANs {
			s.WriteString("  - ")
			s.WriteString(valueStyle.Render(san))
			s.WriteString("\n")
		}
	}

	// Key usage
	if cert.KeyUsage != "" {
		s.WriteString("\n")
		s.WriteString(labelStyle.Render("Key Usage:"))
		s.WriteString(valueStyle.Render(cert.KeyUsage))
		s.WriteString("\n")
	}

	return s.String()
}

func (m X509Model) renderIssueView() string {
	if m.certForm == nil {
		return "Loading form..."
	}
	return m.certForm.View()
}

// parseCertificateInfo parses certificate information from a vault secret
func parseCertificateInfo(path string, secret *vault.Secret) (*CertificateInfo, error) {
	x509Cert, err := secret.X509(false)
	if err != nil {
		return nil, err
	}

	cert := x509Cert.Certificate

	// Collect SANs
	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, email)
	}

	// Format key usage
	keyUsage := formatKeyUsage(x509Cert)

	// Calculate days remaining
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
	}

	// Get key size
	keySize := 0
	if x509Cert.PrivateKey != nil {
		keySize = x509Cert.PrivateKey.N.BitLen()
	} else if cert.PublicKey != nil {
		// Try to get from public key
		switch pk := cert.PublicKey.(type) {
		case interface{ Size() int }:
			keySize = pk.Size() * 8
		}
	}

	return &CertificateInfo{
		Path:          path,
		Subject:       x509Cert.Subject(),
		Issuer:        x509Cert.Issuer(),
		Serial:        x509Cert.FormatSerial(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		KeySize:       keySize,
		SANs:          sans,
		KeyUsage:      keyUsage,
		IsCA:          x509Cert.IsCA(),
		IsExpired:     x509Cert.Expired(),
		DaysRemaining: daysRemaining,
		SignatureAlgo: cert.SignatureAlgorithm.String(),
	}, nil
}

// formatKeyUsage formats key usage flags
func formatKeyUsage(x509 *vault.X509) string {
	var usages []string

	cert := x509.Certificate

	// Standard key usage
	if cert.KeyUsage&1 != 0 { // DigitalSignature
		usages = append(usages, "Digital Signature")
	}
	if cert.KeyUsage&4 != 0 { // KeyEncipherment
		usages = append(usages, "Key Encipherment")
	}
	if cert.KeyUsage&8 != 0 { // DataEncipherment
		usages = append(usages, "Data Encipherment")
	}
	if cert.KeyUsage&16 != 0 { // KeyAgreement
		usages = append(usages, "Key Agreement")
	}
	if cert.KeyUsage&32 != 0 { // CertSign
		usages = append(usages, "Cert Sign")
	}
	if cert.KeyUsage&64 != 0 { // CRLSign
		usages = append(usages, "CRL Sign")
	}

	// Extended key usage
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case 1: // ServerAuth
			usages = append(usages, "Server Auth")
		case 2: // ClientAuth
			usages = append(usages, "Client Auth")
		case 3: // CodeSigning
			usages = append(usages, "Code Signing")
		case 4: // EmailProtection
			usages = append(usages, "Email Protection")
		case 8: // TimeStamping
			usages = append(usages, "Time Stamping")
		}
	}

	return strings.Join(usages, ", ")
}

// parseTTL parses a TTL string like "365d" or "1y" into a duration
func parseTTL(ttl string) time.Duration {
	if ttl == "" {
		return 365 * 24 * time.Hour
	}

	var value int
	var unit string
	_, err := fmt.Sscanf(ttl, "%d%s", &value, &unit)
	if err != nil || value <= 0 {
		return 365 * 24 * time.Hour
	}

	switch strings.ToLower(unit) {
	case "d", "day", "days":
		return time.Duration(value) * 24 * time.Hour
	case "w", "week", "weeks":
		return time.Duration(value) * 7 * 24 * time.Hour
	case "m", "month", "months":
		return time.Duration(value) * 30 * 24 * time.Hour
	case "y", "year", "years":
		return time.Duration(value) * 365 * 24 * time.Hour
	case "h", "hour", "hours":
		return time.Duration(value) * time.Hour
	default:
		return 365 * 24 * time.Hour
	}
}

// Messages

// X509TreeLoadedMsg is sent when the certificate tree is loaded
type X509TreeLoadedMsg struct {
	Root *component.TreeNode
}

// X509TreeChildrenLoadedMsg is sent when children are loaded
type X509TreeChildrenLoadedMsg struct {
	Path     string
	Children []*component.TreeNode
}

// X509CertLoadedMsg is sent when a certificate is loaded for viewing
type X509CertLoadedMsg struct {
	Cert *CertificateInfo
}

// X509ErrorMsg is sent when an error occurs
type X509ErrorMsg struct {
	Err error
}

// X509CertIssuedMsg is sent when a certificate is issued
type X509CertIssuedMsg struct {
	Path string
}

// X509CertRevokedMsg is sent when a certificate is revoked
type X509CertRevokedMsg struct {
	Path string
}

// X509CertRenewedMsg is sent when a certificate is renewed
type X509CertRenewedMsg struct {
	Path string
}

// X509CertValidatedMsg is sent when a certificate is validated
type X509CertValidatedMsg struct {
	Path  string
	Valid bool
	Error string
}

// X509CopyPEMMsg is sent when copying PEM content
type X509CopyPEMMsg struct {
	Path string
}
