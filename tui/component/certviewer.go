package component

import (
	"crypto/sha1" //nolint:gosec // SHA1 used for certificate fingerprints per industry standard
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// CertificateDetails contains all parsed certificate information for display
type CertificateDetails struct {
	// Basic info
	Version       int
	Serial        string // Colon-separated hex
	SignatureAlgo string

	// Subject/Issuer
	Subject string
	Issuer  string

	// Validity
	NotBefore     time.Time
	NotAfter      time.Time
	IsExpired     bool
	DaysRemaining int

	// Public Key
	PublicKeyAlgorithm string
	KeySize            int
	Modulus            string // First/last bytes hex
	Exponent           int

	// X509v3 Extensions
	IsCA           bool
	MaxPathLen     int
	MaxPathLenZero bool
	KeyUsage       []string
	ExtKeyUsage    []string
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []string
	SubjectKeyID   string
	AuthorityKeyID string
	CRLDistPoints  []string
	OCSPServers    []string
	IssuingCertURL []string

	// Fingerprints
	SHA1Fingerprint   string
	SHA256Fingerprint string

	// Chain info
	ChainPosition int
	ChainLength   int
}

// CertViewerStyles contains styles for the certificate viewer overlay
type CertViewerStyles struct {
	Container  lipgloss.Style
	Title      lipgloss.Style
	Section    lipgloss.Style
	Label      lipgloss.Style
	Value      lipgloss.Style
	Highlight  lipgloss.Style
	Warning    lipgloss.Style
	Error      lipgloss.Style
	Divider    lipgloss.Style
	Footer     lipgloss.Style
	Border     lipgloss.Style
	Indented   lipgloss.Style
	SubSection lipgloss.Style
}

type certViewerKeyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	NextCert key.Binding
	PrevCert key.Binding
	Close    key.Binding
}

// CertViewer is a modal overlay component for displaying certificate details
type CertViewer struct {
	viewport   viewport.Model
	details    []CertificateDetails // Main cert + intermediaries
	chainIndex int
	visible    bool
	width      int
	height     int
	styles     CertViewerStyles
	keys       certViewerKeyMap
}

// DefaultCertViewerStyles returns the default styles for the certificate viewer
func DefaultCertViewerStyles() CertViewerStyles {
	return CertViewerStyles{
		Container: lipgloss.NewStyle().
			Background(lipgloss.Color("#1E1E2E")).
			Padding(1, 2),

		Title: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Bold(true).
			Align(lipgloss.Center),

		Section: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6ADC8")).
			Bold(true).
			MarginTop(1),

		Label: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")),

		Value: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")),

		Highlight: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")),

		Warning: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")),

		Error: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")),

		Divider: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#45475A")),

		Footer: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Align(lipgloss.Center),

		Border: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C6FE0")),

		Indented: lipgloss.NewStyle().
			PaddingLeft(4),

		SubSection: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")).
			PaddingLeft(4),
	}
}

func defaultCertViewerKeyMap() certViewerKeyMap {
	return certViewerKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/up", "scroll up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/down", "scroll down"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "ctrl+u"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "ctrl+d"),
			key.WithHelp("pgdown", "page down"),
		),
		NextCert: key.NewBinding(
			key.WithKeys("n", "tab"),
			key.WithHelp("n/tab", "next cert"),
		),
		PrevCert: key.NewBinding(
			key.WithKeys("p", "shift+tab"),
			key.WithHelp("p", "prev cert"),
		),
		Close: key.NewBinding(
			key.WithKeys("i", "esc", "q", "enter"),
			key.WithHelp("i/esc", "close"),
		),
	}
}

// NewCertViewer creates a new certificate viewer
func NewCertViewer() CertViewer {
	return CertViewer{
		viewport: viewport.New(0, 0),
		styles:   DefaultCertViewerStyles(),
		keys:     defaultCertViewerKeyMap(),
		visible:  false,
		width:    80,
		height:   24,
	}
}

// Init initializes the certificate viewer
func (c CertViewer) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (c CertViewer) Update(msg tea.Msg) (CertViewer, tea.Cmd) {
	if !c.visible {
		return c, nil
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		c.width = msg.Width
		c.height = msg.Height
		c.updateViewport()

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, c.keys.Close):
			c.visible = false
			return c, func() tea.Msg {
				return CertViewerCloseMsg{}
			}

		case key.Matches(msg, c.keys.Up):
			c.viewport.LineUp(1)

		case key.Matches(msg, c.keys.Down):
			c.viewport.LineDown(1)

		case key.Matches(msg, c.keys.PageUp):
			c.viewport.HalfViewUp()

		case key.Matches(msg, c.keys.PageDown):
			c.viewport.HalfViewDown()

		case key.Matches(msg, c.keys.NextCert):
			if c.chainIndex < len(c.details)-1 {
				c.chainIndex++
				c.updateViewport()
			}

		case key.Matches(msg, c.keys.PrevCert):
			if c.chainIndex > 0 {
				c.chainIndex--
				c.updateViewport()
			}
		}
	}

	return c, nil
}

// updateViewport updates the viewport content
func (c *CertViewer) updateViewport() {
	// Calculate dimensions with padding for border
	innerWidth := c.width - 12  // Room for borders and padding
	innerHeight := c.height - 8 // Room for title, dividers, footer, borders

	if innerWidth < 60 {
		innerWidth = 60
	}
	if innerHeight < 10 {
		innerHeight = 10
	}

	c.viewport.Width = innerWidth
	c.viewport.Height = innerHeight // Viewport fills available space

	// Build content for current certificate in chain
	if len(c.details) > 0 && c.chainIndex < len(c.details) {
		c.viewport.SetContent(c.formatCertificate(c.details[c.chainIndex], innerWidth))
		c.viewport.GotoTop() // Reset scroll position for new content
	}
}

// formatCertificate formats a certificate in OpenSSL-like output
func (c *CertViewer) formatCertificate(cert CertificateDetails, width int) string {
	var s strings.Builder

	// Certificate header
	s.WriteString(c.styles.Section.Render("Certificate:"))
	s.WriteString("\n")
	s.WriteString(c.styles.SubSection.Render("Data:"))
	s.WriteString("\n")

	// Version
	s.WriteString(c.formatLine("Version", fmt.Sprintf("%d (0x%x)", cert.Version, cert.Version-1), 8))

	// Serial Number
	s.WriteString(c.formatLine("Serial Number", "", 8))
	s.WriteString(c.styles.Indented.Render(c.styles.Value.Render(cert.Serial)))
	s.WriteString("\n")

	// Signature Algorithm
	s.WriteString(c.formatLine("Signature Algorithm", cert.SignatureAlgo, 8))

	// Issuer
	s.WriteString(c.formatLine("Issuer", cert.Issuer, 8))

	// Validity
	s.WriteString(c.styles.Indented.PaddingLeft(8).Render(c.styles.Label.Render("Validity")))
	s.WriteString("\n")

	notBeforeStyle := c.styles.Value
	s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
		c.styles.Label.Render("Not Before: ") + notBeforeStyle.Render(cert.NotBefore.Format("Jan 02 15:04:05 2006 MST"))))
	s.WriteString("\n")

	// Color code the expiry based on status
	notAfterStyle := c.styles.Value
	expiryInfo := ""
	if cert.IsExpired {
		notAfterStyle = c.styles.Error
		expiryInfo = " (EXPIRED)"
	} else if cert.DaysRemaining <= 30 {
		notAfterStyle = c.styles.Warning
		expiryInfo = fmt.Sprintf(" (%d days remaining)", cert.DaysRemaining)
	} else {
		notAfterStyle = c.styles.Highlight
		expiryInfo = fmt.Sprintf(" (%d days remaining)", cert.DaysRemaining)
	}
	s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
		c.styles.Label.Render("Not After:  ") + notAfterStyle.Render(cert.NotAfter.Format("Jan 02 15:04:05 2006 MST")+expiryInfo)))
	s.WriteString("\n")

	// Subject
	s.WriteString(c.formatLine("Subject", cert.Subject, 8))

	// Subject Public Key Info
	s.WriteString(c.styles.Indented.PaddingLeft(8).Render(c.styles.Label.Render("Subject Public Key Info:")))
	s.WriteString("\n")
	s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
		c.styles.Label.Render("Public Key Algorithm: ") + c.styles.Value.Render(cert.PublicKeyAlgorithm)))
	s.WriteString("\n")
	if cert.KeySize > 0 {
		s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
			c.styles.Label.Render("Public-Key: ") + c.styles.Value.Render(fmt.Sprintf("(%d bit)", cert.KeySize))))
		s.WriteString("\n")
	}
	if cert.Modulus != "" {
		s.WriteString(c.styles.Indented.PaddingLeft(16).Render(c.styles.Label.Render("Modulus:")))
		s.WriteString("\n")
		// Split modulus into lines of reasonable length
		modLines := c.wrapHex(cert.Modulus, 45)
		for _, line := range modLines {
			s.WriteString(c.styles.Indented.PaddingLeft(20).Render(c.styles.Value.Render(line)))
			s.WriteString("\n")
		}
	}
	if cert.Exponent > 0 {
		s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
			c.styles.Label.Render("Exponent: ") + c.styles.Value.Render(fmt.Sprintf("%d (0x%x)", cert.Exponent, cert.Exponent))))
		s.WriteString("\n")
	}

	// X509v3 Extensions
	if c.hasExtensions(cert) {
		s.WriteString(c.styles.Indented.PaddingLeft(8).Render(c.styles.Label.Render("X509v3 extensions:")))
		s.WriteString("\n")

		// Basic Constraints
		if cert.IsCA || cert.MaxPathLenZero {
			caStr := "FALSE"
			if cert.IsCA {
				caStr = "TRUE"
			}
			pathLen := ""
			if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
				pathLen = fmt.Sprintf(", pathlen:%d", cert.MaxPathLen)
			}
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("X509v3 Basic Constraints: ") + c.styles.Value.Render("critical")))
			s.WriteString("\n")
			s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
				c.styles.Value.Render(fmt.Sprintf("CA:%s%s", caStr, pathLen))))
			s.WriteString("\n")
		}

		// Key Usage
		if len(cert.KeyUsage) > 0 {
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("X509v3 Key Usage: ") + c.styles.Value.Render("critical")))
			s.WriteString("\n")
			s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
				c.styles.Value.Render(strings.Join(cert.KeyUsage, ", "))))
			s.WriteString("\n")
		}

		// Extended Key Usage
		if len(cert.ExtKeyUsage) > 0 {
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("X509v3 Extended Key Usage:")))
			s.WriteString("\n")
			s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
				c.styles.Value.Render(strings.Join(cert.ExtKeyUsage, ", "))))
			s.WriteString("\n")
		}

		// Subject Alternative Name
		if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("X509v3 Subject Alternative Name:")))
			s.WriteString("\n")
			var sans []string
			for _, dns := range cert.DNSNames {
				sans = append(sans, "DNS:"+dns)
			}
			for _, ip := range cert.IPAddresses {
				sans = append(sans, "IP Address:"+ip.String())
			}
			for _, email := range cert.EmailAddresses {
				sans = append(sans, "email:"+email)
			}
			for _, uri := range cert.URIs {
				sans = append(sans, "URI:"+uri)
			}
			// Wrap SANs to multiple lines if needed
			sanStr := strings.Join(sans, ", ")
			if len(sanStr) > 60 {
				for _, san := range sans {
					s.WriteString(c.styles.Indented.PaddingLeft(16).Render(c.styles.Value.Render(san)))
					s.WriteString("\n")
				}
			} else {
				s.WriteString(c.styles.Indented.PaddingLeft(16).Render(c.styles.Value.Render(sanStr)))
				s.WriteString("\n")
			}
		}

		// Subject Key Identifier
		if cert.SubjectKeyID != "" {
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("X509v3 Subject Key Identifier:")))
			s.WriteString("\n")
			s.WriteString(c.styles.Indented.PaddingLeft(16).Render(c.styles.Value.Render(cert.SubjectKeyID)))
			s.WriteString("\n")
		}

		// Authority Key Identifier
		if cert.AuthorityKeyID != "" {
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("X509v3 Authority Key Identifier:")))
			s.WriteString("\n")
			s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
				c.styles.Value.Render("keyid:" + cert.AuthorityKeyID)))
			s.WriteString("\n")
		}

		// CRL Distribution Points
		if len(cert.CRLDistPoints) > 0 {
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("X509v3 CRL Distribution Points:")))
			s.WriteString("\n")
			for _, crl := range cert.CRLDistPoints {
				s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
					c.styles.Value.Render("URI:" + crl)))
				s.WriteString("\n")
			}
		}

		// Authority Information Access
		if len(cert.OCSPServers) > 0 || len(cert.IssuingCertURL) > 0 {
			s.WriteString(c.styles.Indented.PaddingLeft(12).Render(
				c.styles.Label.Render("Authority Information Access:")))
			s.WriteString("\n")
			for _, ocsp := range cert.OCSPServers {
				s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
					c.styles.Value.Render("OCSP - URI:" + ocsp)))
				s.WriteString("\n")
			}
			for _, ca := range cert.IssuingCertURL {
				s.WriteString(c.styles.Indented.PaddingLeft(16).Render(
					c.styles.Value.Render("CA Issuers - URI:" + ca)))
				s.WriteString("\n")
			}
		}
	}

	// Fingerprints
	s.WriteString(c.styles.Section.Render("Fingerprints:"))
	s.WriteString("\n")
	if cert.SHA1Fingerprint != "" {
		s.WriteString(c.formatLine("SHA-1", cert.SHA1Fingerprint, 4))
	}
	if cert.SHA256Fingerprint != "" {
		s.WriteString(c.formatLine("SHA-256", cert.SHA256Fingerprint, 4))
	}

	return s.String()
}

// formatLine formats a label-value pair with proper indentation
func (c *CertViewer) formatLine(label, value string, indent int) string {
	indentStr := strings.Repeat(" ", indent)
	return indentStr + c.styles.Label.Render(label+": ") + c.styles.Value.Render(value) + "\n"
}

// wrapHex wraps a hex string into multiple lines
func (c *CertViewer) wrapHex(hex string, lineLen int) []string {
	var lines []string
	for len(hex) > lineLen {
		lines = append(lines, hex[:lineLen])
		hex = hex[lineLen:]
	}
	if len(hex) > 0 {
		lines = append(lines, hex)
	}
	return lines
}

// hasExtensions checks if the certificate has any extensions to display
func (c *CertViewer) hasExtensions(cert CertificateDetails) bool {
	return cert.IsCA ||
		len(cert.KeyUsage) > 0 ||
		len(cert.ExtKeyUsage) > 0 ||
		len(cert.DNSNames) > 0 ||
		len(cert.IPAddresses) > 0 ||
		len(cert.EmailAddresses) > 0 ||
		cert.SubjectKeyID != "" ||
		cert.AuthorityKeyID != "" ||
		len(cert.CRLDistPoints) > 0 ||
		len(cert.OCSPServers) > 0 ||
		len(cert.IssuingCertURL) > 0
}

// View renders the certificate viewer overlay
func (c CertViewer) View() string {
	if !c.visible {
		return ""
	}

	var s strings.Builder

	// Calculate dimensions - leave room for border and padding
	contentWidth := c.width - 8
	if contentWidth < 60 {
		contentWidth = 60
	}
	if contentWidth > c.width-4 {
		contentWidth = c.width - 4
	}

	// Title
	title := "CERTIFICATE DETAILS"
	if len(c.details) > 1 {
		title = fmt.Sprintf("CERTIFICATE DETAILS [%d of %d]", c.chainIndex+1, len(c.details))
	}
	titleRendered := c.styles.Title.Width(contentWidth).Render(title)
	s.WriteString(titleRendered)
	s.WriteString("\n")

	// Divider
	s.WriteString(c.styles.Divider.Render(strings.Repeat("─", contentWidth)))
	s.WriteString("\n")

	// Viewport content (scrollable)
	s.WriteString(c.viewport.View())
	s.WriteString("\n")

	// Footer divider
	s.WriteString(c.styles.Divider.Render(strings.Repeat("─", contentWidth)))
	s.WriteString("\n")

	// Footer with scroll indicator
	scrollPercent := c.viewport.ScrollPercent() * 100
	footerText := fmt.Sprintf("j/k scroll (%.0f%%) | Esc to close", scrollPercent)
	if len(c.details) > 1 {
		footerText = fmt.Sprintf("j/k scroll (%.0f%%) | n/p next/prev cert | Esc to close", scrollPercent)
	}
	footer := c.styles.Footer.Width(contentWidth).Render(footerText)
	s.WriteString(footer)

	// Wrap in border with max height constraint
	content := c.styles.Border.
		Width(contentWidth + 4).
		MaxHeight(c.height - 2).
		Render(s.String())

	// Center on screen
	return c.centerContent(content)
}

// centerContent centers the content on screen
func (c *CertViewer) centerContent(content string) string {
	lines := strings.Split(content, "\n")
	contentHeight := len(lines)
	contentWidth := 0
	for _, line := range lines {
		w := lipgloss.Width(line)
		if w > contentWidth {
			contentWidth = w
		}
	}

	// Calculate padding
	topPadding := (c.height - contentHeight) / 2
	leftPadding := (c.width - contentWidth) / 2

	if topPadding < 0 {
		topPadding = 0
	}
	if leftPadding < 0 {
		leftPadding = 0
	}

	var result strings.Builder

	// Add top padding
	for i := 0; i < topPadding; i++ {
		result.WriteString(strings.Repeat(" ", c.width))
		result.WriteString("\n")
	}

	// Add content with left padding
	for _, line := range lines {
		result.WriteString(strings.Repeat(" ", leftPadding))
		result.WriteString(line)
		remaining := c.width - leftPadding - lipgloss.Width(line)
		if remaining > 0 {
			result.WriteString(strings.Repeat(" ", remaining))
		}
		result.WriteString("\n")
	}

	return result.String()
}

// Show shows the certificate viewer with the given certificate details
func (c *CertViewer) Show(details []CertificateDetails) {
	c.details = details
	c.chainIndex = 0
	c.visible = true
	c.updateViewport()
}

// Hide hides the certificate viewer
func (c *CertViewer) Hide() {
	c.visible = false
}

// Toggle toggles the certificate viewer visibility
func (c *CertViewer) Toggle(details []CertificateDetails) {
	if c.visible {
		c.Hide()
	} else {
		c.Show(details)
	}
}

// IsVisible returns whether the certificate viewer is visible
func (c *CertViewer) IsVisible() bool {
	return c.visible
}

// SetSize sets the certificate viewer size
func (c *CertViewer) SetSize(width, height int) {
	c.width = width
	c.height = height
	c.updateViewport()
}

// ParseCertificateDetails parses an x509.Certificate into CertificateDetails
func ParseCertificateDetails(cert *x509.Certificate, position, total int) CertificateDetails {
	details := CertificateDetails{
		Version:       cert.Version,
		Serial:        formatSerialNumber(cert.SerialNumber.Bytes()),
		SignatureAlgo: cert.SignatureAlgorithm.String(),
		Subject:       formatDN(cert.Subject.String()),
		Issuer:        formatDN(cert.Issuer.String()),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		ChainPosition: position,
		ChainLength:   total,
	}

	// Calculate expiry status
	now := time.Now()
	details.IsExpired = now.After(cert.NotAfter)
	if !details.IsExpired {
		details.DaysRemaining = int(cert.NotAfter.Sub(now).Hours() / 24)
	}

	// Public key info
	details.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		details.KeySize = pub.Size() * 8
	}

	// Try to get RSA-specific info
	if rsaPub, ok := cert.PublicKey.(interface {
		Size() int
		N() interface{ Bytes() []byte }
		E() int
	}); ok {
		details.KeySize = rsaPub.Size() * 8
		details.Modulus = formatHexBytes(rsaPub.N().Bytes())
		details.Exponent = rsaPub.E()
	} else {
		// Fallback for RSA keys via reflection or type assertion
		switch pub := cert.PublicKey.(type) {
		case interface{ Equal(x interface{}) bool }:
			// Generic public key, try to extract size
			if sizer, ok := pub.(interface{ Size() int }); ok {
				details.KeySize = sizer.Size() * 8
			}
		default:
			_ = pub // Ignore unknown key types
		}
	}

	// Basic constraints
	details.IsCA = cert.IsCA
	details.MaxPathLen = cert.MaxPathLen
	details.MaxPathLenZero = cert.MaxPathLenZero

	// Key usage
	details.KeyUsage = formatKeyUsage(cert.KeyUsage)

	// Extended key usage
	details.ExtKeyUsage = formatExtKeyUsage(cert.ExtKeyUsage)

	// Subject Alternative Names
	details.DNSNames = cert.DNSNames
	details.IPAddresses = cert.IPAddresses
	details.EmailAddresses = cert.EmailAddresses
	for _, uri := range cert.URIs {
		details.URIs = append(details.URIs, uri.String())
	}

	// Key identifiers
	if len(cert.SubjectKeyId) > 0 {
		details.SubjectKeyID = formatHexColons(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		details.AuthorityKeyID = formatHexColons(cert.AuthorityKeyId)
	}

	// CRL Distribution Points
	details.CRLDistPoints = cert.CRLDistributionPoints

	// Authority Information Access
	details.OCSPServers = cert.OCSPServer
	details.IssuingCertURL = cert.IssuingCertificateURL

	// Fingerprints
	details.SHA1Fingerprint = formatHexColons(cert.Raw[:20]) // First 20 bytes for display, actual SHA1 below
	sha1Sum := sha1Sum(cert.Raw)
	details.SHA1Fingerprint = formatHexColons(sha1Sum)

	sha256Sum := sha256.Sum256(cert.Raw)
	details.SHA256Fingerprint = formatHexColons(sha256Sum[:])

	return details
}

// sha1Sum calculates SHA1 of cert bytes (for fingerprint)
// SHA1 is used here for certificate fingerprints which is industry standard
func sha1Sum(data []byte) []byte {
	sum := sha1.Sum(data) //nolint:gosec // SHA1 for cert fingerprints is standard
	return sum[:]
}

// formatSerialNumber formats a serial number as colon-separated hex
func formatSerialNumber(serial []byte) string {
	return formatHexColons(serial)
}

// formatHexColons formats bytes as colon-separated hex
func formatHexColons(data []byte) string {
	hexStr := hex.EncodeToString(data)
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		end := i + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, hexStr[i:end])
	}
	return strings.ToUpper(strings.Join(parts, ":"))
}

// formatHexBytes formats bytes as hex with line breaks for modulus display
func formatHexBytes(data []byte) string {
	hexStr := hex.EncodeToString(data)
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		end := i + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, hexStr[i:end])
	}
	return strings.ToLower(strings.Join(parts, ":"))
}

// formatDN formats a distinguished name for display
func formatDN(dn string) string {
	// The standard library already provides a good format
	return dn
}

// formatKeyUsage converts x509.KeyUsage bitmap to string slice
func formatKeyUsage(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return usages
}

// formatExtKeyUsage converts x509.ExtKeyUsage slice to string slice
func formatExtKeyUsage(usages []x509.ExtKeyUsage) []string {
	var result []string
	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageAny:
			result = append(result, "Any Extended Key Usage")
		case x509.ExtKeyUsageServerAuth:
			result = append(result, "TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			result = append(result, "TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			result = append(result, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			result = append(result, "E-mail Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			result = append(result, "IPSec End System")
		case x509.ExtKeyUsageIPSECTunnel:
			result = append(result, "IPSec Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			result = append(result, "IPSec User")
		case x509.ExtKeyUsageTimeStamping:
			result = append(result, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			result = append(result, "OCSP Signing")
		default:
			result = append(result, fmt.Sprintf("Unknown (%d)", usage))
		}
	}
	return result
}

// Messages

// CertViewerCloseMsg is sent when the certificate viewer is closed
type CertViewerCloseMsg struct{}

// CertViewerShowMsg is sent to show the certificate viewer
type CertViewerShowMsg struct {
	Details []CertificateDetails
}
