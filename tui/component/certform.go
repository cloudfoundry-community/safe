package component

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// CertFormValues holds the values from the certificate form
type CertFormValues struct {
	OutputPath         string
	CommonName         string
	Organization       string
	Country            string
	State              string
	SANs               []string
	TTL                string
	KeyBits            int
	SignatureAlgorithm string
	SignedBy           string
	IsCA               bool

	// Key usage flags
	DigitalSignature bool
	KeyEncipherment  bool
	ServerAuth       bool
	ClientAuth       bool
	CodeSigning      bool
	EmailProtection  bool
}

// Subject builds a subject string from the form values
func (v CertFormValues) Subject() string {
	var parts []string

	if v.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", v.CommonName))
	}
	if v.Organization != "" {
		parts = append(parts, fmt.Sprintf("O=%s", v.Organization))
	}
	if v.State != "" {
		parts = append(parts, fmt.Sprintf("ST=%s", v.State))
	}
	if v.Country != "" {
		parts = append(parts, fmt.Sprintf("C=%s", v.Country))
	}

	if len(parts) == 0 {
		return "CN=certificate"
	}

	return strings.Join(parts, ",")
}

// KeyUsageList returns the selected key usages as a string slice
func (v CertFormValues) KeyUsageList() []string {
	var usages []string

	if v.DigitalSignature {
		usages = append(usages, "digital_signature")
	}
	if v.KeyEncipherment {
		usages = append(usages, "key_encipherment")
	}
	if v.ServerAuth {
		usages = append(usages, "server_auth")
	}
	if v.ClientAuth {
		usages = append(usages, "client_auth")
	}
	if v.CodeSigning {
		usages = append(usages, "code_signing")
	}
	if v.EmailProtection {
		usages = append(usages, "email_protection")
	}

	// If CA, add cert sign and CRL sign
	if v.IsCA {
		usages = append(usages, "key_cert_sign", "crl_sign")
	}

	return usages
}

// CertFormField represents the different fields in the form
type CertFormField int

const (
	FieldOutputPath CertFormField = iota
	FieldCommonName
	FieldOrganization
	FieldCountry
	FieldState
	FieldIsCA
	FieldSignedBy
	FieldTTL
	FieldKeyBits
	FieldAlgorithm
	FieldSANInput
	FieldDigitalSignature
	FieldKeyEncipherment
	FieldServerAuth
	FieldClientAuth
	FieldSubmit
	FieldCancel
)

const numFields = int(FieldCancel) + 1

// CertForm is a certificate issuance form
type CertForm struct {
	// Text inputs
	outputPath   textinput.Model
	commonName   textinput.Model
	organization textinput.Model
	country      textinput.Model
	state        textinput.Model
	signedBy     textinput.Model
	ttl          textinput.Model
	sanInput     textinput.Model

	// SANs list
	sans []string

	// Dropdown selections
	keyBitsIndex   int
	algorithmIndex int

	// Checkboxes
	isCA             bool
	digitalSignature bool
	keyEncipherment  bool
	serverAuth       bool
	clientAuth       bool

	// State
	focusIndex int
	submitted  bool
	cancelled  bool
	err        error

	// Layout
	width  int
	height int

	// Keys
	keys certFormKeyMap

	// Styles
	styles CertFormStyles
}

type certFormKeyMap struct {
	Next      key.Binding
	Prev      key.Binding
	Submit    key.Binding
	Cancel    key.Binding
	Toggle    key.Binding
	AddSAN    key.Binding
	RemoveSAN key.Binding
	Left      key.Binding
	Right     key.Binding
}

// CertFormStyles contains styles for the form
type CertFormStyles struct {
	Title           lipgloss.Style
	Section         lipgloss.Style
	Label           lipgloss.Style
	Input           lipgloss.Style
	InputFocused    lipgloss.Style
	Checkbox        lipgloss.Style
	CheckboxChecked lipgloss.Style
	Button          lipgloss.Style
	ButtonFocused   lipgloss.Style
	Error           lipgloss.Style
	Hint            lipgloss.Style
	Divider         lipgloss.Style
	SANItem         lipgloss.Style
}

func defaultCertFormStyles() CertFormStyles {
	return CertFormStyles{
		Title: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Bold(true).
			MarginBottom(1),
		Section: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6ADC8")).
			Bold(true).
			MarginTop(1),
		Label: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6ADC8")).
			Width(14),
		Input: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")),
		InputFocused: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")),
		Checkbox: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")),
		CheckboxChecked: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")),
		Button: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#45475A")).
			Padding(0, 2),
		ButtonFocused: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#7C6FE0")).
			Padding(0, 2).
			Bold(true),
		Error: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")),
		Hint: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")),
		Divider: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#45475A")),
		SANItem: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")),
	}
}

func defaultCertFormKeyMap() certFormKeyMap {
	return certFormKeyMap{
		Next: key.NewBinding(
			key.WithKeys("tab", "down"),
			key.WithHelp("Tab/Down", "next field"),
		),
		Prev: key.NewBinding(
			key.WithKeys("shift+tab", "up"),
			key.WithHelp("Shift+Tab/Up", "prev field"),
		),
		Submit: key.NewBinding(
			key.WithKeys("ctrl+s"),
			key.WithHelp("Ctrl+S", "submit"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("Esc", "cancel"),
		),
		Toggle: key.NewBinding(
			key.WithKeys(" ", "enter"),
			key.WithHelp("Space/Enter", "toggle"),
		),
		AddSAN: key.NewBinding(
			key.WithKeys("ctrl+a"),
			key.WithHelp("Ctrl+A", "add SAN"),
		),
		RemoveSAN: key.NewBinding(
			key.WithKeys("ctrl+x"),
			key.WithHelp("Ctrl+X", "remove last SAN"),
		),
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("Left", "prev option"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("Right", "next option"),
		),
	}
}

// Key bits options
var keyBitsOptions = []int{2048, 4096}

// Algorithm options
var algorithmOptions = []string{"sha256", "sha384", "sha512"}

// NewCertForm creates a new certificate form
func NewCertForm() CertForm {
	// Initialize text inputs
	outputPath := textinput.New()
	outputPath.Placeholder = "secret/certs/myapp/server"
	outputPath.Width = 40

	commonName := textinput.New()
	commonName.Placeholder = "server.example.com"
	commonName.Width = 40

	organization := textinput.New()
	organization.Placeholder = "Example Corp"
	organization.Width = 30

	country := textinput.New()
	country.Placeholder = "US"
	country.Width = 10
	country.CharLimit = 2

	state := textinput.New()
	state.Placeholder = "NY"
	state.Width = 15

	signedBy := textinput.New()
	signedBy.Placeholder = "secret/certs/ca (empty for self-signed)"
	signedBy.Width = 40

	ttl := textinput.New()
	ttl.Placeholder = "365d"
	ttl.SetValue("365d")
	ttl.Width = 15

	sanInput := textinput.New()
	sanInput.Placeholder = "Add SAN (domain, IP, or email)"
	sanInput.Width = 40

	// Focus first field
	outputPath.Focus()

	return CertForm{
		outputPath:       outputPath,
		commonName:       commonName,
		organization:     organization,
		country:          country,
		state:            state,
		signedBy:         signedBy,
		ttl:              ttl,
		sanInput:         sanInput,
		sans:             make([]string, 0),
		keyBitsIndex:     1, // Default to 4096
		algorithmIndex:   2, // Default to sha512
		digitalSignature: true,
		serverAuth:       true,
		focusIndex:       0,
		keys:             defaultCertFormKeyMap(),
		styles:           defaultCertFormStyles(),
	}
}

// Init initializes the form
func (f CertForm) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages
func (f CertForm) Update(msg tea.Msg) (CertForm, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.width = msg.Width
		f.height = msg.Height
		return f, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, f.keys.Cancel):
			f.cancelled = true
			return f, func() tea.Msg { return CertFormCancelledMsg{} }

		case key.Matches(msg, f.keys.Submit):
			if f.validate() {
				f.submitted = true
				return f, func() tea.Msg {
					return CertFormSubmittedMsg{Values: f.Values()}
				}
			}

		case key.Matches(msg, f.keys.Next):
			f.focusNext()

		case key.Matches(msg, f.keys.Prev):
			f.focusPrev()

		case key.Matches(msg, f.keys.Toggle):
			// Handle toggle for checkboxes and buttons
			switch CertFormField(f.focusIndex) {
			case FieldIsCA:
				f.isCA = !f.isCA
			case FieldDigitalSignature:
				f.digitalSignature = !f.digitalSignature
			case FieldKeyEncipherment:
				f.keyEncipherment = !f.keyEncipherment
			case FieldServerAuth:
				f.serverAuth = !f.serverAuth
			case FieldClientAuth:
				f.clientAuth = !f.clientAuth
			case FieldSubmit:
				if f.validate() {
					f.submitted = true
					return f, func() tea.Msg {
						return CertFormSubmittedMsg{Values: f.Values()}
					}
				}
			case FieldCancel:
				f.cancelled = true
				return f, func() tea.Msg { return CertFormCancelledMsg{} }
			}

		case key.Matches(msg, f.keys.Left):
			switch CertFormField(f.focusIndex) {
			case FieldKeyBits:
				if f.keyBitsIndex > 0 {
					f.keyBitsIndex--
				}
			case FieldAlgorithm:
				if f.algorithmIndex > 0 {
					f.algorithmIndex--
				}
			}

		case key.Matches(msg, f.keys.Right):
			switch CertFormField(f.focusIndex) {
			case FieldKeyBits:
				if f.keyBitsIndex < len(keyBitsOptions)-1 {
					f.keyBitsIndex++
				}
			case FieldAlgorithm:
				if f.algorithmIndex < len(algorithmOptions)-1 {
					f.algorithmIndex++
				}
			}

		case key.Matches(msg, f.keys.AddSAN):
			if CertFormField(f.focusIndex) == FieldSANInput && f.sanInput.Value() != "" {
				f.sans = append(f.sans, f.sanInput.Value())
				f.sanInput.SetValue("")
			}

		case key.Matches(msg, f.keys.RemoveSAN):
			if len(f.sans) > 0 {
				f.sans = f.sans[:len(f.sans)-1]
			}

		default:
			// Handle enter for SAN input
			if msg.String() == "enter" && CertFormField(f.focusIndex) == FieldSANInput {
				if f.sanInput.Value() != "" {
					f.sans = append(f.sans, f.sanInput.Value())
					f.sanInput.SetValue("")
				}
			}
		}
	}

	// Update focused text input
	var cmd tea.Cmd
	switch CertFormField(f.focusIndex) {
	case FieldOutputPath:
		f.outputPath, cmd = f.outputPath.Update(msg)
		cmds = append(cmds, cmd)
	case FieldCommonName:
		f.commonName, cmd = f.commonName.Update(msg)
		cmds = append(cmds, cmd)
	case FieldOrganization:
		f.organization, cmd = f.organization.Update(msg)
		cmds = append(cmds, cmd)
	case FieldCountry:
		f.country, cmd = f.country.Update(msg)
		cmds = append(cmds, cmd)
	case FieldState:
		f.state, cmd = f.state.Update(msg)
		cmds = append(cmds, cmd)
	case FieldSignedBy:
		f.signedBy, cmd = f.signedBy.Update(msg)
		cmds = append(cmds, cmd)
	case FieldTTL:
		f.ttl, cmd = f.ttl.Update(msg)
		cmds = append(cmds, cmd)
	case FieldSANInput:
		f.sanInput, cmd = f.sanInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return f, tea.Batch(cmds...)
}

// View renders the form
func (f CertForm) View() string {
	var s strings.Builder

	// Title
	s.WriteString(f.styles.Title.Render("ISSUE X509 CERTIFICATE"))
	s.WriteString("\n")
	s.WriteString(f.styles.Divider.Render(strings.Repeat("─", 50)))
	s.WriteString("\n\n")

	// Output Path
	s.WriteString(f.renderField("Output Path", f.outputPath.View(), FieldOutputPath))
	s.WriteString("\n")

	// Subject section
	s.WriteString(f.styles.Section.Render("Subject"))
	s.WriteString("\n")
	s.WriteString(f.styles.Divider.Render(strings.Repeat("─", 30)))
	s.WriteString("\n")

	s.WriteString(f.renderField("Common Name", f.commonName.View(), FieldCommonName))
	s.WriteString(f.renderField("Organization", f.organization.View(), FieldOrganization))

	// Country and State on same line
	s.WriteString(f.styles.Label.Render("Country"))
	s.WriteString(f.renderInlineInput(f.country.View(), FieldCountry))
	s.WriteString("   ")
	s.WriteString(f.styles.Label.Width(8).Render("State"))
	s.WriteString(f.renderInlineInput(f.state.View(), FieldState))
	s.WriteString("\n")

	// Options section
	s.WriteString("\n")
	s.WriteString(f.styles.Section.Render("Options"))
	s.WriteString("\n")
	s.WriteString(f.styles.Divider.Render(strings.Repeat("─", 30)))
	s.WriteString("\n")

	// CA checkbox
	s.WriteString(f.renderCheckbox("CA Certificate", f.isCA, FieldIsCA))
	s.WriteString("\n")

	// Signed by
	s.WriteString(f.renderField("Signed By", f.signedBy.View(), FieldSignedBy))

	// TTL
	s.WriteString(f.renderField("TTL", f.ttl.View(), FieldTTL))

	// Key Bits selector
	s.WriteString(f.styles.Label.Render("Key Bits"))
	s.WriteString(f.renderSelector(keyBitsOptions, f.keyBitsIndex, FieldKeyBits))
	s.WriteString("\n")

	// Algorithm selector
	s.WriteString(f.styles.Label.Render("Algorithm"))
	s.WriteString(f.renderAlgorithmSelector(algorithmOptions, f.algorithmIndex, FieldAlgorithm))
	s.WriteString("\n")

	// SANs section
	s.WriteString("\n")
	s.WriteString(f.styles.Section.Render("Subject Alternative Names"))
	s.WriteString("\n")
	s.WriteString(f.styles.Divider.Render(strings.Repeat("─", 30)))
	s.WriteString("\n")

	// List existing SANs
	for _, san := range f.sans {
		s.WriteString("  ")
		s.WriteString(f.styles.SANItem.Render(san))
		s.WriteString("\n")
	}

	// SAN input
	s.WriteString(f.renderField("", f.sanInput.View(), FieldSANInput))
	s.WriteString(f.styles.Hint.Render("  [Enter] Add  [Ctrl+X] Remove last"))
	s.WriteString("\n")

	// Key Usage section
	s.WriteString("\n")
	s.WriteString(f.styles.Section.Render("Key Usage"))
	s.WriteString("\n")
	s.WriteString(f.styles.Divider.Render(strings.Repeat("─", 30)))
	s.WriteString("\n")

	// Key usage checkboxes in two columns
	s.WriteString(f.renderCheckbox("Digital Signature", f.digitalSignature, FieldDigitalSignature))
	s.WriteString("   ")
	s.WriteString(f.renderCheckbox("Key Encipherment", f.keyEncipherment, FieldKeyEncipherment))
	s.WriteString("\n")

	s.WriteString(f.renderCheckbox("Server Auth", f.serverAuth, FieldServerAuth))
	s.WriteString("       ")
	s.WriteString(f.renderCheckbox("Client Auth", f.clientAuth, FieldClientAuth))
	s.WriteString("\n")

	// Buttons
	s.WriteString("\n\n")
	s.WriteString("        ")
	s.WriteString(f.renderButton("Cancel", FieldCancel))
	s.WriteString("    ")
	s.WriteString(f.renderButton("Issue Certificate", FieldSubmit))
	s.WriteString("\n")

	// Error if any
	if f.err != nil {
		s.WriteString("\n")
		s.WriteString(f.styles.Error.Render("Error: " + f.err.Error()))
		s.WriteString("\n")
	}

	// Help
	s.WriteString("\n")
	s.WriteString(f.styles.Hint.Render("[Tab] next  [Shift+Tab] prev  [Space] toggle  [Ctrl+S] submit  [Esc] cancel"))

	return s.String()
}

// Helper rendering methods

func (f *CertForm) renderField(label, input string, field CertFormField) string {
	var s strings.Builder

	if label != "" {
		s.WriteString(f.styles.Label.Render(label))
	} else {
		s.WriteString(strings.Repeat(" ", 14))
	}

	if CertFormField(f.focusIndex) == field {
		s.WriteString(f.styles.InputFocused.Render("["))
		s.WriteString(input)
		s.WriteString(f.styles.InputFocused.Render("]"))
	} else {
		s.WriteString("[")
		s.WriteString(input)
		s.WriteString("]")
	}
	s.WriteString("\n")

	return s.String()
}

func (f *CertForm) renderInlineInput(input string, field CertFormField) string {
	var s strings.Builder

	if CertFormField(f.focusIndex) == field {
		s.WriteString(f.styles.InputFocused.Render("["))
		s.WriteString(input)
		s.WriteString(f.styles.InputFocused.Render("]"))
	} else {
		s.WriteString("[")
		s.WriteString(input)
		s.WriteString("]")
	}

	return s.String()
}

func (f *CertForm) renderCheckbox(label string, checked bool, field CertFormField) string {
	var s strings.Builder

	isFocused := CertFormField(f.focusIndex) == field

	var checkmark string
	var style lipgloss.Style

	if checked {
		checkmark = "x"
		style = f.styles.CheckboxChecked
	} else {
		checkmark = " "
		style = f.styles.Checkbox
	}

	if isFocused {
		s.WriteString(f.styles.InputFocused.Render("[" + checkmark + "] " + label))
	} else {
		s.WriteString(style.Render("[" + checkmark + "] " + label))
	}

	return s.String()
}

func (f *CertForm) renderSelector(options []int, selectedIndex int, field CertFormField) string {
	var s strings.Builder

	isFocused := CertFormField(f.focusIndex) == field

	for i, opt := range options {
		if i > 0 {
			s.WriteString("  ")
		}

		optStr := strconv.Itoa(opt)
		if i == selectedIndex {
			if isFocused {
				s.WriteString(f.styles.InputFocused.Render("[" + optStr + "]"))
			} else {
				s.WriteString(f.styles.CheckboxChecked.Render("[" + optStr + "]"))
			}
		} else {
			s.WriteString(f.styles.Checkbox.Render(" " + optStr + " "))
		}
	}

	return s.String()
}

func (f *CertForm) renderAlgorithmSelector(options []string, selectedIndex int, field CertFormField) string {
	var s strings.Builder

	isFocused := CertFormField(f.focusIndex) == field

	for i, opt := range options {
		if i > 0 {
			s.WriteString("  ")
		}

		displayName := strings.ToUpper(opt)
		if i == selectedIndex {
			if isFocused {
				s.WriteString(f.styles.InputFocused.Render("[" + displayName + "]"))
			} else {
				s.WriteString(f.styles.CheckboxChecked.Render("[" + displayName + "]"))
			}
		} else {
			s.WriteString(f.styles.Checkbox.Render(" " + displayName + " "))
		}
	}

	return s.String()
}

func (f *CertForm) renderButton(label string, field CertFormField) string {
	if CertFormField(f.focusIndex) == field {
		return f.styles.ButtonFocused.Render(label)
	}
	return f.styles.Button.Render(label)
}

// Navigation methods

func (f *CertForm) focusNext() {
	f.blurCurrent()
	f.focusIndex = (f.focusIndex + 1) % numFields
	f.focusCurrent()
}

func (f *CertForm) focusPrev() {
	f.blurCurrent()
	f.focusIndex--
	if f.focusIndex < 0 {
		f.focusIndex = numFields - 1
	}
	f.focusCurrent()
}

func (f *CertForm) blurCurrent() {
	switch CertFormField(f.focusIndex) {
	case FieldOutputPath:
		f.outputPath.Blur()
	case FieldCommonName:
		f.commonName.Blur()
	case FieldOrganization:
		f.organization.Blur()
	case FieldCountry:
		f.country.Blur()
	case FieldState:
		f.state.Blur()
	case FieldSignedBy:
		f.signedBy.Blur()
	case FieldTTL:
		f.ttl.Blur()
	case FieldSANInput:
		f.sanInput.Blur()
	}
}

func (f *CertForm) focusCurrent() {
	switch CertFormField(f.focusIndex) {
	case FieldOutputPath:
		f.outputPath.Focus()
	case FieldCommonName:
		f.commonName.Focus()
	case FieldOrganization:
		f.organization.Focus()
	case FieldCountry:
		f.country.Focus()
	case FieldState:
		f.state.Focus()
	case FieldSignedBy:
		f.signedBy.Focus()
	case FieldTTL:
		f.ttl.Focus()
	case FieldSANInput:
		f.sanInput.Focus()
	}
}

// Validation

func (f *CertForm) validate() bool {
	f.err = nil

	// Output path is required
	if strings.TrimSpace(f.outputPath.Value()) == "" {
		f.err = fmt.Errorf("output path is required")
		return false
	}

	// Common name is required
	if strings.TrimSpace(f.commonName.Value()) == "" {
		f.err = fmt.Errorf("common name is required")
		return false
	}

	// TTL must be valid
	ttl := strings.TrimSpace(f.ttl.Value())
	if ttl != "" {
		if !isValidTTL(ttl) {
			f.err = fmt.Errorf("invalid TTL format (use e.g., 365d, 1y, 30m)")
			return false
		}
	}

	// Country code should be 2 letters
	country := strings.TrimSpace(f.country.Value())
	if country != "" && len(country) != 2 {
		f.err = fmt.Errorf("country code must be 2 letters (e.g., US, UK)")
		return false
	}

	return true
}

func isValidTTL(ttl string) bool {
	var value int
	var unit string
	n, _ := fmt.Sscanf(ttl, "%d%s", &value, &unit)
	if n < 1 || value <= 0 {
		return false
	}

	validUnits := []string{"d", "day", "days", "w", "week", "weeks", "m", "month", "months", "y", "year", "years", "h", "hour", "hours", ""}
	for _, valid := range validUnits {
		if unit == valid {
			return true
		}
	}
	return false
}

// Values returns the current form values
func (f *CertForm) Values() CertFormValues {
	// Add common name to SANs if not already present
	sans := make([]string, len(f.sans))
	copy(sans, f.sans)

	cn := strings.TrimSpace(f.commonName.Value())
	if cn != "" {
		found := false
		for _, san := range sans {
			if san == cn {
				found = true
				break
			}
		}
		if !found {
			sans = append([]string{cn}, sans...)
		}
	}

	return CertFormValues{
		OutputPath:         strings.TrimSpace(f.outputPath.Value()),
		CommonName:         cn,
		Organization:       strings.TrimSpace(f.organization.Value()),
		Country:            strings.ToUpper(strings.TrimSpace(f.country.Value())),
		State:              strings.TrimSpace(f.state.Value()),
		SANs:               sans,
		TTL:                strings.TrimSpace(f.ttl.Value()),
		KeyBits:            keyBitsOptions[f.keyBitsIndex],
		SignatureAlgorithm: algorithmOptions[f.algorithmIndex],
		SignedBy:           strings.TrimSpace(f.signedBy.Value()),
		IsCA:               f.isCA,
		DigitalSignature:   f.digitalSignature,
		KeyEncipherment:    f.keyEncipherment,
		ServerAuth:         f.serverAuth,
		ClientAuth:         f.clientAuth,
	}
}

// IsSubmitted returns true if the form was submitted
func (f *CertForm) IsSubmitted() bool {
	return f.submitted
}

// IsCancelled returns true if the form was cancelled
func (f *CertForm) IsCancelled() bool {
	return f.cancelled
}

// SetError sets an error message to display
func (f *CertForm) SetError(err error) {
	f.err = err
}

// Messages

// CertFormSubmittedMsg is sent when the form is submitted
type CertFormSubmittedMsg struct {
	Values CertFormValues
}

// CertFormCancelledMsg is sent when the form is cancelled
type CertFormCancelledMsg struct{}
