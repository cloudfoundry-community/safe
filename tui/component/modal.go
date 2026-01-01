package component

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ModalType represents the type of modal
type ModalType int

const (
	ModalTypeConfirm ModalType = iota
	ModalTypeError
	ModalTypeInfo
	ModalTypeWarning
	ModalTypeInput
)

// ModalButton represents a button in a modal
type ModalButton struct {
	Label    string
	Key      string
	Action   string
	IsDanger bool
	IsCancel bool
}

// Modal is a modal dialog component
type Modal struct {
	visible   bool
	modalType ModalType
	title     string
	content   string
	detail    string // Additional detail (e.g., path, error stack)
	buttons   []ModalButton
	activeBtn int
	width     int
	height    int
	screenW   int
	screenH   int
	styles    ModalStyles
	keys      modalKeyMap
	onConfirm string // Action to trigger on confirm
	onCancel  string // Action to trigger on cancel
}

// ModalStyles contains styles for the modal
type ModalStyles struct {
	Container    lipgloss.Style
	Title        lipgloss.Style
	TitleError   lipgloss.Style
	TitleWarning lipgloss.Style
	TitleInfo    lipgloss.Style
	Content      lipgloss.Style
	Detail       lipgloss.Style
	Button       lipgloss.Style
	ButtonActive lipgloss.Style
	ButtonDanger lipgloss.Style
	Footer       lipgloss.Style
	Overlay      lipgloss.Style
}

type modalKeyMap struct {
	Confirm key.Binding
	Cancel  key.Binding
	Left    key.Binding
	Right   key.Binding
	Tab     key.Binding
}

// DefaultModalStyles returns the default modal styles
func DefaultModalStyles() ModalStyles {
	return ModalStyles{
		Container: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C6FE0")).
			Background(lipgloss.Color("#1E1E2E")).
			Padding(1, 2),

		Title: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Bold(true).
			Align(lipgloss.Center).
			MarginBottom(1),

		TitleError: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Bold(true).
			Align(lipgloss.Center).
			MarginBottom(1),

		TitleWarning: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Bold(true).
			Align(lipgloss.Center).
			MarginBottom(1),

		TitleInfo: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")).
			Bold(true).
			Align(lipgloss.Center).
			MarginBottom(1),

		Content: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Align(lipgloss.Center),

		Detail: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Align(lipgloss.Center).
			Bold(true).
			MarginTop(1),

		Button: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#313244")).
			Padding(0, 2).
			Margin(0, 1),

		ButtonActive: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#7C6FE0")).
			Bold(true).
			Padding(0, 2).
			Margin(0, 1),

		ButtonDanger: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#F38BA8")).
			Bold(true).
			Padding(0, 2).
			Margin(0, 1),

		Footer: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Align(lipgloss.Center).
			MarginTop(1),

		Overlay: lipgloss.NewStyle().
			Background(lipgloss.Color("#000000")),
	}
}

func defaultModalKeyMap() modalKeyMap {
	return modalKeyMap{
		Confirm: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "confirm"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("n", "esc"),
			key.WithHelp("n/esc", "cancel"),
		),
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("<-/h", "previous"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("->/l", "next"),
		),
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "switch"),
		),
	}
}

// NewModal creates a new modal dialog
func NewModal() Modal {
	return Modal{
		visible:   false,
		modalType: ModalTypeConfirm,
		buttons:   []ModalButton{},
		activeBtn: 0,
		width:     50,
		height:    10,
		screenW:   80, // Default until SetScreenSize called
		screenH:   24,
		styles:    DefaultModalStyles(),
		keys:      defaultModalKeyMap(),
	}
}

// Init initializes the modal
func (m Modal) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (m Modal) Update(msg tea.Msg) (Modal, tea.Cmd) {
	if !m.visible {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.screenW = msg.Width
		m.screenH = msg.Height

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Cancel):
			m.visible = false
			if m.onCancel != "" {
				return m, func() tea.Msg {
					return ModalActionMsg{Action: m.onCancel, Cancelled: true}
				}
			}
			return m, func() tea.Msg {
				return ModalCloseMsg{}
			}

		case msg.String() == "y":
			// Quick confirm with 'y' key - always triggers the confirm/danger action
			if m.modalType == ModalTypeConfirm {
				m.visible = false
				action := m.onConfirm
				if len(m.buttons) > 0 {
					for _, btn := range m.buttons {
						if btn.IsDanger || (!btn.IsCancel && btn.Key == "y") {
							action = btn.Action
							break
						}
					}
				}
				if action != "" {
					return m, func() tea.Msg {
						return ModalActionMsg{Action: action, Cancelled: false}
					}
				}
			}

		case key.Matches(msg, m.keys.Confirm):
			// Enter key - uses currently active button
			if len(m.buttons) > 0 {
				btn := m.buttons[m.activeBtn]
				m.visible = false
				return m, func() tea.Msg {
					return ModalActionMsg{
						Action:    btn.Action,
						Cancelled: btn.IsCancel,
					}
				}
			}
			m.visible = false
			if m.onConfirm != "" {
				return m, func() tea.Msg {
					return ModalActionMsg{Action: m.onConfirm, Cancelled: false}
				}
			}
			return m, func() tea.Msg {
				return ModalCloseMsg{}
			}

		case key.Matches(msg, m.keys.Left):
			if m.activeBtn > 0 {
				m.activeBtn--
			}

		case key.Matches(msg, m.keys.Right), key.Matches(msg, m.keys.Tab):
			if m.activeBtn < len(m.buttons)-1 {
				m.activeBtn++
			}
		}
	}

	return m, nil
}

// View renders the modal
func (m Modal) View() string {
	if !m.visible {
		return ""
	}

	var s strings.Builder

	// Title with appropriate style
	var titleStyle lipgloss.Style
	switch m.modalType {
	case ModalTypeError:
		titleStyle = m.styles.TitleError
	case ModalTypeWarning:
		titleStyle = m.styles.TitleWarning
	case ModalTypeInfo:
		titleStyle = m.styles.TitleInfo
	default:
		titleStyle = m.styles.Title
	}

	s.WriteString(titleStyle.Width(m.width - 4).Render(m.title))
	s.WriteString("\n")

	// Divider
	dividerWidth := m.width - 4
	if dividerWidth < 1 {
		dividerWidth = 1
	}
	s.WriteString(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#45475A")).
		Render(strings.Repeat("─", dividerWidth)))
	s.WriteString("\n")

	// Content
	s.WriteString(m.styles.Content.Width(m.width - 4).Render(m.content))
	s.WriteString("\n")

	// Detail (if present)
	if m.detail != "" {
		s.WriteString("\n")
		s.WriteString(m.styles.Detail.Width(m.width - 4).Render(m.detail))
		s.WriteString("\n")
	}

	// Buttons
	if len(m.buttons) > 0 {
		s.WriteString("\n")
		var btnRow strings.Builder
		for i, btn := range m.buttons {
			var style lipgloss.Style
			if i == m.activeBtn {
				if btn.IsDanger {
					style = m.styles.ButtonDanger
				} else {
					style = m.styles.ButtonActive
				}
			} else {
				style = m.styles.Button
			}

			label := btn.Label
			if btn.Key != "" {
				label = "[" + btn.Key + "] " + label
			}
			btnRow.WriteString(style.Render(label))
		}

		// Center the button row
		btnContent := btnRow.String()
		btnWidth := lipgloss.Width(btnContent)
		leftPad := (m.width - 4 - btnWidth) / 2
		if leftPad < 0 {
			leftPad = 0
		}
		s.WriteString(strings.Repeat(" ", leftPad))
		s.WriteString(btnContent)
		s.WriteString("\n")
	}

	// Footer hint
	s.WriteString(m.styles.Footer.Width(m.width - 4).Render(m.getFooterHint()))

	// Wrap in container with border
	content := m.styles.Container.Width(m.width).Render(s.String())

	// Center on screen
	return m.centerContent(content)
}

// getFooterHint returns the appropriate footer hint
func (m *Modal) getFooterHint() string {
	switch m.modalType {
	case ModalTypeConfirm:
		return "[y] confirm  [n] cancel  [<-/->] switch"
	case ModalTypeError:
		return "[Enter/Esc] close"
	case ModalTypeInfo:
		return "[Enter/Esc] close"
	case ModalTypeWarning:
		return "[y] proceed  [n] cancel"
	default:
		return "[Enter] confirm  [Esc] cancel"
	}
}

// centerContent centers the content on screen
func (m *Modal) centerContent(content string) string {
	if m.screenW == 0 || m.screenH == 0 {
		return content
	}

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
	topPadding := (m.screenH - contentHeight) / 2
	leftPadding := (m.screenW - contentWidth) / 2

	if topPadding < 0 {
		topPadding = 0
	}
	if leftPadding < 0 {
		leftPadding = 0
	}

	var result strings.Builder

	// Add top padding
	for i := 0; i < topPadding; i++ {
		result.WriteString(strings.Repeat(" ", m.screenW))
		result.WriteString("\n")
	}

	// Add content with left padding
	for _, line := range lines {
		result.WriteString(strings.Repeat(" ", leftPadding))
		result.WriteString(line)
		remaining := m.screenW - leftPadding - lipgloss.Width(line)
		if remaining > 0 {
			result.WriteString(strings.Repeat(" ", remaining))
		}
		result.WriteString("\n")
	}

	return result.String()
}

// Show shows the modal
func (m *Modal) Show() {
	m.visible = true
}

// Hide hides the modal
func (m *Modal) Hide() {
	m.visible = false
}

// IsVisible returns whether the modal is visible
func (m *Modal) IsVisible() bool {
	return m.visible
}

// SetSize sets the screen size for centering
func (m *Modal) SetSize(width, height int) {
	m.screenW = width
	m.screenH = height
}

// Confirm shows a confirmation dialog
func (m *Modal) Confirm(title, content, detail string) {
	m.visible = true
	m.modalType = ModalTypeConfirm
	m.title = title
	m.content = content
	m.detail = detail
	m.buttons = []ModalButton{
		{Label: "Cancel", Key: "n", Action: "cancel", IsCancel: true},
		{Label: "Confirm", Key: "y", Action: "confirm", IsDanger: false},
	}
	m.activeBtn = 0
}

// ConfirmDanger shows a confirmation dialog for dangerous actions
func (m *Modal) ConfirmDanger(title, content, detail, dangerLabel string) {
	m.visible = true
	m.modalType = ModalTypeConfirm
	m.title = title
	m.content = content
	m.detail = detail
	m.buttons = []ModalButton{
		{Label: "Cancel", Key: "n", Action: "cancel", IsCancel: true},
		{Label: dangerLabel, Key: "y", Action: "confirm", IsDanger: true},
	}
	m.activeBtn = 0 // Start on Cancel for safety
}

// ConfirmDelete shows a delete confirmation dialog
func (m *Modal) ConfirmDelete(path string, isDir bool) {
	m.visible = true
	m.modalType = ModalTypeConfirm
	m.title = "Confirm Delete"
	if isDir {
		m.content = "Delete this folder and ALL secrets underneath?"
	} else {
		m.content = "Are you sure you want to delete:"
	}
	m.detail = path
	m.onConfirm = "delete"
	m.onCancel = "cancel"
	m.buttons = []ModalButton{
		{Label: "Cancel", Key: "n", Action: "cancel", IsCancel: true},
		{Label: "Delete", Key: "y", Action: "delete", IsDanger: true},
	}
	m.activeBtn = 0
}

// ConfirmSeal shows a seal confirmation dialog
func (m *Modal) ConfirmSeal() {
	m.visible = true
	m.modalType = ModalTypeConfirm
	m.title = "Confirm Seal"
	m.content = "Are you sure you want to seal the vault?"
	m.detail = "This will prevent all access until unsealed."
	m.onConfirm = "seal"
	m.onCancel = "cancel"
	m.buttons = []ModalButton{
		{Label: "Cancel", Key: "n", Action: "cancel", IsCancel: true},
		{Label: "Seal", Key: "y", Action: "seal", IsDanger: true},
	}
	m.activeBtn = 0
}

// ConfirmRevoke shows a certificate revocation confirmation
func (m *Modal) ConfirmRevoke(certPath string) {
	m.visible = true
	m.modalType = ModalTypeConfirm
	m.title = "Confirm Revoke"
	m.content = "Are you sure you want to revoke this certificate?"
	m.detail = certPath
	m.onConfirm = "revoke"
	m.onCancel = "cancel"
	m.buttons = []ModalButton{
		{Label: "Cancel", Key: "n", Action: "cancel", IsCancel: true},
		{Label: "Revoke", Key: "y", Action: "revoke", IsDanger: true},
	}
	m.activeBtn = 0
}

// Error shows an error modal
func (m *Modal) Error(title, message string) {
	m.visible = true
	m.modalType = ModalTypeError
	m.title = title
	m.content = message
	m.detail = ""
	m.buttons = []ModalButton{
		{Label: "OK", Key: "", Action: "close", IsCancel: false},
	}
	m.activeBtn = 0
}

// ErrorWithDetail shows an error modal with detail (e.g., stack trace)
func (m *Modal) ErrorWithDetail(title, message, detail string) {
	m.visible = true
	m.modalType = ModalTypeError
	m.title = title
	m.content = message
	m.detail = detail
	m.buttons = []ModalButton{
		{Label: "OK", Key: "", Action: "close", IsCancel: false},
	}
	m.activeBtn = 0
}

// Info shows an informational modal
func (m *Modal) Info(title, message string) {
	m.visible = true
	m.modalType = ModalTypeInfo
	m.title = title
	m.content = message
	m.detail = ""
	m.buttons = []ModalButton{
		{Label: "OK", Key: "", Action: "close", IsCancel: false},
	}
	m.activeBtn = 0
}

// Warning shows a warning modal
func (m *Modal) Warning(title, message string) {
	m.visible = true
	m.modalType = ModalTypeWarning
	m.title = title
	m.content = message
	m.detail = ""
	m.buttons = []ModalButton{
		{Label: "OK", Key: "", Action: "close", IsCancel: false},
	}
	m.activeBtn = 0
}

// Success shows a success modal
func (m *Modal) Success(title, message string) {
	m.visible = true
	m.modalType = ModalTypeInfo
	m.title = title
	m.content = message
	m.detail = ""
	m.buttons = []ModalButton{
		{Label: "OK", Key: "", Action: "close", IsCancel: false},
	}
	m.activeBtn = 0
}

// SetWidth sets the modal width
func (m *Modal) SetWidth(width int) {
	m.width = width
}

// SetButtons sets custom buttons
func (m *Modal) SetButtons(buttons []ModalButton) {
	m.buttons = buttons
	m.activeBtn = 0
}

// SetOnConfirm sets the action to trigger on confirm
func (m *Modal) SetOnConfirm(action string) {
	m.onConfirm = action
}

// SetOnCancel sets the action to trigger on cancel
func (m *Modal) SetOnCancel(action string) {
	m.onCancel = action
}

// Messages

// ModalCloseMsg is sent when the modal is closed
type ModalCloseMsg struct{}

// ModalActionMsg is sent when a modal action is selected
type ModalActionMsg struct {
	Action    string
	Cancelled bool
}

// ModalShowMsg is sent to show a modal
type ModalShowMsg struct {
	Type    ModalType
	Title   string
	Content string
	Detail  string
}

// ModalConfirmDeleteMsg requests showing a delete confirmation
type ModalConfirmDeleteMsg struct {
	Path string
}

// ModalConfirmSealMsg requests showing a seal confirmation
type ModalConfirmSealMsg struct{}

// ModalConfirmRevokeMsg requests showing a revoke confirmation
type ModalConfirmRevokeMsg struct {
	Path string
}

// ModalErrorMsg requests showing an error modal
type ModalErrorMsg struct {
	Title   string
	Message string
	Detail  string
}
