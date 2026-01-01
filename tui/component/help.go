package component

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// HelpSection represents a section of help content
type HelpSection struct {
	Title    string
	Bindings []HelpBinding
}

// HelpBinding represents a key binding in the help overlay
type HelpBinding struct {
	Key         string
	Description string
}

// Help is a full-screen help overlay component
type Help struct {
	viewport viewport.Model
	sections []HelpSection
	width    int
	height   int
	visible  bool
	styles   HelpStyles
	keys     helpKeyMap
}

// HelpStyles contains styles for the help overlay
type HelpStyles struct {
	Container   lipgloss.Style
	Title       lipgloss.Style
	Section     lipgloss.Style
	Key         lipgloss.Style
	Description lipgloss.Style
	Divider     lipgloss.Style
	Footer      lipgloss.Style
	Border      lipgloss.Style
}

type helpKeyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Close    key.Binding
}

// DefaultHelpStyles returns the default help styles
func DefaultHelpStyles() HelpStyles {
	return HelpStyles{
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

		Key: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Width(14),

		Description: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")),

		Divider: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#45475A")),

		Footer: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Align(lipgloss.Center),

		Border: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C6FE0")),
	}
}

func defaultHelpKeyMap() helpKeyMap {
	return helpKeyMap{
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
		Close: key.NewBinding(
			key.WithKeys("?", "esc", "q", "enter"),
			key.WithHelp("?/esc", "close"),
		),
	}
}

// DefaultHelpSections returns the default help sections for Safe TUI
func DefaultHelpSections() []HelpSection {
	return []HelpSection{
		{
			Title: "NAVIGATION",
			Bindings: []HelpBinding{
				{Key: "j/k, up/dn", Description: "Move up/down"},
				{Key: "h/l, <-/->", Description: "Collapse/Expand"},
				{Key: "Enter", Description: "Select/Open"},
				{Key: "Esc", Description: "Back/Cancel"},
				{Key: "g", Description: "Go to top"},
				{Key: "G", Description: "Go to bottom"},
				{Key: "/", Description: "Search"},
				{Key: "n/N", Description: "Next/Prev match"},
				{Key: "Ctrl+U/D", Description: "Half page up/down"},
				{Key: "PgUp/PgDn", Description: "Page up/down"},
			},
		},
		{
			Title: "SECRETS",
			Bindings: []HelpBinding{
				{Key: "e", Description: "Edit secret"},
				{Key: "Ctrl+E", Description: "External editor"},
				{Key: "y", Description: "Copy value"},
				{Key: "c", Description: "Copy path"},
				{Key: "d", Description: "Delete"},
				{Key: "a", Description: "Add new secret"},
				{Key: "m", Description: "Move/Rename"},
				{Key: "r/R", Description: "Refresh"},
				{Key: "Ctrl+V", Description: "Toggle values"},
			},
		},
		{
			Title: "TABS",
			Bindings: []HelpBinding{
				{Key: "Ctrl+T", Description: "New tab"},
				{Key: "Ctrl+W", Description: "Close tab"},
				{Key: "Ctrl+Tab", Description: "Next tab"},
				{Key: "Shift+Tab", Description: "Previous tab"},
				{Key: "gt/gT", Description: "Next/Prev tab (vim)"},
				{Key: "1-9", Description: "Jump to tab"},
			},
		},
		{
			Title: "ADMIN",
			Bindings: []HelpBinding{
				{Key: "Ctrl+A", Description: "Admin panel"},
				{Key: "i", Description: "Init vault"},
				{Key: "s", Description: "Seal vault"},
				{Key: "u", Description: "Unseal vault"},
				{Key: "k", Description: "Rekey vault"},
			},
		},
		{
			Title: "X.509 CERTIFICATES",
			Bindings: []HelpBinding{
				{Key: "i", Description: "Inspect cert details"},
				{Key: "x i", Description: "Issue certificate"},
				{Key: "x r", Description: "Revoke certificate"},
				{Key: "x s", Description: "Show certificate"},
				{Key: "x v", Description: "Validate chain"},
				{Key: "x c", Description: "Show CRL"},
			},
		},
		{
			Title: "GLOBAL",
			Bindings: []HelpBinding{
				{Key: "Ctrl+P", Description: "Command palette"},
				{Key: "V", Description: "Compare mode"},
				{Key: "Ctrl+Z", Description: "Undo"},
				{Key: "Ctrl+Y", Description: "Redo"},
				{Key: "?", Description: "This help"},
				{Key: "q", Description: "Quit"},
			},
		},
	}
}

// NewHelp creates a new help overlay
func NewHelp() Help {
	sections := DefaultHelpSections()

	return Help{
		viewport: viewport.New(0, 0),
		sections: sections,
		styles:   DefaultHelpStyles(),
		keys:     defaultHelpKeyMap(),
		visible:  false,
		width:    80, // Default until SetSize called
		height:   24,
	}
}

// Init initializes the help overlay
func (h Help) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (h Help) Update(msg tea.Msg) (Help, tea.Cmd) {
	if !h.visible {
		return h, nil
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h.width = msg.Width
		h.height = msg.Height
		h.updateViewport()

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, h.keys.Close):
			h.visible = false
			return h, func() tea.Msg {
				return HelpCloseMsg{}
			}

		case key.Matches(msg, h.keys.Up):
			h.viewport.LineUp(1)

		case key.Matches(msg, h.keys.Down):
			h.viewport.LineDown(1)

		case key.Matches(msg, h.keys.PageUp):
			h.viewport.HalfViewUp()

		case key.Matches(msg, h.keys.PageDown):
			h.viewport.HalfViewDown()

		default:
			// Any other key closes the help
			h.visible = false
			return h, func() tea.Msg {
				return HelpCloseMsg{}
			}
		}
	}

	return h, nil
}

// updateViewport updates the viewport content
func (h *Help) updateViewport() {
	// Calculate dimensions with padding for border
	innerWidth := h.width - 8
	innerHeight := h.height - 8

	if innerWidth < 40 {
		innerWidth = 40
	}
	if innerHeight < 10 {
		innerHeight = 10
	}

	h.viewport.Width = innerWidth
	h.viewport.Height = innerHeight - 4 // Room for title and footer

	// Build content
	h.viewport.SetContent(h.buildContent(innerWidth))
}

// buildContent builds the help content
func (h *Help) buildContent(width int) string {
	var s strings.Builder

	// Calculate column widths for two-column layout
	colWidth := (width - 6) / 2 // Divide space between two columns

	// Pair up sections for side-by-side display
	for i := 0; i < len(h.sections); i += 2 {
		leftSection := h.sections[i]

		var rightSection *HelpSection
		if i+1 < len(h.sections) {
			rightSection = &h.sections[i+1]
		}

		// Render section headers
		leftHeader := h.styles.Section.Render(leftSection.Title)
		rightHeader := ""
		if rightSection != nil {
			rightHeader = h.styles.Section.Render(rightSection.Title)
		}

		s.WriteString(padRight(leftHeader, colWidth))
		s.WriteString("  ")
		s.WriteString(rightHeader)
		s.WriteString("\n")

		// Render dividers
		leftDivider := h.styles.Divider.Render(strings.Repeat("─", len(leftSection.Title)))
		rightDivider := ""
		if rightSection != nil {
			rightDivider = h.styles.Divider.Render(strings.Repeat("─", len(rightSection.Title)))
		}

		s.WriteString(padRight(leftDivider, colWidth))
		s.WriteString("  ")
		s.WriteString(rightDivider)
		s.WriteString("\n")

		// Find max bindings count
		maxBindings := len(leftSection.Bindings)
		if rightSection != nil && len(rightSection.Bindings) > maxBindings {
			maxBindings = len(rightSection.Bindings)
		}

		// Render bindings side by side
		for j := 0; j < maxBindings; j++ {
			leftLine := ""
			if j < len(leftSection.Bindings) {
				b := leftSection.Bindings[j]
				leftLine = h.styles.Key.Render(b.Key) + h.styles.Description.Render(b.Description)
			}

			rightLine := ""
			if rightSection != nil && j < len(rightSection.Bindings) {
				b := rightSection.Bindings[j]
				rightLine = h.styles.Key.Render(b.Key) + h.styles.Description.Render(b.Description)
			}

			s.WriteString(padRight(leftLine, colWidth))
			s.WriteString("  ")
			s.WriteString(rightLine)
			s.WriteString("\n")
		}

		s.WriteString("\n")
	}

	return s.String()
}

// View renders the help overlay
func (h Help) View() string {
	if !h.visible {
		return ""
	}

	var s strings.Builder

	// Calculate centering
	contentWidth := h.width - 4
	contentHeight := h.height - 4

	if contentWidth < 50 {
		contentWidth = 50
	}
	if contentHeight < 20 {
		contentHeight = 20
	}

	// Title
	title := h.styles.Title.Width(contentWidth).Render("SAFE TUI HELP")
	s.WriteString(title)
	s.WriteString("\n")

	// Divider
	s.WriteString(h.styles.Divider.Render(strings.Repeat("─", contentWidth)))
	s.WriteString("\n")

	// Content
	s.WriteString(h.viewport.View())
	s.WriteString("\n")

	// Footer divider
	s.WriteString(h.styles.Divider.Render(strings.Repeat("─", contentWidth)))
	s.WriteString("\n")

	// Footer
	footer := h.styles.Footer.Width(contentWidth).Render("Press any key to close")
	s.WriteString(footer)

	// Wrap in border
	content := h.styles.Border.
		Width(contentWidth + 2).
		Render(s.String())

	// Center on screen
	return h.centerContent(content)
}

// centerContent centers the content on screen
func (h *Help) centerContent(content string) string {
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
	topPadding := (h.height - contentHeight) / 2
	leftPadding := (h.width - contentWidth) / 2

	if topPadding < 0 {
		topPadding = 0
	}
	if leftPadding < 0 {
		leftPadding = 0
	}

	var result strings.Builder

	// Add top padding
	for i := 0; i < topPadding; i++ {
		result.WriteString(strings.Repeat(" ", h.width))
		result.WriteString("\n")
	}

	// Add content with left padding
	for _, line := range lines {
		result.WriteString(strings.Repeat(" ", leftPadding))
		result.WriteString(line)
		remaining := h.width - leftPadding - lipgloss.Width(line)
		if remaining > 0 {
			result.WriteString(strings.Repeat(" ", remaining))
		}
		result.WriteString("\n")
	}

	return result.String()
}

// Show shows the help overlay
func (h *Help) Show() {
	h.visible = true
	h.updateViewport()
}

// Hide hides the help overlay
func (h *Help) Hide() {
	h.visible = false
}

// Toggle toggles the help overlay visibility
func (h *Help) Toggle() {
	if h.visible {
		h.Hide()
	} else {
		h.Show()
	}
}

// IsVisible returns whether the help overlay is visible
func (h *Help) IsVisible() bool {
	return h.visible
}

// SetSize sets the help overlay size
func (h *Help) SetSize(width, height int) {
	h.width = width
	h.height = height
	h.updateViewport()
}

// SetSections sets custom help sections
func (h *Help) SetSections(sections []HelpSection) {
	h.sections = sections
	h.updateViewport()
}

// padRight pads a string to a fixed width
func padRight(s string, width int) string {
	currentWidth := lipgloss.Width(s)
	if currentWidth >= width {
		return s
	}
	return s + strings.Repeat(" ", width-currentWidth)
}

// Messages

// HelpCloseMsg is sent when the help overlay is closed
type HelpCloseMsg struct{}

// HelpToggleMsg is sent to toggle the help overlay
type HelpToggleMsg struct{}
