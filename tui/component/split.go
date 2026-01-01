package component

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SplitOrientation defines whether the split is vertical or horizontal
type SplitOrientation int

const (
	// SplitVertical splits panes left/right
	SplitVertical SplitOrientation = iota
	// SplitHorizontal splits panes top/bottom
	SplitHorizontal
)

// SplitFocus indicates which pane has focus
type SplitFocus int

const (
	// FocusLeft is the left pane (or top in horizontal split)
	FocusLeft SplitFocus = iota
	// FocusRight is the right pane (or bottom in horizontal split)
	FocusRight
)

// SplitPane is a container that manages two panes side by side
type SplitPane struct {
	// Configuration
	orientation SplitOrientation
	ratio       float64 // 0.0 to 1.0, representing the size of the first pane
	minRatio    float64
	maxRatio    float64

	// Focus
	focus SplitFocus

	// Dimensions
	width  int
	height int

	// Content renderers (set by parent)
	leftContent  string
	rightContent string

	// Labels for the panes
	leftLabel  string
	rightLabel string

	// Styling
	styles SplitStyles

	// Key bindings
	keys splitKeyMap
}

// SplitStyles contains styles for the split pane
type SplitStyles struct {
	Border         lipgloss.Style
	BorderFocused  lipgloss.Style
	Label          lipgloss.Style
	LabelFocused   lipgloss.Style
	Divider        lipgloss.Style
	DividerFocused lipgloss.Style
}

type splitKeyMap struct {
	SwitchFocus  key.Binding
	ResizeLeft   key.Binding
	ResizeRight  key.Binding
	ToggleLayout key.Binding
}

// DefaultSplitStyles returns the default styles for a split pane
func DefaultSplitStyles() SplitStyles {
	return SplitStyles{
		Border: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#45475A")),
		BorderFocused: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C6FE0")),
		Label: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Bold(true),
		LabelFocused: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Bold(true),
		Divider: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#45475A")),
		DividerFocused: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")),
	}
}

func defaultSplitKeyMap() splitKeyMap {
	return splitKeyMap{
		SwitchFocus: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "switch pane"),
		),
		ResizeLeft: key.NewBinding(
			key.WithKeys("ctrl+left"),
			key.WithHelp("ctrl+left", "resize left"),
		),
		ResizeRight: key.NewBinding(
			key.WithKeys("ctrl+right"),
			key.WithHelp("ctrl+right", "resize right"),
		),
		ToggleLayout: key.NewBinding(
			key.WithKeys("ctrl+\\"),
			key.WithHelp("ctrl+\\", "toggle split direction"),
		),
	}
}

// NewSplitPane creates a new split pane component
func NewSplitPane() SplitPane {
	return SplitPane{
		orientation: SplitVertical,
		ratio:       0.5,
		minRatio:    0.2,
		maxRatio:    0.8,
		focus:       FocusLeft,
		styles:      DefaultSplitStyles(),
		keys:        defaultSplitKeyMap(),
		width:       80, // Default until SetSize called
		height:      24,
	}
}

// SetOrientation sets the split orientation
func (s *SplitPane) SetOrientation(o SplitOrientation) {
	s.orientation = o
}

// SetRatio sets the split ratio (0.0 to 1.0)
func (s *SplitPane) SetRatio(ratio float64) {
	if ratio < s.minRatio {
		ratio = s.minRatio
	}
	if ratio > s.maxRatio {
		ratio = s.maxRatio
	}
	s.ratio = ratio
}

// SetSize sets the dimensions of the split pane
func (s *SplitPane) SetSize(width, height int) {
	s.width = width
	s.height = height
}

// SetContent sets the content for both panes
func (s *SplitPane) SetContent(left, right string) {
	s.leftContent = left
	s.rightContent = right
}

// SetLabels sets the labels for both panes
func (s *SplitPane) SetLabels(left, right string) {
	s.leftLabel = left
	s.rightLabel = right
}

// Focus returns the currently focused pane
func (s *SplitPane) Focus() SplitFocus {
	return s.focus
}

// SetFocus sets the focus to a specific pane
func (s *SplitPane) SetFocus(f SplitFocus) {
	s.focus = f
}

// SwitchFocus toggles focus between panes
func (s *SplitPane) SwitchFocus() {
	if s.focus == FocusLeft {
		s.focus = FocusRight
	} else {
		s.focus = FocusLeft
	}
}

// Orientation returns the current orientation
func (s *SplitPane) Orientation() SplitOrientation {
	return s.orientation
}

// Ratio returns the current split ratio
func (s *SplitPane) Ratio() float64 {
	return s.ratio
}

// LeftPaneSize returns the dimensions of the left pane
func (s *SplitPane) LeftPaneSize() (width, height int) {
	if s.orientation == SplitVertical {
		// Account for borders (2) and divider (1)
		usableWidth := s.width - 5
		width = int(float64(usableWidth) * s.ratio)
		height = s.height - 2 // Account for top/bottom borders
	} else {
		width = s.width - 2
		usableHeight := s.height - 5
		height = int(float64(usableHeight) * s.ratio)
	}
	return
}

// RightPaneSize returns the dimensions of the right pane
func (s *SplitPane) RightPaneSize() (width, height int) {
	if s.orientation == SplitVertical {
		usableWidth := s.width - 5
		leftWidth := int(float64(usableWidth) * s.ratio)
		width = usableWidth - leftWidth
		height = s.height - 2
	} else {
		width = s.width - 2
		usableHeight := s.height - 5
		leftHeight := int(float64(usableHeight) * s.ratio)
		height = usableHeight - leftHeight
	}
	return
}

// Init initializes the split pane
func (s SplitPane) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (s SplitPane) Update(msg tea.Msg) (SplitPane, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, s.keys.SwitchFocus):
			s.SwitchFocus()
			return s, func() tea.Msg {
				return SplitFocusChangedMsg{Focus: s.focus}
			}

		case key.Matches(msg, s.keys.ResizeLeft):
			s.SetRatio(s.ratio - 0.05)
			return s, func() tea.Msg {
				return SplitResizedMsg{Ratio: s.ratio}
			}

		case key.Matches(msg, s.keys.ResizeRight):
			s.SetRatio(s.ratio + 0.05)
			return s, func() tea.Msg {
				return SplitResizedMsg{Ratio: s.ratio}
			}

		case key.Matches(msg, s.keys.ToggleLayout):
			if s.orientation == SplitVertical {
				s.orientation = SplitHorizontal
			} else {
				s.orientation = SplitVertical
			}
			return s, func() tea.Msg {
				return SplitOrientationChangedMsg{Orientation: s.orientation}
			}
		}
	}

	return s, nil
}

// View renders the split pane
func (s SplitPane) View() string {
	if s.width <= 0 || s.height <= 0 {
		return ""
	}

	if s.orientation == SplitVertical {
		return s.renderVertical()
	}
	return s.renderHorizontal()
}

// renderVertical renders a vertical split (left | right)
func (s *SplitPane) renderVertical() string {
	leftW, leftH := s.LeftPaneSize()
	rightW, rightH := s.RightPaneSize()

	// Prepare pane styles based on focus
	leftStyle := s.styles.Border.
		Width(leftW).
		Height(leftH)
	rightStyle := s.styles.Border.
		Width(rightW).
		Height(rightH)

	// Prepare label styles
	leftLabelStyle := s.styles.Label
	rightLabelStyle := s.styles.Label

	if s.focus == FocusLeft {
		leftStyle = s.styles.BorderFocused.
			Width(leftW).
			Height(leftH)
		leftLabelStyle = s.styles.LabelFocused
	} else {
		rightStyle = s.styles.BorderFocused.
			Width(rightW).
			Height(rightH)
		rightLabelStyle = s.styles.LabelFocused
	}

	// Render labels
	var leftLabel, rightLabel string
	if s.leftLabel != "" {
		leftLabel = leftLabelStyle.Render(s.leftLabel)
	}
	if s.rightLabel != "" {
		rightLabel = rightLabelStyle.Render(s.rightLabel)
	}

	// Truncate/pad content to fit
	leftContent := s.fitContent(s.leftContent, leftW, leftH)
	rightContent := s.fitContent(s.rightContent, rightW, rightH)

	// Build the panes
	var leftPane, rightPane string

	if leftLabel != "" {
		leftPane = lipgloss.JoinVertical(lipgloss.Left,
			leftLabel,
			leftStyle.Render(leftContent),
		)
	} else {
		leftPane = leftStyle.Render(leftContent)
	}

	if rightLabel != "" {
		rightPane = lipgloss.JoinVertical(lipgloss.Left,
			rightLabel,
			rightStyle.Render(rightContent),
		)
	} else {
		rightPane = rightStyle.Render(rightContent)
	}

	// Join horizontally with a divider
	divider := s.renderVerticalDivider()

	return lipgloss.JoinHorizontal(lipgloss.Top,
		leftPane,
		divider,
		rightPane,
	)
}

// renderHorizontal renders a horizontal split (top / bottom)
func (s *SplitPane) renderHorizontal() string {
	topW, topH := s.LeftPaneSize()
	bottomW, bottomH := s.RightPaneSize()

	// Prepare pane styles based on focus
	topStyle := s.styles.Border.
		Width(topW).
		Height(topH)
	bottomStyle := s.styles.Border.
		Width(bottomW).
		Height(bottomH)

	// Prepare label styles
	topLabelStyle := s.styles.Label
	bottomLabelStyle := s.styles.Label

	if s.focus == FocusLeft {
		topStyle = s.styles.BorderFocused.
			Width(topW).
			Height(topH)
		topLabelStyle = s.styles.LabelFocused
	} else {
		bottomStyle = s.styles.BorderFocused.
			Width(bottomW).
			Height(bottomH)
		bottomLabelStyle = s.styles.LabelFocused
	}

	// Render labels
	var topLabel, bottomLabel string
	if s.leftLabel != "" {
		topLabel = topLabelStyle.Render(s.leftLabel)
	}
	if s.rightLabel != "" {
		bottomLabel = bottomLabelStyle.Render(s.rightLabel)
	}

	// Truncate/pad content to fit
	topContent := s.fitContent(s.leftContent, topW, topH)
	bottomContent := s.fitContent(s.rightContent, bottomW, bottomH)

	// Build the panes
	var topPane, bottomPane string

	if topLabel != "" {
		topPane = lipgloss.JoinVertical(lipgloss.Left,
			topLabel,
			topStyle.Render(topContent),
		)
	} else {
		topPane = topStyle.Render(topContent)
	}

	if bottomLabel != "" {
		bottomPane = lipgloss.JoinVertical(lipgloss.Left,
			bottomLabel,
			bottomStyle.Render(bottomContent),
		)
	} else {
		bottomPane = bottomStyle.Render(bottomContent)
	}

	// Join vertically with a divider
	divider := s.renderHorizontalDivider()

	return lipgloss.JoinVertical(lipgloss.Left,
		topPane,
		divider,
		bottomPane,
	)
}

// renderVerticalDivider renders a vertical divider between panes
func (s *SplitPane) renderVerticalDivider() string {
	dividerStyle := s.styles.Divider
	height := s.height
	if s.leftLabel != "" {
		height += 1 // Account for label
	}

	var lines []string
	for i := 0; i < height; i++ {
		lines = append(lines, dividerStyle.Render(" "))
	}
	return strings.Join(lines, "\n")
}

// renderHorizontalDivider renders a horizontal divider between panes
func (s *SplitPane) renderHorizontalDivider() string {
	dividerStyle := s.styles.Divider
	dividerWidth := s.width - 2
	if dividerWidth < 1 {
		dividerWidth = 1
	}
	return dividerStyle.Render(strings.Repeat("─", dividerWidth))
}

// fitContent truncates or pads content to fit the given dimensions
func (s *SplitPane) fitContent(content string, width, height int) string {
	if content == "" {
		return ""
	}

	lines := strings.Split(content, "\n")

	// Truncate lines to height
	if len(lines) > height {
		lines = lines[:height]
	}

	// Truncate or pad each line to width
	for i, line := range lines {
		lineWidth := lipgloss.Width(line)
		if lineWidth > width {
			// Truncate with ellipsis
			if width > 3 {
				lines[i] = truncateString(line, width-3) + "..."
			} else {
				lines[i] = truncateString(line, width)
			}
		}
	}

	// Pad with empty lines to reach height
	for len(lines) < height {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

// truncateString truncates a string to a maximum width
func truncateString(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}

	runes := []rune(s)
	width := 0
	for i := range runes {
		// Simple width calculation (not accounting for wide characters)
		width++
		if width > maxWidth {
			return string(runes[:i])
		}
	}
	return s
}

// Messages

// SplitFocusChangedMsg is sent when focus changes between panes
type SplitFocusChangedMsg struct {
	Focus SplitFocus
}

// SplitResizedMsg is sent when the split ratio changes
type SplitResizedMsg struct {
	Ratio float64
}

// SplitOrientationChangedMsg is sent when the orientation changes
type SplitOrientationChangedMsg struct {
	Orientation SplitOrientation
}
