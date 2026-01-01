package component

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// StatusLevel indicates the severity of a status message
type StatusLevel int

const (
	StatusInfo StatusLevel = iota
	StatusSuccess
	StatusWarning
	StatusError
)

// StatusBar represents the bottom status bar
type StatusBar struct {
	message string
	level   StatusLevel
	target  string
	path    string
	auth    bool
	sealed  bool
}

// NewStatusBar creates a new status bar
func NewStatusBar() StatusBar {
	return StatusBar{
		message: "",
		level:   StatusInfo,
	}
}

// SetMessage sets the status message
func (s *StatusBar) SetMessage(msg string, level StatusLevel) {
	s.message = msg
	s.level = level
}

// SetTarget sets the current target
func (s *StatusBar) SetTarget(target string) {
	s.target = target
}

// SetPath sets the current path
func (s *StatusBar) SetPath(path string) {
	s.path = path
}

// SetAuth sets the authentication status
func (s *StatusBar) SetAuth(auth bool) {
	s.auth = auth
}

// SetSealed sets the sealed status
func (s *StatusBar) SetSealed(sealed bool) {
	s.sealed = sealed
}

// View renders the status bar
func (s *StatusBar) View(width int) string {
	// Base style for status bar
	baseStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("#313244")).
		Width(width)

	// Left section: target and path
	leftStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4")).
		Padding(0, 1)

	var leftParts []string

	if s.target != "" {
		targetStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")).
			Bold(true)
		leftParts = append(leftParts, targetStyle.Render(s.target))
	}

	if s.path != "" {
		pathStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6ADC8"))
		leftParts = append(leftParts, pathStyle.Render(s.path))
	}

	left := leftStyle.Render(strings.Join(leftParts, " │ "))

	// Middle section: message
	var messageStyle lipgloss.Style
	switch s.level {
	case StatusSuccess:
		messageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1"))
	case StatusWarning:
		messageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF"))
	case StatusError:
		messageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8"))
	default:
		messageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4"))
	}
	middle := messageStyle.Render(s.message)

	// Right section: auth status
	var rightContent string
	if s.sealed {
		sealedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Bold(true)
		rightContent = sealedStyle.Render("● sealed")
	} else if s.auth {
		authStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")).
			Bold(true)
		rightContent = authStyle.Render("● authenticated")
	} else if s.target != "" {
		noAuthStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF"))
		rightContent = noAuthStyle.Render("○ not authenticated")
	}

	rightStyle := lipgloss.NewStyle().
		Padding(0, 1)
	right := rightStyle.Render(rightContent)

	// Calculate spacing
	leftWidth := lipgloss.Width(left)
	rightWidth := lipgloss.Width(right)
	middleMaxWidth := width - leftWidth - rightWidth - 2

	// Truncate middle if needed
	if lipgloss.Width(middle) > middleMaxWidth && middleMaxWidth > 3 {
		middle = middle[:middleMaxWidth-3] + "..."
	}

	// Build the status bar
	middleWidth := lipgloss.Width(middle)
	padding := width - leftWidth - middleWidth - rightWidth
	if padding < 0 {
		padding = 0
	}

	content := left + middle + strings.Repeat(" ", padding) + right

	return baseStyle.Render(content)
}
