package component

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SpinnerStyle represents different spinner animation styles
type SpinnerStyle int

const (
	SpinnerDots SpinnerStyle = iota
	SpinnerLine
	SpinnerBraille
	SpinnerCircle
	SpinnerMeter
	SpinnerMini
	SpinnerJump
	SpinnerPulse
	SpinnerPoints
	SpinnerGlobe
	SpinnerMoon
	SpinnerMonkey
	SpinnerHamburger
)

// spinnerFrames contains the animation frames for each spinner style
var spinnerFrames = map[SpinnerStyle][]string{
	SpinnerDots:      {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	SpinnerLine:      {"|", "/", "-", "\\"},
	SpinnerBraille:   {"⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"},
	SpinnerCircle:    {"◐", "◓", "◑", "◒"},
	SpinnerMeter:     {"▱▱▱▱▱▱▱", "▰▱▱▱▱▱▱", "▰▰▱▱▱▱▱", "▰▰▰▱▱▱▱", "▰▰▰▰▱▱▱", "▰▰▰▰▰▱▱", "▰▰▰▰▰▰▱", "▰▰▰▰▰▰▰"},
	SpinnerMini:      {"⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"},
	SpinnerJump:      {"⢄", "⢂", "⢁", "⡁", "⡈", "⡐", "⡠"},
	SpinnerPulse:     {"█", "▓", "▒", "░", "▒", "▓"},
	SpinnerPoints:    {"∙∙∙", "●∙∙", "∙●∙", "∙∙●"},
	SpinnerGlobe:     {"🌍", "🌎", "🌏"},
	SpinnerMoon:      {"🌑", "🌒", "🌓", "🌔", "🌕", "🌖", "🌗", "🌘"},
	SpinnerMonkey:    {"🙈", "🙉", "🙊"},
	SpinnerHamburger: {"☱", "☲", "☴", "☲"},
}

// spinnerIntervals defines the animation speed for each spinner style
var spinnerIntervals = map[SpinnerStyle]time.Duration{
	SpinnerDots:      80 * time.Millisecond,
	SpinnerLine:      120 * time.Millisecond,
	SpinnerBraille:   80 * time.Millisecond,
	SpinnerCircle:    120 * time.Millisecond,
	SpinnerMeter:     100 * time.Millisecond,
	SpinnerMini:      80 * time.Millisecond,
	SpinnerJump:      100 * time.Millisecond,
	SpinnerPulse:     100 * time.Millisecond,
	SpinnerPoints:    200 * time.Millisecond,
	SpinnerGlobe:     180 * time.Millisecond,
	SpinnerMoon:      100 * time.Millisecond,
	SpinnerMonkey:    300 * time.Millisecond,
	SpinnerHamburger: 100 * time.Millisecond,
}

// SpinnerTickMsg is sent to advance the spinner animation
type SpinnerTickMsg struct {
	ID   int
	Time time.Time
}

// Spinner is an animated loading spinner component
type Spinner struct {
	id      int
	style   SpinnerStyle
	frame   int
	message string
	visible bool
	styles  SpinnerStyles
}

// SpinnerStyles contains styles for the spinner
type SpinnerStyles struct {
	Spinner lipgloss.Style
	Message lipgloss.Style
}

// DefaultSpinnerStyles returns the default spinner styles
func DefaultSpinnerStyles() SpinnerStyles {
	return SpinnerStyles{
		Spinner: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")),
		Message: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6ADC8")).
			MarginLeft(1),
	}
}

// NewSpinner creates a new spinner with the default style
func NewSpinner() Spinner {
	return NewSpinnerWithStyle(SpinnerDots)
}

// NewSpinnerWithStyle creates a new spinner with a specific style
func NewSpinnerWithStyle(style SpinnerStyle) Spinner {
	return Spinner{
		id:      nextSpinnerID(),
		style:   style,
		frame:   0,
		message: "",
		visible: false,
		styles:  DefaultSpinnerStyles(),
	}
}

var spinnerIDCounter int

func nextSpinnerID() int {
	spinnerIDCounter++
	return spinnerIDCounter
}

// Init initializes the spinner
func (s Spinner) Init() tea.Cmd {
	if s.visible {
		return s.tick()
	}
	return nil
}

// tick returns a command that sends a tick message after the appropriate interval
func (s Spinner) tick() tea.Cmd {
	interval := spinnerIntervals[s.style]
	return tea.Tick(interval, func(t time.Time) tea.Msg {
		return SpinnerTickMsg{ID: s.id, Time: t}
	})
}

// Update handles messages
func (s Spinner) Update(msg tea.Msg) (Spinner, tea.Cmd) {
	switch msg := msg.(type) {
	case SpinnerTickMsg:
		if msg.ID != s.id || !s.visible {
			return s, nil
		}

		frames := spinnerFrames[s.style]
		s.frame = (s.frame + 1) % len(frames)
		return s, s.tick()
	}

	return s, nil
}

// View renders the spinner
func (s Spinner) View() string {
	if !s.visible {
		return ""
	}

	frames := spinnerFrames[s.style]
	spinner := s.styles.Spinner.Render(frames[s.frame])

	if s.message == "" {
		return spinner
	}

	message := s.styles.Message.Render(s.message)
	return spinner + message
}

// ViewCentered renders the spinner centered in the given width
func (s Spinner) ViewCentered(width int) string {
	content := s.View()
	if content == "" {
		return ""
	}

	contentWidth := lipgloss.Width(content)
	leftPadding := (width - contentWidth) / 2
	if leftPadding < 0 {
		leftPadding = 0
	}

	return strings.Repeat(" ", leftPadding) + content
}

// ViewBox renders the spinner in a centered box
func (s Spinner) ViewBox(width, height int) string {
	if !s.visible {
		return ""
	}

	content := s.View()
	contentWidth := lipgloss.Width(content)
	contentHeight := 1

	// Calculate padding
	topPadding := (height - contentHeight) / 2
	leftPadding := (width - contentWidth) / 2

	if topPadding < 0 {
		topPadding = 0
	}
	if leftPadding < 0 {
		leftPadding = 0
	}

	var result strings.Builder

	// Add top padding
	for i := 0; i < topPadding; i++ {
		result.WriteString(strings.Repeat(" ", width))
		result.WriteString("\n")
	}

	// Add content with left padding
	result.WriteString(strings.Repeat(" ", leftPadding))
	result.WriteString(content)
	result.WriteString("\n")

	return result.String()
}

// Start starts the spinner animation
func (s *Spinner) Start() tea.Cmd {
	s.visible = true
	s.frame = 0
	return s.tick()
}

// Stop stops the spinner animation
func (s *Spinner) Stop() {
	s.visible = false
}

// IsVisible returns whether the spinner is visible
func (s *Spinner) IsVisible() bool {
	return s.visible
}

// SetMessage sets the spinner message
func (s *Spinner) SetMessage(message string) {
	s.message = message
}

// SetStyle sets the spinner style
func (s *Spinner) SetStyle(style SpinnerStyle) {
	s.style = style
	s.frame = 0
}

// SetStyles sets custom styles
func (s *Spinner) SetStyles(styles SpinnerStyles) {
	s.styles = styles
}

// ID returns the spinner's unique ID
func (s *Spinner) ID() int {
	return s.id
}

// Tick advances the spinner animation manually
func (s *Spinner) Tick() tea.Cmd {
	if s.visible {
		frames := spinnerFrames[s.style]
		s.frame = (s.frame + 1) % len(frames)
		return s.tick()
	}
	return nil
}

// Loading represents a loading state with spinner
type Loading struct {
	spinner Spinner
	title   string
	width   int
	height  int
	styles  LoadingStyles
}

// LoadingStyles contains styles for the loading component
type LoadingStyles struct {
	Container lipgloss.Style
	Title     lipgloss.Style
	Spinner   lipgloss.Style
}

// DefaultLoadingStyles returns the default loading styles
func DefaultLoadingStyles() LoadingStyles {
	return LoadingStyles{
		Container: lipgloss.NewStyle().
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C6FE0")).
			Background(lipgloss.Color("#1E1E2E")),

		Title: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Bold(true).
			Align(lipgloss.Center),

		Spinner: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")),
	}
}

// NewLoading creates a new loading component
func NewLoading() Loading {
	return Loading{
		spinner: NewSpinner(),
		title:   "Loading...",
		width:   40,
		styles:  DefaultLoadingStyles(),
	}
}

// Init initializes the loading component
func (l Loading) Init() tea.Cmd {
	return l.spinner.Init()
}

// Update handles messages
func (l Loading) Update(msg tea.Msg) (Loading, tea.Cmd) {
	var cmd tea.Cmd
	l.spinner, cmd = l.spinner.Update(msg)
	return l, cmd
}

// View renders the loading component
func (l Loading) View() string {
	if !l.spinner.IsVisible() {
		return ""
	}

	var s strings.Builder

	// Title
	s.WriteString(l.styles.Title.Width(l.width - 4).Render(l.title))
	s.WriteString("\n\n")

	// Spinner
	spinnerView := l.spinner.View()
	spinnerWidth := lipgloss.Width(spinnerView)
	leftPadding := (l.width - 4 - spinnerWidth) / 2
	if leftPadding < 0 {
		leftPadding = 0
	}
	s.WriteString(strings.Repeat(" ", leftPadding))
	s.WriteString(spinnerView)

	return l.styles.Container.Width(l.width).Render(s.String())
}

// ViewCentered renders the loading component centered on screen
func (l Loading) ViewCentered() string {
	if !l.spinner.IsVisible() {
		return ""
	}

	content := l.View()
	lines := strings.Split(content, "\n")
	contentHeight := len(lines)
	contentWidth := l.width

	// Calculate padding
	topPadding := (l.height - contentHeight) / 2
	leftPadding := (l.width - contentWidth) / 2

	if topPadding < 0 {
		topPadding = 0
	}
	if leftPadding < 0 {
		leftPadding = 0
	}

	var result strings.Builder

	// Add top padding
	for i := 0; i < topPadding; i++ {
		result.WriteString("\n")
	}

	// Add content with left padding
	for _, line := range lines {
		result.WriteString(strings.Repeat(" ", leftPadding))
		result.WriteString(line)
		result.WriteString("\n")
	}

	return result.String()
}

// Start starts the loading animation
func (l *Loading) Start() tea.Cmd {
	return l.spinner.Start()
}

// Stop stops the loading animation
func (l *Loading) Stop() {
	l.spinner.Stop()
}

// IsLoading returns whether loading is in progress
func (l *Loading) IsLoading() bool {
	return l.spinner.IsVisible()
}

// SetTitle sets the loading title
func (l *Loading) SetTitle(title string) {
	l.title = title
}

// SetMessage sets the spinner message
func (l *Loading) SetMessage(message string) {
	l.spinner.SetMessage(message)
}

// SetWidth sets the loading box width
func (l *Loading) SetWidth(width int) {
	l.width = width
}

// SetSize sets the screen size for centering
func (l *Loading) SetSize(width, height int) {
	l.width = width
	l.height = height
}

// SetSpinnerStyle sets the spinner style
func (l *Loading) SetSpinnerStyle(style SpinnerStyle) {
	l.spinner.SetStyle(style)
}

// SpinnerStartMsg is sent to start a spinner
type SpinnerStartMsg struct {
	Message string
}

// SpinnerStopMsg is sent to stop a spinner
type SpinnerStopMsg struct{}

// LoadingStartMsg is sent to start loading
type LoadingStartMsg struct {
	Title   string
	Message string
}

// LoadingStopMsg is sent to stop loading
type LoadingStopMsg struct{}
