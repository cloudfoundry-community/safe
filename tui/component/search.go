package component

import (
	"fmt"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SearchMode represents the search display mode
type SearchMode int

const (
	SearchModeJump   SearchMode = iota // Highlight matches, n/N to navigate
	SearchModeFilter                   // Hide non-matching paths
)

// String returns the display name for the mode
func (m SearchMode) String() string {
	switch m {
	case SearchModeJump:
		return "jump"
	case SearchModeFilter:
		return "filter"
	default:
		return "unknown"
	}
}

// SearchPatternType represents the pattern matching type
type SearchPatternType int

const (
	SearchPatternGlob  SearchPatternType = iota // Glob pattern (default)
	SearchPatternRegex                          // Regular expression
)

// String returns the display name for the pattern type
func (t SearchPatternType) String() string {
	switch t {
	case SearchPatternGlob:
		return "glob"
	case SearchPatternRegex:
		return "regex"
	default:
		return "unknown"
	}
}

// SearchState holds the current search state
type SearchState struct {
	Active      bool              // Is search currently active
	Query       string            // Current search query
	Mode        SearchMode        // Jump or Filter mode
	PatternType SearchPatternType // Glob or Regex
	Matches     []int             // Indices of matching nodes in flattened list
	MatchCursor int               // Current match index for n/N navigation
	Error       string            // Pattern compilation error (for regex)
}

// Range represents a character range for highlighting
type Range struct {
	Start int
	End   int
}

// Search is the search input/state component
type Search struct {
	input  textinput.Model
	state  SearchState
	width  int
	styles SearchStyles
	keys   searchKeyMap
}

// SearchStyles contains styles for the search component
type SearchStyles struct {
	Input          lipgloss.Style
	InputActive    lipgloss.Style
	ModeIndicator  lipgloss.Style
	MatchCount     lipgloss.Style
	Error          lipgloss.Style
	MatchHighlight lipgloss.Style
}

type searchKeyMap struct {
	NextMatch  key.Binding
	PrevMatch  key.Binding
	ToggleMode key.Binding
	ToggleType key.Binding
	Cancel     key.Binding
	Confirm    key.Binding
}

// DefaultSearchStyles returns default search styles
func DefaultSearchStyles() SearchStyles {
	return SearchStyles{
		Input: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#313244")).
			Padding(0, 1),

		InputActive: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#45475A")).
			Padding(0, 1),

		ModeIndicator: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")),

		MatchCount: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")),

		Error: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")),

		MatchHighlight: lipgloss.NewStyle().
			Background(lipgloss.Color("#F9E2AF")).
			Foreground(lipgloss.Color("#1E1E2E")).
			Bold(true),
	}
}

func defaultSearchKeyMap() searchKeyMap {
	return searchKeyMap{
		NextMatch: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "next match"),
		),
		PrevMatch: key.NewBinding(
			key.WithKeys("N"),
			key.WithHelp("N", "prev match"),
		),
		ToggleMode: key.NewBinding(
			key.WithKeys("ctrl+f"),
			key.WithHelp("ctrl+f", "toggle filter/jump"),
		),
		ToggleType: key.NewBinding(
			key.WithKeys("ctrl+r"),
			key.WithHelp("ctrl+r", "toggle regex/glob"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "cancel search"),
		),
		Confirm: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "confirm"),
		),
	}
}

// NewSearch creates a new search component
func NewSearch() Search {
	ti := textinput.New()
	ti.Placeholder = "Search pattern..."
	ti.CharLimit = 256
	ti.Width = 30

	return Search{
		input:  ti,
		state:  SearchState{},
		styles: DefaultSearchStyles(),
		keys:   defaultSearchKeyMap(),
	}
}

// Init initializes the search component
func (s Search) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages for the search component
func (s Search) Update(msg tea.Msg) (Search, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, s.keys.Cancel):
			s.state.Active = false
			s.input.Blur()
			s.input.SetValue("")
			s.state.Query = ""
			s.state.Matches = nil
			s.state.MatchCursor = 0
			s.state.Error = ""
			return s, func() tea.Msg { return SearchCancelMsg{} }

		case key.Matches(msg, s.keys.Confirm):
			s.input.Blur()
			return s, func() tea.Msg { return SearchConfirmMsg{} }

		case msg.String() == "tab":
			// Tab switches focus to results
			s.input.Blur()
			return s, func() tea.Msg { return SearchBlurMsg{} }

		case key.Matches(msg, s.keys.ToggleMode):
			s.ToggleMode()
			return s, func() tea.Msg { return SearchToggleModeMsg{} }

		case key.Matches(msg, s.keys.ToggleType):
			s.ToggleType()
			return s, func() tea.Msg {
				return SearchQueryMsg{
					Query:       s.state.Query,
					PatternType: s.state.PatternType,
				}
			}
		}
	}

	// Update text input
	oldValue := s.input.Value()
	s.input, cmd = s.input.Update(msg)
	newValue := s.input.Value()

	// If query changed, emit search query message
	if oldValue != newValue {
		s.state.Query = newValue
		return s, tea.Batch(cmd, func() tea.Msg {
			return SearchQueryMsg{
				Query:       newValue,
				PatternType: s.state.PatternType,
			}
		})
	}

	return s, cmd
}

// View renders the search component
func (s Search) View() string {
	return s.input.View()
}

// ViewWithStatus renders the search bar with mode indicator and match count
func (s Search) ViewWithStatus() string {
	// Mode indicator
	modeStr := fmt.Sprintf("[%s|%s]", s.state.PatternType, s.state.Mode)
	indicator := s.styles.ModeIndicator.Render(modeStr)

	// Input
	inputView := s.input.View()

	// Build result
	result := indicator + " " + inputView

	// Match count
	if len(s.state.Matches) > 0 {
		count := fmt.Sprintf(" %d/%d", s.state.MatchCursor+1, len(s.state.Matches))
		result += s.styles.MatchCount.Render(count)
	} else if s.state.Query != "" && s.state.Error == "" {
		result += s.styles.ModeIndicator.Render(" no matches")
	}

	// Error
	if s.state.Error != "" {
		result += " " + s.styles.Error.Render(s.state.Error)
	}

	return result
}

// Focus focuses the search input
func (s *Search) Focus() tea.Cmd {
	s.state.Active = true
	return s.input.Focus()
}

// Blur blurs the search input
func (s *Search) Blur() {
	s.input.Blur()
}

// IsFocused returns whether the input is focused
func (s *Search) IsFocused() bool {
	return s.input.Focused()
}

// SetWidth sets the width of the search input
func (s *Search) SetWidth(width int) {
	s.width = width
	s.input.Width = width - 20 // Account for mode indicator and match count
	if s.input.Width < 10 {
		s.input.Width = 10
	}
}

// State returns the current search state
func (s *Search) State() *SearchState {
	return &s.state
}

// SetMatches sets the match indices
func (s *Search) SetMatches(matches []int) {
	s.state.Matches = matches
	if len(matches) > 0 && s.state.MatchCursor >= len(matches) {
		s.state.MatchCursor = 0
	}
}

// SetError sets the error message
func (s *Search) SetError(err string) {
	s.state.Error = err
}

// ClearError clears the error message
func (s *Search) ClearError() {
	s.state.Error = ""
}

// HasMatches returns whether there are any matches
func (s *Search) HasMatches() bool {
	return len(s.state.Matches) > 0
}

// MatchCount returns the number of matches
func (s *Search) MatchCount() int {
	return len(s.state.Matches)
}

// CurrentMatchIndex returns the current match cursor position
func (s *Search) CurrentMatchIndex() int {
	return s.state.MatchCursor
}

// CurrentMatch returns the node index of the current match
func (s *Search) CurrentMatch() int {
	if len(s.state.Matches) == 0 {
		return -1
	}
	return s.state.Matches[s.state.MatchCursor]
}

// NextMatch moves to the next match
func (s *Search) NextMatch() {
	if len(s.state.Matches) == 0 {
		return
	}
	s.state.MatchCursor = (s.state.MatchCursor + 1) % len(s.state.Matches)
}

// PrevMatch moves to the previous match
func (s *Search) PrevMatch() {
	if len(s.state.Matches) == 0 {
		return
	}
	s.state.MatchCursor--
	if s.state.MatchCursor < 0 {
		s.state.MatchCursor = len(s.state.Matches) - 1
	}
}

// ToggleMode toggles between Jump and Filter mode
func (s *Search) ToggleMode() {
	if s.state.Mode == SearchModeJump {
		s.state.Mode = SearchModeFilter
	} else {
		s.state.Mode = SearchModeJump
	}
}

// ToggleType toggles between Glob and Regex pattern type
func (s *Search) ToggleType() {
	if s.state.PatternType == SearchPatternGlob {
		s.state.PatternType = SearchPatternRegex
	} else {
		s.state.PatternType = SearchPatternGlob
	}
}

// Reset resets the search state
func (s *Search) Reset() {
	s.input.SetValue("")
	s.state = SearchState{}
}

// Query returns the current search query
func (s *Search) Query() string {
	return s.state.Query
}

// IsActive returns whether search is active
func (s *Search) IsActive() bool {
	return s.state.Active
}

// Message types

// SearchStartMsg indicates search mode is starting
type SearchStartMsg struct{}

// SearchQueryMsg indicates the search query changed
type SearchQueryMsg struct {
	Query       string
	PatternType SearchPatternType
}

// SearchMatchesMsg contains computed matches
type SearchMatchesMsg struct {
	Matches []int  // Node indices
	Error   string // Pattern error if any
}

// SearchNextMatchMsg requests navigation to next match
type SearchNextMatchMsg struct{}

// SearchPrevMatchMsg requests navigation to previous match
type SearchPrevMatchMsg struct{}

// SearchToggleModeMsg toggles between Jump and Filter mode
type SearchToggleModeMsg struct{}

// SearchToggleTypeMsg toggles between Glob and Regex
type SearchToggleTypeMsg struct{}

// SearchCancelMsg cancels search
type SearchCancelMsg struct{}

// SearchConfirmMsg confirms current position and exits search
type SearchConfirmMsg struct{}

// SearchBlurMsg is sent when Tab is pressed to switch focus to results
type SearchBlurMsg struct{}

// SearchFocusNodeMsg requests focusing on a specific node
type SearchFocusNodeMsg struct {
	NodeIndex int
}
