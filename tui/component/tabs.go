package component

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Tab represents a single tab in the tab bar
type Tab struct {
	ID          string
	Label       string
	TargetAlias string
	Modified    bool
	Closeable   bool
}

// tabPosition tracks the X position of a rendered tab
type tabPosition struct {
	start int
	end   int
}

// TabBar is a component for managing multiple tabs
type TabBar struct {
	tabs      []Tab
	active    int
	width     int
	keys      tabKeyMap
	styles    TabStyles
	showClose bool

	// Mouse support
	tabPositions   []tabPosition // X positions of each tab (calculated during render)
	addButtonStart int           // X position where [+] button starts
}

type tabKeyMap struct {
	NextTab  key.Binding
	PrevTab  key.Binding
	CloseTab key.Binding
	NewTab   key.Binding
	Tab1     key.Binding
	Tab2     key.Binding
	Tab3     key.Binding
	Tab4     key.Binding
	Tab5     key.Binding
	Tab6     key.Binding
	Tab7     key.Binding
	Tab8     key.Binding
	Tab9     key.Binding
}

// TabStyles contains styles for the tab bar
type TabStyles struct {
	Bar         lipgloss.Style
	Active      lipgloss.Style
	Inactive    lipgloss.Style
	Modified    lipgloss.Style
	CloseButton lipgloss.Style
	AddButton   lipgloss.Style
	Separator   lipgloss.Style
}

// DefaultTabStyles returns default tab bar styles
func DefaultTabStyles() TabStyles {
	return TabStyles{
		Bar: lipgloss.NewStyle().
			Background(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#1E1E2E"}).
			Padding(0, 0).
			MarginBottom(0),

		Active: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#1E1E2E"}).
			Background(lipgloss.AdaptiveColor{Light: "#5A4FCF", Dark: "#7C6FE0"}).
			Bold(true).
			Padding(0, 1),

		Inactive: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#757575", Dark: "#A6ADC8"}).
			Background(lipgloss.AdaptiveColor{Light: "#F5F5F5", Dark: "#313244"}).
			Padding(0, 1),

		Modified: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#F57C00", Dark: "#F9E2AF"}).
			Bold(true),

		CloseButton: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#9E9E9E", Dark: "#6C7086"}).
			Padding(0, 0),

		AddButton: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#757575", Dark: "#A6ADC8"}).
			Background(lipgloss.AdaptiveColor{Light: "#F5F5F5", Dark: "#313244"}).
			Padding(0, 1),

		Separator: lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#E0E0E0", Dark: "#45475A"}),
	}
}

func defaultTabKeyMap() tabKeyMap {
	return tabKeyMap{
		NextTab: key.NewBinding(
			key.WithKeys("ctrl+tab", "tab"),
			key.WithHelp("ctrl+tab", "next tab"),
		),
		PrevTab: key.NewBinding(
			key.WithKeys("ctrl+shift+tab", "shift+tab"),
			key.WithHelp("ctrl+shift+tab", "prev tab"),
		),
		CloseTab: key.NewBinding(
			key.WithKeys("ctrl+w"),
			key.WithHelp("ctrl+w", "close tab"),
		),
		NewTab: key.NewBinding(
			key.WithKeys("ctrl+t"),
			key.WithHelp("ctrl+t", "new tab"),
		),
		Tab1: key.NewBinding(
			key.WithKeys("1"),
			key.WithHelp("1", "tab 1"),
		),
		Tab2: key.NewBinding(
			key.WithKeys("2"),
			key.WithHelp("2", "tab 2"),
		),
		Tab3: key.NewBinding(
			key.WithKeys("3"),
			key.WithHelp("3", "tab 3"),
		),
		Tab4: key.NewBinding(
			key.WithKeys("4"),
			key.WithHelp("4", "tab 4"),
		),
		Tab5: key.NewBinding(
			key.WithKeys("5"),
			key.WithHelp("5", "tab 5"),
		),
		Tab6: key.NewBinding(
			key.WithKeys("6"),
			key.WithHelp("6", "tab 6"),
		),
		Tab7: key.NewBinding(
			key.WithKeys("7"),
			key.WithHelp("7", "tab 7"),
		),
		Tab8: key.NewBinding(
			key.WithKeys("8"),
			key.WithHelp("8", "tab 8"),
		),
		Tab9: key.NewBinding(
			key.WithKeys("9"),
			key.WithHelp("9", "tab 9"),
		),
	}
}

// NewTabBar creates a new tab bar component
func NewTabBar() TabBar {
	return TabBar{
		tabs:      make([]Tab, 0),
		active:    0,
		keys:      defaultTabKeyMap(),
		styles:    DefaultTabStyles(),
		showClose: true,
	}
}

// SetWidth sets the width of the tab bar
func (t *TabBar) SetWidth(width int) {
	t.width = width
}

// SetShowClose sets whether to show close buttons
func (t *TabBar) SetShowClose(show bool) {
	t.showClose = show
}

// AddTab adds a new tab
func (t *TabBar) AddTab(tab Tab) int {
	t.tabs = append(t.tabs, tab)
	return len(t.tabs) - 1
}

// RemoveTab removes a tab by index
func (t *TabBar) RemoveTab(index int) {
	if index < 0 || index >= len(t.tabs) {
		return
	}

	t.tabs = append(t.tabs[:index], t.tabs[index+1:]...)

	// Adjust active index if needed
	if t.active >= len(t.tabs) && len(t.tabs) > 0 {
		t.active = len(t.tabs) - 1
	}
	if t.active < 0 {
		t.active = 0
	}
}

// RemoveTabByID removes a tab by its ID
func (t *TabBar) RemoveTabByID(id string) {
	for i, tab := range t.tabs {
		if tab.ID == id {
			t.RemoveTab(i)
			return
		}
	}
}

// GetTab returns a tab by index
func (t *TabBar) GetTab(index int) *Tab {
	if index < 0 || index >= len(t.tabs) {
		return nil
	}
	return &t.tabs[index]
}

// GetTabByID returns a tab by its ID
func (t *TabBar) GetTabByID(id string) *Tab {
	for i := range t.tabs {
		if t.tabs[i].ID == id {
			return &t.tabs[i]
		}
	}
	return nil
}

// GetActiveTab returns the active tab
func (t *TabBar) GetActiveTab() *Tab {
	return t.GetTab(t.active)
}

// GetActiveIndex returns the active tab index
func (t *TabBar) GetActiveIndex() int {
	return t.active
}

// SetActiveIndex sets the active tab by index
func (t *TabBar) SetActiveIndex(index int) {
	if index >= 0 && index < len(t.tabs) {
		t.active = index
	}
}

// SetActiveByID sets the active tab by ID
func (t *TabBar) SetActiveByID(id string) {
	for i, tab := range t.tabs {
		if tab.ID == id {
			t.active = i
			return
		}
	}
}

// SetModified sets the modified state of a tab by ID
func (t *TabBar) SetModified(id string, modified bool) {
	for i := range t.tabs {
		if t.tabs[i].ID == id {
			t.tabs[i].Modified = modified
			return
		}
	}
}

// TabCount returns the number of tabs
func (t *TabBar) TabCount() int {
	return len(t.tabs)
}

// HasTabs returns whether there are any tabs
func (t *TabBar) HasTabs() bool {
	return len(t.tabs) > 0
}

// NextTab switches to the next tab
func (t *TabBar) NextTab() {
	if len(t.tabs) > 0 {
		t.active = (t.active + 1) % len(t.tabs)
	}
}

// PrevTab switches to the previous tab
func (t *TabBar) PrevTab() {
	if len(t.tabs) > 0 {
		t.active = (t.active - 1 + len(t.tabs)) % len(t.tabs)
	}
}

// GoToTab switches to a specific tab by number (1-9)
func (t *TabBar) GoToTab(num int) bool {
	index := num - 1
	if index >= 0 && index < len(t.tabs) {
		t.active = index
		return true
	}
	return false
}

// handleMouse handles mouse events for the tab bar
func (t TabBar) handleMouse(msg tea.MouseMsg) (TabBar, tea.Cmd) {
	// Only handle left clicks on the tab bar row (Y == 0)
	if msg.Type != tea.MouseLeft || msg.Y != 0 {
		return t, nil
	}

	// Check if click is on a tab
	for i, pos := range t.tabPositions {
		if msg.X >= pos.start && msg.X < pos.end {
			t.active = i
			return t, func() tea.Msg {
				return TabSwitchedMsg{Index: i}
			}
		}
	}

	// Check if click is on the [+] button
	if t.addButtonStart > 0 && msg.X >= t.addButtonStart {
		return t, func() tea.Msg {
			return TabNewRequestMsg{}
		}
	}

	return t, nil
}

// Init initializes the tab bar
func (t TabBar) Init() tea.Cmd {
	return nil
}

// Update handles messages for the tab bar
func (t TabBar) Update(msg tea.Msg) (TabBar, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		return t.handleMouse(msg)

	case tea.KeyMsg:
		// Handle vim-style gt/gT for tab navigation
		keyStr := msg.String()

		switch {
		case keyStr == "g":
			// Wait for next key - this would need state tracking
			// For simplicity, gt and gT are handled as sequences in root model
			return t, nil

		case key.Matches(msg, t.keys.NextTab):
			t.NextTab()
			return t, func() tea.Msg {
				return TabSwitchedMsg{Index: t.active}
			}

		case key.Matches(msg, t.keys.PrevTab):
			t.PrevTab()
			return t, func() tea.Msg {
				return TabSwitchedMsg{Index: t.active}
			}

		case key.Matches(msg, t.keys.CloseTab):
			if len(t.tabs) > 0 {
				index := t.active
				return t, func() tea.Msg {
					return TabCloseRequestMsg{Index: index}
				}
			}

		case key.Matches(msg, t.keys.NewTab):
			return t, func() tea.Msg {
				return TabNewRequestMsg{}
			}

		// Number keys 1-9 for direct tab access
		case key.Matches(msg, t.keys.Tab1):
			if t.GoToTab(1) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab2):
			if t.GoToTab(2) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab3):
			if t.GoToTab(3) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab4):
			if t.GoToTab(4) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab5):
			if t.GoToTab(5) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab6):
			if t.GoToTab(6) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab7):
			if t.GoToTab(7) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab8):
			if t.GoToTab(8) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		case key.Matches(msg, t.keys.Tab9):
			if t.GoToTab(9) {
				return t, func() tea.Msg {
					return TabSwitchedMsg{Index: t.active}
				}
			}
		}
	}

	return t, nil
}

// View renders the tab bar
func (t *TabBar) View() string {
	if len(t.tabs) == 0 {
		return ""
	}

	var parts []string

	// Track positions for mouse click detection
	t.tabPositions = make([]tabPosition, len(t.tabs))
	currentX := 0

	for i, tab := range t.tabs {
		rendered := t.renderTab(tab, i == t.active, i)
		renderedWidth := lipgloss.Width(rendered)

		t.tabPositions[i] = tabPosition{
			start: currentX,
			end:   currentX + renderedWidth,
		}
		currentX += renderedWidth + 1 // +1 for space separator

		parts = append(parts, rendered)
	}

	// Add the [+] button and track its position
	addBtn := t.styles.AddButton.Render("[+]")
	t.addButtonStart = currentX
	parts = append(parts, addBtn)

	// Join all tabs
	content := strings.Join(parts, " ")

	// Apply bar style with full width
	return t.styles.Bar.Width(t.width).Render(content)
}

// renderTab renders a single tab
func (t *TabBar) renderTab(tab Tab, isActive bool, index int) string {
	var s strings.Builder

	// Tab number prefix for tabs 1-9
	if index < 9 {
		numStyle := lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#9E9E9E", Dark: "#6C7086"})
		s.WriteString(numStyle.Render(string(rune('1' + index))))
		s.WriteString(":")
	}

	// Tab label with modified indicator
	label := tab.Label
	if tab.Modified {
		label = t.styles.Modified.Render("*") + label
	}

	// Close button
	closeBtn := ""
	if t.showClose && tab.Closeable {
		closeBtn = " " + t.styles.CloseButton.Render("x")
	}

	// Combine label and close button
	content := label + closeBtn

	// Apply active/inactive style
	var style lipgloss.Style
	if isActive {
		style = t.styles.Active
	} else {
		style = t.styles.Inactive
	}

	s.WriteString(style.Render("[" + content + "]"))

	return s.String()
}

// ViewCompact renders a compact version of the tab bar (for narrow terminals)
func (t TabBar) ViewCompact() string {
	if len(t.tabs) == 0 {
		return ""
	}

	var parts []string

	for i, tab := range t.tabs {
		// Use short label (first 8 chars)
		shortLabel := tab.Label
		if len(shortLabel) > 8 {
			shortLabel = shortLabel[:7] + "..."
		}

		shortTab := Tab{
			ID:          tab.ID,
			Label:       shortLabel,
			TargetAlias: tab.TargetAlias,
			Modified:    tab.Modified,
			Closeable:   tab.Closeable,
		}
		parts = append(parts, t.renderTabCompact(shortTab, i == t.active))
	}

	// Add the [+] button
	addBtn := t.styles.AddButton.Render("+")
	parts = append(parts, addBtn)

	return strings.Join(parts, "")
}

// renderTabCompact renders a compact tab
func (t *TabBar) renderTabCompact(tab Tab, isActive bool) string {
	label := tab.Label
	if tab.Modified {
		label += "*"
	}

	var style lipgloss.Style
	if isActive {
		style = t.styles.Active
	} else {
		style = t.styles.Inactive
	}

	return style.Render("[" + label + "]")
}

// Messages for tab bar events

// TabSwitchedMsg is sent when the active tab changes
type TabSwitchedMsg struct {
	Index int
}

// TabCloseRequestMsg is sent when a tab close is requested
type TabCloseRequestMsg struct {
	Index int
}

// TabNewRequestMsg is sent when a new tab is requested
type TabNewRequestMsg struct{}

// TabClosedMsg is sent when a tab has been closed
type TabClosedMsg struct {
	ID    string
	Index int
}

// TabCreatedMsg is sent when a new tab is created
type TabCreatedMsg struct {
	ID          string
	TargetAlias string
	Index       int
}
