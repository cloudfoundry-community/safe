package view

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/rc"
	"github.com/cloudfoundry-community/safe/tui/adapter"
)

// TargetItem represents a target in the list
type TargetItem struct {
	info adapter.TargetInfo
}

func (t TargetItem) FilterValue() string { return t.info.Alias }
func (t TargetItem) Title() string       { return t.info.Alias }
func (t TargetItem) Description() string { return t.info.URL }

// TargetsModel is the model for the targets view
type TargetsModel struct {
	list     list.Model
	config   *adapter.ConfigAdapter
	selected string
	width    int
	height   int
	keys     targetKeyMap
}

type targetKeyMap struct {
	Select key.Binding
	Add    key.Binding
	Delete key.Binding
	Edit   key.Binding
	Auth   key.Binding
	Quit   key.Binding
	Help   key.Binding
}

func defaultTargetKeyMap() targetKeyMap {
	return targetKeyMap{
		Select: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Add: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "add target"),
		),
		Delete: key.NewBinding(
			key.WithKeys("d"),
			key.WithHelp("d", "delete"),
		),
		Edit: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "edit"),
		),
		Auth: key.NewBinding(
			key.WithKeys("A"),
			key.WithHelp("A", "authenticate"),
		),
		Quit: key.NewBinding(
			key.WithKeys("ctrl+q", "ctrl+c"),
			key.WithHelp("ctrl+q", "quit"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
	}
}

// NewTargetsModel creates a new targets view model
func NewTargetsModel(cfg *rc.Config) TargetsModel {
	configAdapter := adapter.NewConfigAdapter(cfg)
	targets := configAdapter.ListTargets()

	// Create list items
	items := make([]list.Item, len(targets))
	for i, t := range targets {
		items[i] = TargetItem{info: t}
	}

	// Create the list
	delegate := list.NewDefaultDelegate()
	delegate.ShowDescription = true

	// Style the delegate
	delegate.Styles.SelectedTitle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#7C6FE0")).
		Bold(true).
		Padding(0, 1)

	delegate.Styles.SelectedDesc = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#7C6FE0")).
		Padding(0, 1)

	delegate.Styles.NormalTitle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4")).
		Padding(0, 1)

	delegate.Styles.NormalDesc = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Padding(0, 1)

	l := list.New(items, delegate, 0, 0)
	l.Title = "VAULT TARGETS"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(false)

	// Style the list
	l.Styles.Title = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true).
		Padding(0, 1)

	l.Styles.StatusBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	l.Styles.FilterPrompt = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA"))

	l.Styles.FilterCursor = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0"))

	return TargetsModel{
		list:   l,
		config: configAdapter,
		keys:   defaultTargetKeyMap(),
	}
}

// Init initializes the model
func (m TargetsModel) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (m TargetsModel) Update(msg tea.Msg) (TargetsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width, msg.Height-4)
		return m, nil

	case tea.KeyMsg:
		// Don't handle keys when filtering
		if m.list.FilterState() == list.Filtering {
			break
		}

		switch {
		case key.Matches(msg, m.keys.Select):
			if item, ok := m.list.SelectedItem().(TargetItem); ok {
				m.selected = item.info.Alias
				return m, func() tea.Msg {
					return TargetSelectedMsg{Alias: item.info.Alias}
				}
			}

		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// View renders the model
func (m TargetsModel) View() string {
	var s strings.Builder

	// Render the list
	s.WriteString(m.list.View())
	s.WriteString("\n")

	// Help hints at bottom
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	hints := []string{
		"[enter] select",
		"[a] add",
		"[d] delete",
		"[/] filter",
		"[?] help",
		"[ctrl+q] quit",
	}
	s.WriteString(hintStyle.Render(strings.Join(hints, "  ")))

	return s.String()
}

// SelectedTarget returns the currently selected target
func (m TargetsModel) SelectedTarget() string {
	if item, ok := m.list.SelectedItem().(TargetItem); ok {
		return item.info.Alias
	}
	return ""
}

// Refresh reloads targets from config
func (m *TargetsModel) Refresh(cfg *rc.Config) {
	m.config = adapter.NewConfigAdapter(cfg)
	targets := m.config.ListTargets()

	items := make([]list.Item, len(targets))
	for i, t := range targets {
		items[i] = TargetItem{info: t}
	}
	m.list.SetItems(items)
}

// Messages

// TargetSelectedMsg is sent when a target is selected
type TargetSelectedMsg struct {
	Alias string
}

// AddTargetMsg requests adding a new target
type AddTargetMsg struct{}

// DeleteTargetMsg requests deleting a target
type DeleteTargetMsg struct {
	Alias string
}

// AuthenticateMsg requests authentication to a target
type AuthenticateMsg struct {
	Alias string
}
