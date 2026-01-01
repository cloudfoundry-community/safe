package view

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/vault"
)

// EditorModel is the model for the secret editor view
type EditorModel struct {
	path   string
	vault  *adapter.VaultAdapter
	target string

	// Key-value pairs
	keys   []string
	values map[string]string

	// Original values for change detection
	originalKeys   []string
	originalValues map[string]string

	// UI state
	cursor       int
	editingKey   bool
	editingValue bool
	showValues   bool
	modified     bool

	// Text inputs for editing
	keyInput   textinput.Model
	valueInput textinput.Model

	// Adding new key-value pair
	addingNew bool
	newKey    textinput.Model
	newValue  textinput.Model

	// Confirm discard dialog
	showConfirm  bool
	confirmFocus int

	// Layout
	width  int
	height int

	// Keys
	editorKeys editorKeyMap

	// Styles
	styles editorStyles
}

type editorKeyMap struct {
	Up          key.Binding
	Down        key.Binding
	Edit        key.Binding
	EditValue   key.Binding
	ToggleShow  key.Binding
	AddKey      key.Binding
	DeleteKey   key.Binding
	Save        key.Binding
	Cancel      key.Binding
	Confirm     key.Binding
	GenPassword key.Binding
	Tab         key.Binding
}

type editorStyles struct {
	Title        lipgloss.Style
	Path         lipgloss.Style
	Key          lipgloss.Style
	KeySelected  lipgloss.Style
	Value        lipgloss.Style
	ValueMasked  lipgloss.Style
	Modified     lipgloss.Style
	Input        lipgloss.Style
	InputFocused lipgloss.Style
	Help         lipgloss.Style
	Button       lipgloss.Style
	ButtonFocus  lipgloss.Style
	ButtonDanger lipgloss.Style
	Modal        lipgloss.Style
	ModalTitle   lipgloss.Style
}

func defaultEditorKeyMap() editorKeyMap {
	return editorKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/up", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/down", "down"),
		),
		Edit: key.NewBinding(
			key.WithKeys("e", "enter"),
			key.WithHelp("e/enter", "edit value"),
		),
		EditValue: key.NewBinding(
			key.WithKeys("E"),
			key.WithHelp("E", "edit key name"),
		),
		ToggleShow: key.NewBinding(
			key.WithKeys("ctrl+v"),
			key.WithHelp("ctrl+v", "toggle values"),
		),
		AddKey: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "add key"),
		),
		DeleteKey: key.NewBinding(
			key.WithKeys("d", "delete"),
			key.WithHelp("d", "delete key"),
		),
		Save: key.NewBinding(
			key.WithKeys("ctrl+s"),
			key.WithHelp("ctrl+s", "save"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "cancel"),
		),
		Confirm: key.NewBinding(
			key.WithKeys("y", "enter"),
			key.WithHelp("y/enter", "confirm"),
		),
		GenPassword: key.NewBinding(
			key.WithKeys("g"),
			key.WithHelp("g", "generate password"),
		),
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "next field"),
		),
	}
}

func defaultEditorStyles() editorStyles {
	return editorStyles{
		Title: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Bold(true),
		Path: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")).
			Bold(true),
		Key: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Width(20),
		KeySelected: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#45475A")).
			Width(20).
			Bold(true),
		Value: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")),
		ValueMasked: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")),
		Modified: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Bold(true),
		Input: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#45475A")).
			Padding(0, 1),
		InputFocused: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C6FE0")).
			Padding(0, 1),
		Help: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")),
		Button: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#313244")).
			Padding(0, 2),
		ButtonFocus: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#7C6FE0")).
			Padding(0, 2).
			Bold(true),
		ButtonDanger: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#F38BA8")).
			Padding(0, 2).
			Bold(true),
		Modal: lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#F9E2AF")).
			Background(lipgloss.Color("#1E1E2E")).
			Padding(1, 2),
		ModalTitle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Bold(true),
	}
}

// NewEditorModel creates a new editor model
func NewEditorModel(path string, target string, vault *adapter.VaultAdapter) EditorModel {
	// Create text inputs
	keyInput := textinput.New()
	keyInput.Placeholder = "key name"
	keyInput.Width = 30

	valueInput := textinput.New()
	valueInput.Placeholder = "value"
	valueInput.Width = 50

	newKey := textinput.New()
	newKey.Placeholder = "new key name"
	newKey.Width = 30

	newValue := textinput.New()
	newValue.Placeholder = "value"
	newValue.Width = 50

	return EditorModel{
		path:           path,
		vault:          vault,
		target:         target,
		keys:           make([]string, 0),
		values:         make(map[string]string),
		originalKeys:   make([]string, 0),
		originalValues: make(map[string]string),
		showValues:     false,
		keyInput:       keyInput,
		valueInput:     valueInput,
		newKey:         newKey,
		newValue:       newValue,
		editorKeys:     defaultEditorKeyMap(),
		styles:         defaultEditorStyles(),
		width:          80, // Default until WindowSizeMsg
		height:         24,
	}
}

// Init initializes the editor
func (m EditorModel) Init() tea.Cmd {
	return m.loadSecret()
}

// loadSecret loads the secret from vault
func (m *EditorModel) loadSecret() tea.Cmd {
	return func() tea.Msg {
		secret, err := m.vault.Read(m.path)
		if err != nil {
			return EditorErrorMsg{Err: err}
		}
		return EditorSecretLoadedMsg{Path: m.path, Secret: secret}
	}
}

// SetSecret sets the secret data to edit
func (m *EditorModel) SetSecret(secret *vault.Secret) {
	if secret == nil {
		return
	}

	m.keys = secret.Keys()
	sort.Strings(m.keys)

	m.values = make(map[string]string)
	for _, k := range m.keys {
		m.values[k] = secret.Get(k)
	}

	// Store originals for change detection
	m.originalKeys = make([]string, len(m.keys))
	copy(m.originalKeys, m.keys)
	m.originalValues = make(map[string]string)
	for k, v := range m.values {
		m.originalValues[k] = v
	}

	m.modified = false
}

// Update handles messages
func (m EditorModel) Update(msg tea.Msg) (EditorModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case EditorSecretLoadedMsg:
		m.SetSecret(msg.Secret)
		return m, nil

	case EditorErrorMsg:
		// Handle error - could set an error state
		return m, nil

	case EditorSavedMsg:
		// Secret saved, go back to browser
		return m, func() tea.Msg {
			return EditorCloseMsg{Saved: true}
		}

	case EditorSaveErrorMsg:
		// Handle save error
		return m, nil

	case GeneratedPasswordMsg:
		if m.cursor < len(m.keys) {
			key := m.keys[m.cursor]
			m.values[key] = msg.Password
			m.modified = true
		} else if m.addingNew {
			m.newValue.SetValue(msg.Password)
		}
		return m, nil

	case tea.KeyMsg:
		// Handle confirm dialog first
		if m.showConfirm {
			return m.updateConfirmDialog(msg)
		}

		// Handle adding new key-value
		if m.addingNew {
			return m.updateAddingNew(msg)
		}

		// Handle editing
		if m.editingValue {
			return m.updateEditingValue(msg)
		}

		if m.editingKey {
			return m.updateEditingKey(msg)
		}

		// Normal navigation
		return m.updateNavigation(msg)
	}

	return m, tea.Batch(cmds...)
}

// updateNavigation handles navigation keys
func (m EditorModel) updateNavigation(msg tea.KeyMsg) (EditorModel, tea.Cmd) {
	switch {
	case key.Matches(msg, m.editorKeys.Up):
		if m.cursor > 0 {
			m.cursor--
		}

	case key.Matches(msg, m.editorKeys.Down):
		if m.cursor < len(m.keys)-1 {
			m.cursor++
		}

	case key.Matches(msg, m.editorKeys.Edit):
		if len(m.keys) > 0 && m.cursor < len(m.keys) {
			m.editingValue = true
			m.valueInput.SetValue(m.values[m.keys[m.cursor]])
			m.valueInput.Focus()
			return m, textinput.Blink
		}

	case key.Matches(msg, m.editorKeys.EditValue):
		if len(m.keys) > 0 && m.cursor < len(m.keys) {
			m.editingKey = true
			m.keyInput.SetValue(m.keys[m.cursor])
			m.keyInput.Focus()
			return m, textinput.Blink
		}

	case key.Matches(msg, m.editorKeys.ToggleShow):
		m.showValues = !m.showValues

	case key.Matches(msg, m.editorKeys.AddKey):
		m.addingNew = true
		m.newKey.SetValue("")
		m.newValue.SetValue("")
		m.newKey.Focus()
		return m, textinput.Blink

	case key.Matches(msg, m.editorKeys.DeleteKey):
		if len(m.keys) > 0 && m.cursor < len(m.keys) {
			keyToDelete := m.keys[m.cursor]
			delete(m.values, keyToDelete)
			m.keys = removeString(m.keys, m.cursor)
			if m.cursor >= len(m.keys) && m.cursor > 0 {
				m.cursor--
			}
			m.modified = true
		}

	case key.Matches(msg, m.editorKeys.GenPassword):
		if len(m.keys) > 0 && m.cursor < len(m.keys) {
			return m, generatePasswordCmd(32, "a-zA-Z0-9!@#$%^&*")
		}

	case key.Matches(msg, m.editorKeys.Save):
		return m, m.saveSecret()

	case key.Matches(msg, m.editorKeys.Cancel):
		if m.modified {
			m.showConfirm = true
			m.confirmFocus = 0
		} else {
			return m, func() tea.Msg {
				return EditorCloseMsg{Saved: false}
			}
		}

	case msg.String() == "g":
		// Go to top
		m.cursor = 0

	case msg.String() == "G":
		// Go to bottom
		if len(m.keys) > 0 {
			m.cursor = len(m.keys) - 1
		}
	}

	return m, nil
}

// updateEditingValue handles editing a value
func (m EditorModel) updateEditingValue(msg tea.KeyMsg) (EditorModel, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.editingValue = false
		m.valueInput.Blur()
		return m, nil

	case tea.KeyEnter:
		if m.cursor < len(m.keys) {
			key := m.keys[m.cursor]
			newValue := m.valueInput.Value()
			if m.values[key] != newValue {
				m.values[key] = newValue
				m.modified = true
			}
		}
		m.editingValue = false
		m.valueInput.Blur()
		return m, nil
	}

	// Update the text input
	var cmd tea.Cmd
	m.valueInput, cmd = m.valueInput.Update(msg)
	return m, cmd
}

// updateEditingKey handles editing a key name
func (m EditorModel) updateEditingKey(msg tea.KeyMsg) (EditorModel, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.editingKey = false
		m.keyInput.Blur()
		return m, nil

	case tea.KeyEnter:
		if m.cursor < len(m.keys) {
			oldKey := m.keys[m.cursor]
			newKey := strings.TrimSpace(m.keyInput.Value())
			if newKey != "" && newKey != oldKey {
				// Check for duplicate
				if _, exists := m.values[newKey]; !exists {
					// Rename key
					value := m.values[oldKey]
					delete(m.values, oldKey)
					m.values[newKey] = value
					m.keys[m.cursor] = newKey
					m.modified = true
				}
			}
		}
		m.editingKey = false
		m.keyInput.Blur()
		return m, nil
	}

	// Update the text input
	var cmd tea.Cmd
	m.keyInput, cmd = m.keyInput.Update(msg)
	return m, cmd
}

// updateAddingNew handles adding a new key-value pair
func (m EditorModel) updateAddingNew(msg tea.KeyMsg) (EditorModel, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.addingNew = false
		m.newKey.Blur()
		m.newValue.Blur()
		return m, nil

	case tea.KeyTab, tea.KeyShiftTab:
		// Toggle focus between key and value inputs
		if m.newKey.Focused() {
			m.newKey.Blur()
			m.newValue.Focus()
		} else {
			m.newValue.Blur()
			m.newKey.Focus()
		}
		return m, textinput.Blink

	case tea.KeyEnter:
		if m.newValue.Focused() {
			// Submit new key-value pair
			newKey := strings.TrimSpace(m.newKey.Value())
			newValue := m.newValue.Value()
			if newKey != "" {
				// Check for duplicate
				if _, exists := m.values[newKey]; !exists {
					m.keys = append(m.keys, newKey)
					sort.Strings(m.keys)
					m.values[newKey] = newValue
					m.modified = true
					// Find new cursor position
					for i, k := range m.keys {
						if k == newKey {
							m.cursor = i
							break
						}
					}
				}
			}
			m.addingNew = false
			m.newKey.Blur()
			m.newValue.Blur()
			return m, nil
		}
		// Move to value field
		m.newKey.Blur()
		m.newValue.Focus()
		return m, textinput.Blink
	}

	// Handle generate password in add mode
	if key.Matches(msg, m.editorKeys.GenPassword) && m.newValue.Focused() {
		return m, generatePasswordCmd(32, "a-zA-Z0-9!@#$%^&*")
	}

	// Update the focused input
	var cmd tea.Cmd
	if m.newKey.Focused() {
		m.newKey, cmd = m.newKey.Update(msg)
	} else {
		m.newValue, cmd = m.newValue.Update(msg)
	}
	return m, cmd
}

// updateConfirmDialog handles the confirm discard dialog
func (m EditorModel) updateConfirmDialog(msg tea.KeyMsg) (EditorModel, tea.Cmd) {
	switch {
	case msg.String() == "y" || (msg.Type == tea.KeyEnter && m.confirmFocus == 0):
		// Discard changes
		m.showConfirm = false
		return m, func() tea.Msg {
			return EditorCloseMsg{Saved: false}
		}

	case msg.String() == "n" || msg.Type == tea.KeyEsc || (msg.Type == tea.KeyEnter && m.confirmFocus == 1):
		// Cancel, go back to editing
		m.showConfirm = false
		return m, nil

	case msg.Type == tea.KeyTab, msg.Type == tea.KeyLeft, msg.Type == tea.KeyRight:
		// Toggle button focus
		m.confirmFocus = 1 - m.confirmFocus
	}

	return m, nil
}

// saveSecret saves the current secret to vault
func (m *EditorModel) saveSecret() tea.Cmd {
	return func() tea.Msg {
		secret := vault.NewSecret()
		for _, k := range m.keys {
			if err := secret.Set(k, m.values[k], false); err != nil {
				return EditorSaveErrorMsg{Path: m.path, Err: err}
			}
		}

		err := m.vault.Write(m.path, secret)
		if err != nil {
			return EditorSaveErrorMsg{Path: m.path, Err: err}
		}

		return EditorSavedMsg{Path: m.path}
	}
}

// View renders the editor
func (m EditorModel) View() string {
	var s strings.Builder

	// Header
	s.WriteString(m.styles.Title.Render("SECRET EDITOR"))
	s.WriteString("  ")
	s.WriteString(m.styles.Path.Render(m.path))
	if m.modified {
		s.WriteString("  ")
		s.WriteString(m.styles.Modified.Render("[modified]"))
	}
	s.WriteString("\n")
	dividerWidth := m.width - 2
	if dividerWidth < 1 {
		dividerWidth = 1
	}
	s.WriteString(strings.Repeat("-", dividerWidth))
	s.WriteString("\n\n")

	// Show confirm dialog if active
	if m.showConfirm {
		s.WriteString(m.renderConfirmDialog())
		return s.String()
	}

	// Show add new form if active
	if m.addingNew {
		s.WriteString(m.renderAddNewForm())
		return s.String()
	}

	// Key-value table
	s.WriteString(m.renderTable())

	// Help hints
	s.WriteString("\n\n")
	if m.editingValue || m.editingKey {
		s.WriteString(m.styles.Help.Render("[Enter] save  [Esc] cancel"))
	} else {
		hints := "[j/k] navigate  [e] edit value  [E] edit key  [a] add  [d] delete  [g] gen password  [Ctrl+V] toggle show  [Ctrl+S] save  [Esc] cancel"
		s.WriteString(m.styles.Help.Render(hints))
	}

	return s.String()
}

// renderTable renders the key-value table
func (m EditorModel) renderTable() string {
	if len(m.keys) == 0 {
		mutedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Italic(true)
		return mutedStyle.Render("  No keys. Press [a] to add one.")
	}

	var s strings.Builder

	// Table header
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Bold(true)
	s.WriteString("  ")
	s.WriteString(headerStyle.Render(padRight("KEY", 20)))
	s.WriteString("  ")
	s.WriteString(headerStyle.Render("VALUE"))
	s.WriteString("\n")
	s.WriteString("  ")
	tableWidth := m.width - 6
	if tableWidth < 1 {
		tableWidth = 1
	}
	s.WriteString(strings.Repeat("-", tableWidth))
	s.WriteString("\n")

	// Calculate visible range based on height
	visibleHeight := m.height - 10 // Account for header/footer
	if visibleHeight < 5 {
		visibleHeight = 5
	}

	start := 0
	if m.cursor >= visibleHeight {
		start = m.cursor - visibleHeight + 1
	}
	end := start + visibleHeight
	if end > len(m.keys) {
		end = len(m.keys)
	}

	for i := start; i < end; i++ {
		key := m.keys[i]
		value := m.values[key]
		isSelected := i == m.cursor

		s.WriteString("  ")

		// Key column
		if isSelected {
			if m.editingKey {
				// Show key input
				s.WriteString(m.styles.InputFocused.Render(m.keyInput.View()))
			} else {
				s.WriteString(m.styles.KeySelected.Render(padRight(key, 20)))
			}
		} else {
			s.WriteString(m.styles.Key.Render(padRight(key, 20)))
		}

		s.WriteString("  ")

		// Value column
		if isSelected && m.editingValue {
			// Show value input
			s.WriteString(m.styles.InputFocused.Render(m.valueInput.View()))
		} else if m.showValues || !isSensitiveKey(key) {
			displayValue := truncate(value, m.width-30)
			if isSelected {
				s.WriteString(lipgloss.NewStyle().
					Foreground(lipgloss.Color("#FFFFFF")).
					Background(lipgloss.Color("#45475A")).
					Render(displayValue))
			} else {
				s.WriteString(m.styles.Value.Render(displayValue))
			}
		} else {
			// Mask the value
			masked := strings.Repeat("*", min(len(value), 20))
			if isSelected {
				s.WriteString(lipgloss.NewStyle().
					Foreground(lipgloss.Color("#6C7086")).
					Background(lipgloss.Color("#45475A")).
					Render(masked))
			} else {
				s.WriteString(m.styles.ValueMasked.Render(masked))
			}
		}

		s.WriteString("\n")
	}

	// Scroll indicator
	if len(m.keys) > visibleHeight {
		s.WriteString("\n")
		scrollInfo := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Italic(true)
		s.WriteString(scrollInfo.Render("  (scroll: " + string(rune('0'+start+1)) + "-" + string(rune('0'+end)) + " of " + string(rune('0'+len(m.keys))) + ")"))
	}

	return s.String()
}

// renderAddNewForm renders the add new key-value form
func (m EditorModel) renderAddNewForm() string {
	var s strings.Builder

	s.WriteString("  ")
	s.WriteString(m.styles.Title.Render("Add New Key-Value Pair"))
	s.WriteString("\n\n")

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Width(10)

	s.WriteString("  ")
	s.WriteString(labelStyle.Render("Key:"))
	s.WriteString("  ")
	if m.newKey.Focused() {
		s.WriteString(m.styles.InputFocused.Render(m.newKey.View()))
	} else {
		s.WriteString(m.styles.Input.Render(m.newKey.View()))
	}
	s.WriteString("\n\n")

	s.WriteString("  ")
	s.WriteString(labelStyle.Render("Value:"))
	s.WriteString("  ")
	if m.newValue.Focused() {
		s.WriteString(m.styles.InputFocused.Render(m.newValue.View()))
	} else {
		s.WriteString(m.styles.Input.Render(m.newValue.View()))
	}
	s.WriteString("\n\n")

	s.WriteString("  ")
	s.WriteString(m.styles.Help.Render("[Tab] switch field  [Enter] submit  [g] generate password  [Esc] cancel"))

	return s.String()
}

// renderConfirmDialog renders the discard changes confirmation dialog
func (m EditorModel) renderConfirmDialog() string {
	var s strings.Builder

	// Center the modal
	modalWidth := 50
	leftPadding := (m.width - modalWidth) / 2
	if leftPadding < 0 {
		leftPadding = 0
	}

	modal := strings.Builder{}
	modal.WriteString(m.styles.ModalTitle.Render("Discard Changes?"))
	modal.WriteString("\n\n")
	modal.WriteString("You have unsaved changes. Are you sure you\n")
	modal.WriteString("want to discard them?\n\n")

	// Buttons
	var discardBtn, cancelBtn string
	if m.confirmFocus == 0 {
		discardBtn = m.styles.ButtonDanger.Render(" Discard ")
		cancelBtn = m.styles.Button.Render(" Cancel ")
	} else {
		discardBtn = m.styles.Button.Render(" Discard ")
		cancelBtn = m.styles.ButtonFocus.Render(" Cancel ")
	}

	modal.WriteString("  ")
	modal.WriteString(discardBtn)
	modal.WriteString("  ")
	modal.WriteString(cancelBtn)

	// Wrap in modal style
	modalContent := m.styles.Modal.Width(modalWidth).Render(modal.String())

	// Add padding to center
	lines := strings.Split(modalContent, "\n")
	for _, line := range lines {
		s.WriteString(strings.Repeat(" ", leftPadding))
		s.WriteString(line)
		s.WriteString("\n")
	}

	s.WriteString("\n")
	s.WriteString(strings.Repeat(" ", leftPadding))
	s.WriteString(m.styles.Help.Render("[y] discard  [n/Esc] cancel  [Tab] switch"))

	return s.String()
}

// IsModified returns whether there are unsaved changes
func (m *EditorModel) IsModified() bool {
	return m.modified
}

// Path returns the secret path being edited
func (m *EditorModel) Path() string {
	return m.path
}

// Helper functions

func removeString(slice []string, i int) []string {
	if i < 0 || i >= len(slice) {
		return slice
	}
	return append(slice[:i], slice[i+1:]...)
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}

// generatePasswordCmd creates a command to generate a random password
func generatePasswordCmd(length int, policy string) tea.Cmd {
	return func() tea.Msg {
		secret := vault.NewSecret()
		err := secret.Password("temp", length, policy, false)
		if err != nil {
			return EditorErrorMsg{Err: err}
		}
		return GeneratedPasswordMsg{Password: secret.Get("temp")}
	}
}

// Messages

// EditorSecretLoadedMsg is sent when a secret is loaded for editing
type EditorSecretLoadedMsg struct {
	Path   string
	Secret *vault.Secret
}

// EditorErrorMsg is sent when an error occurs in the editor
type EditorErrorMsg struct {
	Err error
}

// EditorSavedMsg is sent when a secret is saved successfully
type EditorSavedMsg struct {
	Path string
}

// EditorSaveErrorMsg is sent when saving a secret fails
type EditorSaveErrorMsg struct {
	Path string
	Err  error
}

// EditorCloseMsg is sent when the editor should close
type EditorCloseMsg struct {
	Saved bool
}

// GeneratedPasswordMsg is sent when a password is generated
type GeneratedPasswordMsg struct {
	Password string
}
