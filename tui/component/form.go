package component

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// FormField represents a single field in a form
type FormField struct {
	Key         string
	Label       string
	Value       string
	Placeholder string
	Sensitive   bool
	Required    bool
	Width       int
	input       textinput.Model
}

// Form is a form component with multiple fields
type Form struct {
	Title      string
	Fields     []FormField
	focusIndex int
	submitted  bool
	cancelled  bool
	width      int
	height     int
	keys       formKeyMap
}

type formKeyMap struct {
	Next   key.Binding
	Prev   key.Binding
	Submit key.Binding
	Cancel key.Binding
	Toggle key.Binding
}

func defaultFormKeyMap() formKeyMap {
	return formKeyMap{
		Next: key.NewBinding(
			key.WithKeys("tab", "down"),
			key.WithHelp("tab/↓", "next field"),
		),
		Prev: key.NewBinding(
			key.WithKeys("shift+tab", "up"),
			key.WithHelp("shift+tab/↑", "prev field"),
		),
		Submit: key.NewBinding(
			key.WithKeys("ctrl+s"),
			key.WithHelp("ctrl+s", "submit"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "cancel"),
		),
		Toggle: key.NewBinding(
			key.WithKeys("ctrl+v"),
			key.WithHelp("ctrl+v", "toggle visibility"),
		),
	}
}

// NewForm creates a new form
func NewForm(title string, fields []FormField) Form {
	// Initialize text inputs for each field
	for i := range fields {
		ti := textinput.New()
		ti.Placeholder = fields[i].Placeholder
		ti.SetValue(fields[i].Value)
		ti.Width = 40

		if fields[i].Width > 0 {
			ti.Width = fields[i].Width
		}

		if fields[i].Sensitive {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
		}

		if i == 0 {
			ti.Focus()
		}

		fields[i].input = ti
	}

	return Form{
		Title:  title,
		Fields: fields,
		keys:   defaultFormKeyMap(),
	}
}

// Init initializes the form
func (f Form) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages
func (f Form) Update(msg tea.Msg) (Form, tea.Cmd) {
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
			return f, func() tea.Msg { return FormCancelledMsg{} }

		case key.Matches(msg, f.keys.Submit):
			if f.validate() {
				f.submitted = true
				return f, func() tea.Msg {
					return FormSubmittedMsg{Values: f.Values()}
				}
			}

		case key.Matches(msg, f.keys.Next):
			f.focusNext()

		case key.Matches(msg, f.keys.Prev):
			f.focusPrev()

		case key.Matches(msg, f.keys.Toggle):
			// Toggle visibility of current field if sensitive
			if f.Fields[f.focusIndex].Sensitive {
				field := &f.Fields[f.focusIndex]
				if field.input.EchoMode == textinput.EchoPassword {
					field.input.EchoMode = textinput.EchoNormal
				} else {
					field.input.EchoMode = textinput.EchoPassword
				}
			}
		}
	}

	// Update the focused input
	if f.focusIndex < len(f.Fields) {
		var cmd tea.Cmd
		f.Fields[f.focusIndex].input, cmd = f.Fields[f.focusIndex].input.Update(msg)
		cmds = append(cmds, cmd)
	}

	return f, tea.Batch(cmds...)
}

// View renders the form
func (f Form) View() string {
	var s strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true).
		MarginBottom(1)

	s.WriteString(titleStyle.Render(f.Title))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 40))
	s.WriteString("\n\n")

	// Fields
	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Width(12)

	focusedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0"))

	for i, field := range f.Fields {
		// Label
		label := labelStyle.Render(field.Label)

		// Required indicator
		if field.Required {
			label += " *"
		}

		s.WriteString(label)
		s.WriteString(" ")

		// Input
		if i == f.focusIndex {
			s.WriteString(focusedStyle.Render(field.input.View()))
		} else {
			s.WriteString(field.input.View())
		}
		s.WriteString("\n\n")
	}

	// Help
	s.WriteString("\n")
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	hints := "[Tab] next  [Shift+Tab] prev  [Ctrl+S] submit  [Esc] cancel"
	if f.hasSensitiveField() {
		hints += "  [Ctrl+V] toggle password"
	}
	s.WriteString(hintStyle.Render(hints))

	return s.String()
}

// focusNext moves focus to the next field
func (f *Form) focusNext() {
	f.Fields[f.focusIndex].input.Blur()
	f.focusIndex = (f.focusIndex + 1) % len(f.Fields)
	f.Fields[f.focusIndex].input.Focus()
}

// focusPrev moves focus to the previous field
func (f *Form) focusPrev() {
	f.Fields[f.focusIndex].input.Blur()
	f.focusIndex--
	if f.focusIndex < 0 {
		f.focusIndex = len(f.Fields) - 1
	}
	f.Fields[f.focusIndex].input.Focus()
}

// validate checks if all required fields are filled
func (f *Form) validate() bool {
	for _, field := range f.Fields {
		if field.Required && strings.TrimSpace(field.input.Value()) == "" {
			return false
		}
	}
	return true
}

// hasSensitiveField checks if any field is sensitive
func (f *Form) hasSensitiveField() bool {
	for _, field := range f.Fields {
		if field.Sensitive {
			return true
		}
	}
	return false
}

// Values returns the current values of all fields
func (f *Form) Values() map[string]string {
	values := make(map[string]string)
	for _, field := range f.Fields {
		values[field.Key] = field.input.Value()
	}
	return values
}

// GetValue returns the value of a specific field
func (f *Form) GetValue(key string) string {
	for _, field := range f.Fields {
		if field.Key == key {
			return field.input.Value()
		}
	}
	return ""
}

// SetValue sets the value of a specific field
func (f *Form) SetValue(key, value string) {
	for i, field := range f.Fields {
		if field.Key == key {
			f.Fields[i].input.SetValue(value)
			return
		}
	}
}

// IsSubmitted returns true if the form was submitted
func (f *Form) IsSubmitted() bool {
	return f.submitted
}

// IsCancelled returns true if the form was cancelled
func (f *Form) IsCancelled() bool {
	return f.cancelled
}

// Messages

// FormSubmittedMsg is sent when a form is submitted
type FormSubmittedMsg struct {
	Values map[string]string
}

// FormCancelledMsg is sent when a form is cancelled
type FormCancelledMsg struct{}
