package component

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sahilm/fuzzy"
)

// CommandCategory represents a category of commands
type CommandCategory string

const (
	CategoryNavigation CommandCategory = "Navigation"
	CategorySecrets    CommandCategory = "Secrets"
	CategoryGenerate   CommandCategory = "Generate"
	CategoryX509       CommandCategory = "X.509"
	CategoryAdmin      CommandCategory = "Admin"
	CategoryUtility    CommandCategory = "Utility"
)

// Command represents a command in the palette
type Command struct {
	ID          string
	Name        string
	Description string
	Shortcut    string
	Category    CommandCategory
	Action      string // Action identifier for execution
}

// CommandList implements fuzzy.Source for fuzzy matching
type CommandList []Command

func (cl CommandList) String(i int) string {
	return cl[i].Name + " " + cl[i].Description
}

func (cl CommandList) Len() int {
	return len(cl)
}

// Palette is a command palette component
type Palette struct {
	input      textinput.Model
	commands   CommandList
	filtered   []fuzzy.Match
	cursor     int
	width      int
	height     int
	maxVisible int
	offset     int
	keys       paletteKeyMap
	styles     PaletteStyles
}

type paletteKeyMap struct {
	Up       key.Binding
	Down     key.Binding
	Select   key.Binding
	Cancel   key.Binding
	PageUp   key.Binding
	PageDown key.Binding
}

// PaletteStyles contains styles for the palette
type PaletteStyles struct {
	Container      lipgloss.Style
	Input          lipgloss.Style
	InputPrompt    lipgloss.Style
	Item           lipgloss.Style
	ItemSelected   lipgloss.Style
	ItemName       lipgloss.Style
	ItemDesc       lipgloss.Style
	ItemShortcut   lipgloss.Style
	MatchHighlight lipgloss.Style
	Category       lipgloss.Style
	NoResults      lipgloss.Style
	Overlay        lipgloss.Style
}

// DefaultPaletteStyles returns default palette styles
func DefaultPaletteStyles() PaletteStyles {
	return PaletteStyles{
		Container: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7C6FE0")).
			Background(lipgloss.Color("#1E1E2E")).
			Padding(1, 2).
			Width(60),

		Input: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#1E1E2E")),

		InputPrompt: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Background(lipgloss.Color("#1E1E2E")).
			Bold(true),

		Item: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#1E1E2E")).
			Padding(0, 1),

		ItemSelected: lipgloss.NewStyle().
			Background(lipgloss.Color("#7C6FE0")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true).
			Padding(0, 1),

		ItemName: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")).
			Background(lipgloss.Color("#1E1E2E")),

		ItemDesc: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Background(lipgloss.Color("#1E1E2E")).
			Italic(true),

		ItemShortcut: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Background(lipgloss.Color("#1E1E2E")).
			Align(lipgloss.Right),

		MatchHighlight: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Background(lipgloss.Color("#1E1E2E")).
			Bold(true),

		Category: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6ADC8")).
			Background(lipgloss.Color("#1E1E2E")).
			Bold(true).
			MarginTop(1),

		NoResults: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Background(lipgloss.Color("#1E1E2E")).
			Italic(true).
			Padding(1, 0),

		Overlay: lipgloss.NewStyle().
			Background(lipgloss.Color("#000000")),
	}
}

func defaultPaletteKeyMap() paletteKeyMap {
	return paletteKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "ctrl+k", "ctrl+p"),
			key.WithHelp("up/ctrl+k", "previous"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "ctrl+j", "ctrl+n"),
			key.WithHelp("down/ctrl+j", "next"),
		),
		Select: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("esc", "ctrl+c"),
			key.WithHelp("esc", "cancel"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("pgup", "ctrl+u"),
			key.WithHelp("pgup", "page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("pgdown", "ctrl+d"),
			key.WithHelp("pgdown", "page down"),
		),
	}
}

// AllCommands returns all available commands for the Safe TUI
func AllCommands() CommandList {
	return CommandList{
		// Navigation commands
		{ID: "nav.switch_target", Name: "Switch Target", Description: "Switch to a different Vault target", Shortcut: "Esc", Category: CategoryNavigation, Action: "switch_target"},
		{ID: "nav.goto_path", Name: "Go to Path", Description: "Navigate to a specific path", Shortcut: "g /", Category: CategoryNavigation, Action: "goto_path"},
		{ID: "nav.refresh", Name: "Refresh", Description: "Refresh current view", Shortcut: "r", Category: CategoryNavigation, Action: "refresh"},
		{ID: "nav.back", Name: "Go Back", Description: "Return to previous view", Shortcut: "Esc", Category: CategoryNavigation, Action: "back"},
		{ID: "nav.parent", Name: "Go to Parent", Description: "Navigate to parent directory", Shortcut: "-", Category: CategoryNavigation, Action: "parent"},

		// Secret operations
		{ID: "secret.get", Name: "Get Secret", Description: "Read a secret value", Shortcut: "Enter", Category: CategorySecrets, Action: "get"},
		{ID: "secret.set", Name: "Set Secret", Description: "Write a secret value", Shortcut: "s", Category: CategorySecrets, Action: "set"},
		{ID: "secret.edit", Name: "Edit Secret", Description: "Edit secret in editor", Shortcut: "e", Category: CategorySecrets, Action: "edit"},
		{ID: "secret.delete", Name: "Delete Secret", Description: "Delete a secret", Shortcut: "d", Category: CategorySecrets, Action: "delete"},
		{ID: "secret.copy", Name: "Copy Secret", Description: "Copy secret to clipboard", Shortcut: "y", Category: CategorySecrets, Action: "copy"},
		{ID: "secret.copy_path", Name: "Copy Path", Description: "Copy secret path to clipboard", Shortcut: "c", Category: CategorySecrets, Action: "copy_path"},
		{ID: "secret.move", Name: "Move Secret", Description: "Move/rename a secret", Shortcut: "m", Category: CategorySecrets, Action: "move"},
		{ID: "secret.paste", Name: "Paste Secret", Description: "Paste secret from clipboard", Shortcut: "p", Category: CategorySecrets, Action: "paste"},
		{ID: "secret.new", Name: "New Secret", Description: "Create a new secret", Shortcut: "a", Category: CategorySecrets, Action: "new"},
		{ID: "secret.versions", Name: "Secret Versions", Description: "View secret version history", Shortcut: "", Category: CategorySecrets, Action: "versions"},
		{ID: "secret.diff", Name: "Diff Secrets", Description: "Compare two secrets", Shortcut: "", Category: CategorySecrets, Action: "diff"},

		// Generate commands
		{ID: "gen.password", Name: "Generate Password", Description: "Generate a random password", Shortcut: "g p", Category: CategoryGenerate, Action: "gen_password"},
		{ID: "gen.ssh", Name: "Generate SSH Key", Description: "Generate SSH keypair", Shortcut: "g s", Category: CategoryGenerate, Action: "gen_ssh"},
		{ID: "gen.rsa", Name: "Generate RSA Key", Description: "Generate RSA keypair", Shortcut: "g r", Category: CategoryGenerate, Action: "gen_rsa"},
		{ID: "gen.ec", Name: "Generate EC Key", Description: "Generate EC keypair", Shortcut: "g e", Category: CategoryGenerate, Action: "gen_ec"},
		{ID: "gen.dh", Name: "Generate DH Params", Description: "Generate Diffie-Hellman parameters", Shortcut: "g d", Category: CategoryGenerate, Action: "gen_dh"},
		{ID: "gen.uuid", Name: "Generate UUID", Description: "Generate a UUID", Shortcut: "g u", Category: CategoryGenerate, Action: "gen_uuid"},
		{ID: "gen.random", Name: "Generate Random", Description: "Generate random bytes", Shortcut: "", Category: CategoryGenerate, Action: "gen_random"},
		{ID: "gen.fmt", Name: "Format Secret", Description: "Format secret from template", Shortcut: "", Category: CategoryGenerate, Action: "gen_fmt"},

		// X.509 commands
		{ID: "x509.issue", Name: "Issue Certificate", Description: "Issue a new X.509 certificate", Shortcut: "", Category: CategoryX509, Action: "x509_issue"},
		{ID: "x509.revoke", Name: "Revoke Certificate", Description: "Revoke an X.509 certificate", Shortcut: "", Category: CategoryX509, Action: "x509_revoke"},
		{ID: "x509.show", Name: "Show Certificate", Description: "Display certificate details", Shortcut: "", Category: CategoryX509, Action: "x509_show"},
		{ID: "x509.renew", Name: "Renew Certificate", Description: "Renew an X.509 certificate", Shortcut: "", Category: CategoryX509, Action: "x509_renew"},
		{ID: "x509.validate", Name: "Validate Certificate", Description: "Validate a certificate", Shortcut: "", Category: CategoryX509, Action: "x509_validate"},
		{ID: "x509.crl", Name: "Show CRL", Description: "Show Certificate Revocation List", Shortcut: "", Category: CategoryX509, Action: "x509_crl"},
		{ID: "x509.ca.init", Name: "Initialize CA", Description: "Initialize a new Certificate Authority", Shortcut: "", Category: CategoryX509, Action: "x509_ca_init"},
		{ID: "x509.sign", Name: "Sign CSR", Description: "Sign a Certificate Signing Request", Shortcut: "", Category: CategoryX509, Action: "x509_sign"},

		// Admin commands
		{ID: "admin.init", Name: "Init Vault", Description: "Initialize a new Vault", Shortcut: "", Category: CategoryAdmin, Action: "init"},
		{ID: "admin.seal", Name: "Seal Vault", Description: "Seal the Vault", Shortcut: "", Category: CategoryAdmin, Action: "seal"},
		{ID: "admin.unseal", Name: "Unseal Vault", Description: "Unseal the Vault", Shortcut: "", Category: CategoryAdmin, Action: "unseal"},
		{ID: "admin.rekey", Name: "Rekey Vault", Description: "Rekey the Vault", Shortcut: "", Category: CategoryAdmin, Action: "rekey"},
		{ID: "admin.status", Name: "Vault Status", Description: "Show Vault status", Shortcut: "", Category: CategoryAdmin, Action: "status"},
		{ID: "admin.auth", Name: "Authenticate", Description: "Authenticate to Vault", Shortcut: "", Category: CategoryAdmin, Action: "auth"},
		{ID: "admin.token", Name: "Token Info", Description: "Show current token info", Shortcut: "", Category: CategoryAdmin, Action: "token"},
		{ID: "admin.renew", Name: "Renew Token", Description: "Renew authentication token", Shortcut: "", Category: CategoryAdmin, Action: "renew"},
		{ID: "admin.policy.list", Name: "List Policies", Description: "List all policies", Shortcut: "", Category: CategoryAdmin, Action: "policy_list"},
		{ID: "admin.policy.show", Name: "Show Policy", Description: "Show policy details", Shortcut: "", Category: CategoryAdmin, Action: "policy_show"},
		{ID: "admin.mount", Name: "List Mounts", Description: "List secret backends", Shortcut: "", Category: CategoryAdmin, Action: "mount"},
		{ID: "admin.target.add", Name: "Add Target", Description: "Add a new Vault target", Shortcut: "", Category: CategoryAdmin, Action: "target_add"},
		{ID: "admin.target.delete", Name: "Delete Target", Description: "Delete a Vault target", Shortcut: "", Category: CategoryAdmin, Action: "target_delete"},

		// Utility commands
		{ID: "util.export", Name: "Export Secrets", Description: "Export secrets to file", Shortcut: "", Category: CategoryUtility, Action: "export"},
		{ID: "util.import", Name: "Import Secrets", Description: "Import secrets from file", Shortcut: "", Category: CategoryUtility, Action: "import"},
		{ID: "util.tree", Name: "Tree View", Description: "Show secrets as tree", Shortcut: "", Category: CategoryUtility, Action: "tree"},
		{ID: "util.paths", Name: "List Paths", Description: "List all paths", Shortcut: "", Category: CategoryUtility, Action: "paths"},
		{ID: "util.env", Name: "Export to Env", Description: "Export secrets as environment variables", Shortcut: "", Category: CategoryUtility, Action: "env"},
		{ID: "util.curl", Name: "Curl Command", Description: "Generate curl command for API", Shortcut: "", Category: CategoryUtility, Action: "curl"},
		{ID: "util.exists", Name: "Check Exists", Description: "Check if path exists", Shortcut: "", Category: CategoryUtility, Action: "exists"},
		{ID: "util.local", Name: "Local Vault", Description: "Work with local Vault files", Shortcut: "", Category: CategoryUtility, Action: "local"},
		{ID: "util.prompt", Name: "Prompt for Value", Description: "Prompt for secret value interactively", Shortcut: "", Category: CategoryUtility, Action: "prompt"},
		{ID: "util.vault", Name: "Vault Subcommand", Description: "Execute Vault CLI command", Shortcut: "", Category: CategoryUtility, Action: "vault"},

		// TUI-specific commands
		{ID: "tui.help", Name: "Show Help", Description: "Display help information", Shortcut: "?", Category: CategoryUtility, Action: "help"},
		{ID: "tui.quit", Name: "Quit", Description: "Exit the TUI", Shortcut: "q", Category: CategoryUtility, Action: "quit"},
		{ID: "tui.toggle_values", Name: "Toggle Values", Description: "Show/hide secret values", Shortcut: "Ctrl+V", Category: CategoryUtility, Action: "toggle_values"},
		{ID: "tui.toggle_split", Name: "Toggle Split", Description: "Toggle split view", Shortcut: "v", Category: CategoryUtility, Action: "toggle_split"},
		{ID: "tui.new_tab", Name: "New Tab", Description: "Open a new tab", Shortcut: "Ctrl+T", Category: CategoryUtility, Action: "new_tab"},
		{ID: "tui.close_tab", Name: "Close Tab", Description: "Close current tab", Shortcut: "Ctrl+W", Category: CategoryUtility, Action: "close_tab"},
		{ID: "tui.search", Name: "Search", Description: "Search for secrets", Shortcut: "/", Category: CategoryUtility, Action: "search"},
	}
}

// NewPalette creates a new command palette
func NewPalette() Palette {
	ti := textinput.New()
	ti.Placeholder = "Type to search commands..."
	ti.Focus()
	ti.CharLimit = 100
	ti.Width = 50

	commands := AllCommands()

	p := Palette{
		input:      ti,
		commands:   commands,
		maxVisible: 10,
		keys:       defaultPaletteKeyMap(),
		styles:     DefaultPaletteStyles(),
		width:      80, // Default until SetSize called
		height:     24,
	}

	// Initialize with all commands
	p.updateFilter("")

	return p
}

// Init initializes the palette
func (p Palette) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages
func (p Palette) Update(msg tea.Msg) (Palette, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.MouseMsg:
		return p.handleMouse(msg)

	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.height = msg.Height
		// Adjust max visible based on height
		p.maxVisible = min(15, (msg.Height-10)/2)
		if p.maxVisible < 5 {
			p.maxVisible = 5
		}

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, p.keys.Cancel):
			return p, func() tea.Msg {
				return PaletteCloseMsg{}
			}

		case key.Matches(msg, p.keys.Select):
			if len(p.filtered) > 0 && p.cursor < len(p.filtered) {
				cmd := p.commands[p.filtered[p.cursor].Index]
				return p, func() tea.Msg {
					return CommandSelectedMsg{
						CommandID: cmd.ID,
						Action:    cmd.Action,
					}
				}
			}

		case key.Matches(msg, p.keys.Up):
			p.moveUp()
			return p, nil

		case key.Matches(msg, p.keys.Down):
			p.moveDown()
			return p, nil

		case key.Matches(msg, p.keys.PageUp):
			p.pageUp()
			return p, nil

		case key.Matches(msg, p.keys.PageDown):
			p.pageDown()
			return p, nil
		}
	}

	// Update text input
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(msg)
	cmds = append(cmds, cmd)

	// Update filter when input changes
	p.updateFilter(p.input.Value())

	return p, tea.Batch(cmds...)
}

// updateFilter updates the filtered command list based on the query
func (p *Palette) updateFilter(query string) {
	if query == "" {
		// Show all commands when no query
		p.filtered = make([]fuzzy.Match, len(p.commands))
		for i := range p.commands {
			p.filtered[i] = fuzzy.Match{Index: i}
		}
	} else {
		// Fuzzy match
		p.filtered = fuzzy.FindFrom(query, p.commands)
	}

	// Reset cursor
	p.cursor = 0
	p.offset = 0
}

// moveUp moves the cursor up
func (p *Palette) moveUp() {
	if p.cursor > 0 {
		p.cursor--
		p.ensureVisible()
	}
}

// moveDown moves the cursor down
func (p *Palette) moveDown() {
	if p.cursor < len(p.filtered)-1 {
		p.cursor++
		p.ensureVisible()
	}
}

// pageUp moves up by half a page
func (p *Palette) pageUp() {
	p.cursor -= p.maxVisible / 2
	if p.cursor < 0 {
		p.cursor = 0
	}
	p.ensureVisible()
}

// pageDown moves down by half a page
func (p *Palette) pageDown() {
	p.cursor += p.maxVisible / 2
	if p.cursor >= len(p.filtered) {
		p.cursor = len(p.filtered) - 1
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
	p.ensureVisible()
}

// ensureVisible ensures the cursor is within the visible area
func (p *Palette) ensureVisible() {
	if p.cursor < p.offset {
		p.offset = p.cursor
	}
	if p.cursor >= p.offset+p.maxVisible {
		p.offset = p.cursor - p.maxVisible + 1
	}
	if p.offset < 0 {
		p.offset = 0
	}
}

// handleMouse handles mouse events for the palette
func (p Palette) handleMouse(msg tea.MouseMsg) (Palette, tea.Cmd) {
	switch msg.Type {
	case tea.MouseLeft:
		// The palette has:
		// - Line 0: input prompt "> "
		// - Line 1: separator "───"
		// - Lines 2+: command items (or category headers when not filtering)
		// We need to map click Y to the correct item index

		// Skip if clicking on input or separator
		headerLines := 2
		if msg.Y < headerLines {
			return p, nil
		}

		// Calculate which item was clicked
		// Account for the palette's position in the viewport
		relativeY := msg.Y - headerLines
		clickedIndex := p.offset + relativeY

		// When not filtering (query == ""), category headers take up space
		// For simplicity, we'll handle the filtered case directly
		if clickedIndex >= 0 && clickedIndex < len(p.filtered) {
			p.cursor = clickedIndex
			p.ensureVisible()

			// Double-click behavior could select immediately
			// For now, single click just moves cursor
		}

	case tea.MouseWheelUp:
		p.moveUp()
		p.moveUp()
		p.moveUp()

	case tea.MouseWheelDown:
		p.moveDown()
		p.moveDown()
		p.moveDown()
	}

	return p, nil
}

// View renders the palette
func (p Palette) View() string {
	var s strings.Builder

	// Input prompt
	prompt := p.styles.InputPrompt.Render("> ")
	s.WriteString(prompt)
	s.WriteString(p.input.View())
	s.WriteString("\n")

	// Separator
	s.WriteString(strings.Repeat("─", 56))
	s.WriteString("\n")

	// No results
	if len(p.filtered) == 0 {
		s.WriteString(p.styles.NoResults.Render("  No matching commands"))
		s.WriteString("\n")
	} else {
		// Commands list
		visibleCount := p.maxVisible
		if visibleCount > len(p.filtered) {
			visibleCount = len(p.filtered)
		}

		end := p.offset + visibleCount
		if end > len(p.filtered) {
			end = len(p.filtered)
		}

		lastCategory := CommandCategory("")
		query := p.input.Value()

		for i := p.offset; i < end; i++ {
			match := p.filtered[i]
			cmd := p.commands[match.Index]

			// Category header (only show when grouped and not searching)
			if query == "" && cmd.Category != lastCategory {
				if lastCategory != "" {
					s.WriteString("\n")
				}
				s.WriteString(p.styles.Category.Render(string(cmd.Category)))
				s.WriteString("\n")
				lastCategory = cmd.Category
			}

			// Command item
			isSelected := i == p.cursor
			line := p.renderCommand(cmd, match, isSelected, query)
			s.WriteString(line)
			s.WriteString("\n")
		}

		// Scroll indicator
		if len(p.filtered) > p.maxVisible {
			scrollInfo := lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6C7086")).
				Render(strings.Repeat(" ", 40) +
					"[" + string(rune('0'+p.cursor+1)) + "/" +
					string(rune('0'+len(p.filtered))) + "]")
			if len(p.filtered) > 9 || p.cursor > 8 {
				// Use proper number formatting for larger numbers
				scrollInfo = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#6C7086")).
					Render(formatScrollIndicator(p.cursor+1, len(p.filtered)))
			}
			s.WriteString(scrollInfo)
			s.WriteString("\n")
		}
	}

	// Wrap in container
	content := s.String()
	return p.styles.Container.Render(content)
}

// renderCommand renders a single command item
func (p *Palette) renderCommand(cmd Command, match fuzzy.Match, isSelected bool, query string) string {
	var s strings.Builder

	// Selection indicator
	if isSelected {
		s.WriteString(p.styles.ItemSelected.Render("  "))
	} else {
		s.WriteString("    ")
	}

	// Command name with highlighting
	_ = cmd.Name // nameStr will be used via highlightMatches

	// Calculate widths for alignment
	nameWidth := 25
	shortcutWidth := 12

	// Render based on selection
	if isSelected {
		// Pad name to fixed width
		name := cmd.Name
		if len(name) > nameWidth {
			name = name[:nameWidth-1] + "."
		}
		for len(name) < nameWidth {
			name += " "
		}

		// Shortcut
		shortcut := ""
		if cmd.Shortcut != "" {
			shortcut = "[" + cmd.Shortcut + "]"
		}
		for len(shortcut) < shortcutWidth {
			shortcut = " " + shortcut
		}

		line := name + shortcut
		s.WriteString(p.styles.ItemSelected.Render(line))
	} else {
		// Name (possibly highlighted)
		if query != "" && len(match.MatchedIndexes) > 0 {
			s.WriteString(p.renderHighlightedName(cmd.Name, match.MatchedIndexes, nameWidth))
		} else {
			name := cmd.Name
			if len(name) > nameWidth {
				name = name[:nameWidth-1] + "."
			}
			for len(name) < nameWidth {
				name += " "
			}
			s.WriteString(p.styles.ItemName.Render(name))
		}

		// Shortcut
		shortcut := ""
		if cmd.Shortcut != "" {
			shortcut = "[" + cmd.Shortcut + "]"
		}
		for len(shortcut) < shortcutWidth {
			shortcut = " " + shortcut
		}
		s.WriteString(p.styles.ItemShortcut.Render(shortcut))
	}

	return s.String()
}

// highlightMatches highlights matched characters in a string
func (p *Palette) highlightMatches(s string, matchedIndexes []int) string {
	if len(matchedIndexes) == 0 {
		return s
	}

	// Create a map of matched indexes
	matchSet := make(map[int]bool)
	for _, idx := range matchedIndexes {
		if idx < len(s) {
			matchSet[idx] = true
		}
	}

	var result strings.Builder
	for i, char := range s {
		if matchSet[i] {
			result.WriteString(p.styles.MatchHighlight.Render(string(char)))
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// renderHighlightedName renders a name with match highlighting
func (p *Palette) renderHighlightedName(name string, matchedIndexes []int, maxWidth int) string {
	if len(name) > maxWidth {
		name = name[:maxWidth-1] + "."
	}

	// Create a map of matched indexes
	matchSet := make(map[int]bool)
	for _, idx := range matchedIndexes {
		if idx < len(name) {
			matchSet[idx] = true
		}
	}

	var result strings.Builder
	for i, char := range name {
		if matchSet[i] {
			result.WriteString(p.styles.MatchHighlight.Render(string(char)))
		} else {
			result.WriteString(p.styles.ItemName.Render(string(char)))
		}
	}

	// Pad to width
	currentLen := len(name)
	for currentLen < maxWidth {
		result.WriteString(" ")
		currentLen++
	}

	return result.String()
}

// formatScrollIndicator formats the scroll position indicator
func formatScrollIndicator(current, total int) string {
	return strings.Repeat(" ", 35) + "[" + intToStr(current) + "/" + intToStr(total) + "]"
}

// intToStr converts an int to string without fmt
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// Focus focuses the palette input
func (p *Palette) Focus() tea.Cmd {
	return p.input.Focus()
}

// Blur blurs the palette input
func (p *Palette) Blur() {
	p.input.Blur()
}

// Reset resets the palette state
func (p *Palette) Reset() {
	p.input.SetValue("")
	p.cursor = 0
	p.offset = 0
	p.updateFilter("")
}

// SetWidth sets the palette width
func (p *Palette) SetWidth(width int) {
	p.width = width
	p.input.Width = width - 10
	p.styles.Container = p.styles.Container.Width(width - 4)
}

// SetHeight sets the palette height
func (p *Palette) SetHeight(height int) {
	p.height = height
	p.maxVisible = min(15, (height-10)/2)
	if p.maxVisible < 5 {
		p.maxVisible = 5
	}
}

// SelectedCommand returns the currently selected command
func (p *Palette) SelectedCommand() *Command {
	if len(p.filtered) > 0 && p.cursor < len(p.filtered) {
		return &p.commands[p.filtered[p.cursor].Index]
	}
	return nil
}

// Messages

// PaletteCloseMsg is sent when the palette should be closed
type PaletteCloseMsg struct{}

// CommandSelectedMsg is sent when a command is selected
type CommandSelectedMsg struct {
	CommandID string
	Action    string
}

// PaletteOpenMsg is sent when the palette should be opened
type PaletteOpenMsg struct{}

// ViewWithOverlay renders the palette with a semi-transparent overlay
func (p Palette) ViewWithOverlay(width, height int) string {
	// Create the palette view
	paletteView := p.View()

	// Calculate centering
	paletteWidth := 60
	paletteHeight := strings.Count(paletteView, "\n") + 1

	// Calculate position (centered)
	left := (width - paletteWidth) / 2
	top := (height - paletteHeight) / 3 // Position in upper third

	if left < 0 {
		left = 0
	}
	if top < 0 {
		top = 0
	}

	// Build overlay with palette positioned
	var s strings.Builder

	// Add top padding
	for i := 0; i < top; i++ {
		s.WriteString(strings.Repeat(" ", width))
		s.WriteString("\n")
	}

	// Add palette with left padding
	lines := strings.Split(paletteView, "\n")
	for _, line := range lines {
		s.WriteString(strings.Repeat(" ", left))
		s.WriteString(line)
		remaining := width - left - lipgloss.Width(line)
		if remaining > 0 {
			s.WriteString(strings.Repeat(" ", remaining))
		}
		s.WriteString("\n")
	}

	return s.String()
}
