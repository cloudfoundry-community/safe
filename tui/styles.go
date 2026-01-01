package tui

import "github.com/charmbracelet/lipgloss"

// Colors defines the color palette for the TUI
var Colors = struct {
	// Primary colors
	Primary   lipgloss.AdaptiveColor
	Secondary lipgloss.AdaptiveColor

	// Status colors
	Success lipgloss.AdaptiveColor
	Warning lipgloss.AdaptiveColor
	Error   lipgloss.AdaptiveColor
	Info    lipgloss.AdaptiveColor

	// Surface colors
	Background lipgloss.AdaptiveColor
	Surface    lipgloss.AdaptiveColor
	SurfaceAlt lipgloss.AdaptiveColor
	Border     lipgloss.AdaptiveColor

	// Text colors
	TextPrimary   lipgloss.AdaptiveColor
	TextSecondary lipgloss.AdaptiveColor
	TextMuted     lipgloss.AdaptiveColor

	// Semantic colors
	Directory lipgloss.AdaptiveColor
	Secret    lipgloss.AdaptiveColor
	Key       lipgloss.AdaptiveColor
}{
	Primary:   lipgloss.AdaptiveColor{Light: "#5A4FCF", Dark: "#7C6FE0"},
	Secondary: lipgloss.AdaptiveColor{Light: "#6B4FCF", Dark: "#8E7CFF"},

	Success: lipgloss.AdaptiveColor{Light: "#2E7D32", Dark: "#4CAF50"},
	Warning: lipgloss.AdaptiveColor{Light: "#F57C00", Dark: "#FFB74D"},
	Error:   lipgloss.AdaptiveColor{Light: "#C62828", Dark: "#EF5350"},
	Info:    lipgloss.AdaptiveColor{Light: "#1565C0", Dark: "#42A5F5"},

	Background: lipgloss.AdaptiveColor{Light: "#FAFAFA", Dark: "#1E1E2E"},
	Surface:    lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#282A36"},
	SurfaceAlt: lipgloss.AdaptiveColor{Light: "#F5F5F5", Dark: "#313244"},
	Border:     lipgloss.AdaptiveColor{Light: "#E0E0E0", Dark: "#45475A"},

	TextPrimary:   lipgloss.AdaptiveColor{Light: "#212121", Dark: "#CDD6F4"},
	TextSecondary: lipgloss.AdaptiveColor{Light: "#757575", Dark: "#A6ADC8"},
	TextMuted:     lipgloss.AdaptiveColor{Light: "#9E9E9E", Dark: "#6C7086"},

	Directory: lipgloss.AdaptiveColor{Light: "#1565C0", Dark: "#89B4FA"},
	Secret:    lipgloss.AdaptiveColor{Light: "#2E7D32", Dark: "#A6E3A1"},
	Key:       lipgloss.AdaptiveColor{Light: "#F57C00", Dark: "#F9E2AF"},
}

// Styles contains all style definitions for the TUI
var Styles = struct {
	// App-level styles
	App lipgloss.Style

	// Status bar
	StatusBar           lipgloss.Style
	StatusBarItem       lipgloss.Style
	StatusAuthenticated lipgloss.Style
	StatusError         lipgloss.Style
	StatusWarning       lipgloss.Style

	// Tab bar
	TabBar      lipgloss.Style
	TabActive   lipgloss.Style
	TabInactive lipgloss.Style
	TabModified lipgloss.Style

	// Tree browser
	TreePane      lipgloss.Style
	TreeNode      lipgloss.Style
	TreeDirectory lipgloss.Style
	TreeSecret    lipgloss.Style
	TreeKey       lipgloss.Style
	TreeSelected  lipgloss.Style
	TreeExpanded  lipgloss.Style
	TreeCollapsed lipgloss.Style

	// Secret view
	SecretPane   lipgloss.Style
	SecretKey    lipgloss.Style
	SecretValue  lipgloss.Style
	SecretMasked lipgloss.Style

	// Forms
	FormLabel        lipgloss.Style
	FormInput        lipgloss.Style
	FormInputFocused lipgloss.Style
	FormError        lipgloss.Style

	// Modal
	Modal        lipgloss.Style
	ModalTitle   lipgloss.Style
	ModalContent lipgloss.Style

	// Command palette
	Palette         lipgloss.Style
	PaletteItem     lipgloss.Style
	PaletteMatch    lipgloss.Style
	PaletteSelected lipgloss.Style

	// Buttons
	Button        lipgloss.Style
	ButtonFocused lipgloss.Style
	ButtonDanger  lipgloss.Style

	// Help
	HelpKey  lipgloss.Style
	HelpDesc lipgloss.Style

	// Title/Header
	Title   lipgloss.Style
	Header  lipgloss.Style
	Divider lipgloss.Style
}{
	App: lipgloss.NewStyle(),

	StatusBar: lipgloss.NewStyle().
		Background(Colors.SurfaceAlt).
		Foreground(Colors.TextSecondary).
		Padding(0, 1),

	StatusBarItem: lipgloss.NewStyle().
		Padding(0, 1),

	StatusAuthenticated: lipgloss.NewStyle().
		Foreground(Colors.Success).
		Bold(true),

	StatusError: lipgloss.NewStyle().
		Foreground(Colors.Error).
		Bold(true),

	StatusWarning: lipgloss.NewStyle().
		Foreground(Colors.Warning),

	TabBar: lipgloss.NewStyle().
		Background(Colors.Surface).
		Padding(0, 1).
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		BorderForeground(Colors.Border),

	TabActive: lipgloss.NewStyle().
		Foreground(Colors.Primary).
		Background(Colors.SurfaceAlt).
		Bold(true).
		Padding(0, 2),

	TabInactive: lipgloss.NewStyle().
		Foreground(Colors.TextSecondary).
		Padding(0, 2),

	TabModified: lipgloss.NewStyle().
		Foreground(Colors.Warning).
		Bold(true).
		Padding(0, 2),

	TreePane: lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Border).
		Padding(0, 1),

	TreeNode: lipgloss.NewStyle().
		Foreground(Colors.TextPrimary),

	TreeDirectory: lipgloss.NewStyle().
		Foreground(Colors.Directory).
		Bold(true),

	TreeSecret: lipgloss.NewStyle().
		Foreground(Colors.Secret),

	TreeKey: lipgloss.NewStyle().
		Foreground(Colors.Key),

	TreeSelected: lipgloss.NewStyle().
		Background(Colors.Primary).
		Foreground(lipgloss.Color("#FFFFFF")).
		Bold(true),

	TreeExpanded: lipgloss.NewStyle().
		Foreground(Colors.TextMuted),

	TreeCollapsed: lipgloss.NewStyle().
		Foreground(Colors.TextMuted),

	SecretPane: lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Border).
		Padding(0, 1),

	SecretKey: lipgloss.NewStyle().
		Foreground(Colors.Key).
		Bold(true),

	SecretValue: lipgloss.NewStyle().
		Foreground(Colors.TextPrimary),

	SecretMasked: lipgloss.NewStyle().
		Foreground(Colors.TextMuted).
		Italic(true),

	FormLabel: lipgloss.NewStyle().
		Foreground(Colors.TextSecondary).
		Width(12),

	FormInput: lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Border).
		Padding(0, 1),

	FormInputFocused: lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Primary).
		Padding(0, 1),

	FormError: lipgloss.NewStyle().
		Foreground(Colors.Error),

	Modal: lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Primary).
		Background(Colors.Surface).
		Padding(1, 2),

	ModalTitle: lipgloss.NewStyle().
		Foreground(Colors.Primary).
		Bold(true).
		MarginBottom(1),

	ModalContent: lipgloss.NewStyle().
		Foreground(Colors.TextPrimary),

	Palette: lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Primary).
		Background(Colors.Surface).
		Padding(1, 2).
		Width(60),

	PaletteItem: lipgloss.NewStyle().
		Foreground(Colors.TextPrimary).
		Padding(0, 1),

	PaletteMatch: lipgloss.NewStyle().
		Foreground(Colors.Primary).
		Bold(true),

	PaletteSelected: lipgloss.NewStyle().
		Background(Colors.Primary).
		Foreground(lipgloss.Color("#FFFFFF")).
		Padding(0, 1),

	Button: lipgloss.NewStyle().
		Foreground(Colors.TextPrimary).
		Background(Colors.Surface).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Border).
		Padding(0, 2),

	ButtonFocused: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(Colors.Primary).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Primary).
		Padding(0, 2),

	ButtonDanger: lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(Colors.Error).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(Colors.Error).
		Padding(0, 2),

	HelpKey: lipgloss.NewStyle().
		Foreground(Colors.Key),

	HelpDesc: lipgloss.NewStyle().
		Foreground(Colors.TextMuted),

	Title: lipgloss.NewStyle().
		Foreground(Colors.Primary).
		Bold(true).
		Padding(0, 1),

	Header: lipgloss.NewStyle().
		Foreground(Colors.TextSecondary).
		Bold(true),

	Divider: lipgloss.NewStyle().
		Foreground(Colors.Border),
}

// Tree characters for rendering
const (
	TreeVertical   = "│"
	TreeHorizontal = "─"
	TreeCorner     = "└"
	TreeBranch     = "├"
	TreeExpanded   = "▼"
	TreeCollapsed  = "▶"
	TreeSecret     = "●"
	TreeKey        = ":"
)
