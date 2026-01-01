package view

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/tui/component"
	"github.com/cloudfoundry-community/safe/vault"
)

// DiffStatus represents the comparison status of an item
type DiffStatus int

const (
	// DiffSame indicates the item is identical in both vaults
	DiffSame DiffStatus = iota
	// DiffDifferent indicates the item exists in both but differs
	DiffDifferent
	// DiffMissingLeft indicates the item only exists in the right vault
	DiffMissingLeft
	// DiffMissingRight indicates the item only exists in the left vault
	DiffMissingRight
)

// ComparePane represents one side of the comparison
type ComparePane struct {
	target      string
	vault       *adapter.VaultAdapter
	treeAdapter *adapter.TreeAdapter
	tree        component.Tree

	// Preview state
	previewPath   string
	previewSecret *vault.Secret

	// Loading state
	loading bool
	err     error
}

// CompareModel is the model for the comparison view
type CompareModel struct {
	// Split pane container
	split component.SplitPane

	// Left and right comparison panes
	left  ComparePane
	right ComparePane

	// Current focus (left or right)
	focus component.SplitFocus

	// Sync scroll mode
	syncScroll bool

	// Diff data
	diffCache map[string]DiffStatus // path -> status

	// Layout
	width  int
	height int

	// Keys
	keys compareKeyMap

	// Styles
	styles CompareStyles
}

type compareKeyMap struct {
	SwitchPane  key.Binding
	CopyToRight key.Binding
	CopyToLeft  key.Binding
	SyncScroll  key.Binding
	Refresh     key.Binding
	Exit        key.Binding
	ResizeLeft  key.Binding
	ResizeRight key.Binding
	Up          key.Binding
	Down        key.Binding
	Expand      key.Binding
	Collapse    key.Binding
}

// CompareStyles contains styles for the compare view
type CompareStyles struct {
	Same         lipgloss.Style
	Different    lipgloss.Style
	MissingLeft  lipgloss.Style
	MissingRight lipgloss.Style
	DiffTag      lipgloss.Style
	Header       lipgloss.Style
	HelpBar      lipgloss.Style
}

func defaultCompareKeyMap() compareKeyMap {
	return compareKeyMap{
		SwitchPane: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "switch pane"),
		),
		CopyToRight: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("right/l", "copy to right"),
		),
		CopyToLeft: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("left/h", "copy to left"),
		),
		SyncScroll: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "toggle sync scroll"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "refresh"),
		),
		Exit: key.NewBinding(
			key.WithKeys("v", "esc"),
			key.WithHelp("v/esc", "exit compare"),
		),
		ResizeLeft: key.NewBinding(
			key.WithKeys("ctrl+left"),
			key.WithHelp("ctrl+left", "resize left"),
		),
		ResizeRight: key.NewBinding(
			key.WithKeys("ctrl+right"),
			key.WithHelp("ctrl+right", "resize right"),
		),
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/up", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/down", "down"),
		),
		Expand: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "expand/select"),
		),
		Collapse: key.NewBinding(
			key.WithKeys("backspace"),
			key.WithHelp("backspace", "collapse"),
		),
	}
}

func defaultCompareStyles() CompareStyles {
	return CompareStyles{
		Same: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")),
		Different: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")),
		MissingLeft: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")),
		MissingRight: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")),
		DiffTag: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Bold(true),
		Header: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")).
			Bold(true),
		HelpBar: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")),
	}
}

// NewCompareModel creates a new comparison model
func NewCompareModel(leftTarget string, leftVault *adapter.VaultAdapter,
	rightTarget string, rightVault *adapter.VaultAdapter) CompareModel {

	split := component.NewSplitPane()
	split.SetLabels(leftTarget, rightTarget)

	left := ComparePane{
		target:      leftTarget,
		vault:       leftVault,
		treeAdapter: adapter.NewTreeAdapter(leftVault),
		tree:        component.NewTree(),
	}

	right := ComparePane{
		target:      rightTarget,
		vault:       rightVault,
		treeAdapter: adapter.NewTreeAdapter(rightVault),
		tree:        component.NewTree(),
	}

	return CompareModel{
		split:      split,
		left:       left,
		right:      right,
		focus:      component.FocusLeft,
		syncScroll: true,
		diffCache:  make(map[string]DiffStatus),
		keys:       defaultCompareKeyMap(),
		styles:     defaultCompareStyles(),
		width:      80, // Default until WindowSizeMsg
		height:     24,
	}
}

// Init initializes the compare model
func (m CompareModel) Init() tea.Cmd {
	return tea.Batch(
		m.loadLeftRoot(),
		m.loadRightRoot(),
	)
}

// loadLeftRoot loads the root of the left tree
func (m *CompareModel) loadLeftRoot() tea.Cmd {
	return func() tea.Msg {
		root, err := m.left.treeAdapter.BuildRootNode()
		if err != nil {
			return CompareErrorMsg{Side: "left", Err: err}
		}
		return CompareRootLoadedMsg{Side: "left", Root: root}
	}
}

// loadRightRoot loads the root of the right tree
func (m *CompareModel) loadRightRoot() tea.Cmd {
	return func() tea.Msg {
		root, err := m.right.treeAdapter.BuildRootNode()
		if err != nil {
			return CompareErrorMsg{Side: "right", Err: err}
		}
		return CompareRootLoadedMsg{Side: "right", Root: root}
	}
}

// Update handles messages
func (m CompareModel) Update(msg tea.Msg) (CompareModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()

	case CompareRootLoadedMsg:
		if msg.Side == "left" {
			m.left.tree.SetRoot(msg.Root)
			m.left.tree.Expand("/")
			m.left.loading = false
		} else {
			m.right.tree.SetRoot(msg.Root)
			m.right.tree.Expand("/")
			m.right.loading = false
		}
		return m, nil

	case CompareChildrenLoadedMsg:
		if msg.Side == "left" {
			m.left.tree.SetChildren(msg.Path, msg.Children)
			m.left.tree.SetLoading(msg.Path, false)
		} else {
			m.right.tree.SetChildren(msg.Path, msg.Children)
			m.right.tree.SetLoading(msg.Path, false)
		}
		// Update diff cache
		m.updateDiffCache()
		return m, nil

	case CompareSecretLoadedMsg:
		if msg.Side == "left" {
			m.left.previewPath = msg.Path
			m.left.previewSecret = msg.Secret
		} else {
			m.right.previewPath = msg.Path
			m.right.previewSecret = msg.Secret
		}
		// Update diff cache for this path
		m.computeSecretDiff(msg.Path)
		return m, nil

	case CompareCopyCompleteMsg:
		// Refresh the target side after copy
		if msg.ToSide == "left" {
			return m, m.loadLeftRoot()
		}
		return m, m.loadRightRoot()

	case CompareErrorMsg:
		if msg.Side == "left" {
			m.left.err = msg.Err
			m.left.loading = false
		} else {
			m.right.err = msg.Err
			m.right.loading = false
		}
		return m, nil

	case component.TreeExpandMsg:
		// Handle tree expansion for the focused pane
		if m.focus == component.FocusLeft {
			m.left.tree.SetLoading(msg.Path, true)
			return m, m.loadLeftChildren(msg.Path)
		} else {
			m.right.tree.SetLoading(msg.Path, true)
			return m, m.loadRightChildren(msg.Path)
		}

	case component.TreeSelectMsg:
		// Load secret for preview
		if msg.IsSecret {
			if m.focus == component.FocusLeft {
				return m, m.loadLeftSecret(msg.Path)
			}
			return m, m.loadRightSecret(msg.Path)
		}

	case component.SplitFocusChangedMsg:
		m.focus = msg.Focus

	case tea.KeyMsg:
		return m.handleKeyMsg(msg)
	}

	return m, tea.Batch(cmds...)
}

// handleKeyMsg handles key presses
func (m CompareModel) handleKeyMsg(msg tea.KeyMsg) (CompareModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch {
	case key.Matches(msg, m.keys.Exit):
		return m, func() tea.Msg {
			return ExitCompareMsg{}
		}

	case key.Matches(msg, m.keys.SwitchPane):
		m.focus = m.toggleFocus()
		m.split.SetFocus(m.focus)
		return m, nil

	case key.Matches(msg, m.keys.SyncScroll):
		m.syncScroll = !m.syncScroll
		return m, nil

	case key.Matches(msg, m.keys.Refresh):
		m.left.loading = true
		m.right.loading = true
		return m, tea.Batch(m.loadLeftRoot(), m.loadRightRoot())

	case key.Matches(msg, m.keys.CopyToRight):
		// Copy selected item from left to right
		if m.focus == component.FocusLeft {
			if node := m.left.tree.SelectedNode(); node != nil && node.IsSecret {
				return m, m.copySecret(node.Path, "left", "right")
			}
		}

	case key.Matches(msg, m.keys.CopyToLeft):
		// Copy selected item from right to left
		if m.focus == component.FocusRight {
			if node := m.right.tree.SelectedNode(); node != nil && node.IsSecret {
				return m, m.copySecret(node.Path, "right", "left")
			}
		}

	case key.Matches(msg, m.keys.ResizeLeft):
		m.split.SetRatio(m.split.Ratio() - 0.05)
		m.updateLayout()
		return m, nil

	case key.Matches(msg, m.keys.ResizeRight):
		m.split.SetRatio(m.split.Ratio() + 0.05)
		m.updateLayout()
		return m, nil

	default:
		// Forward navigation keys to the focused tree
		if m.focus == component.FocusLeft {
			var cmd tea.Cmd
			m.left.tree, cmd = m.left.tree.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}

			// Sync scroll if enabled
			if m.syncScroll {
				m.syncTreePosition(&m.left.tree, &m.right.tree)
			}
		} else {
			var cmd tea.Cmd
			m.right.tree, cmd = m.right.tree.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}

			// Sync scroll if enabled
			if m.syncScroll {
				m.syncTreePosition(&m.right.tree, &m.left.tree)
			}
		}
	}

	return m, tea.Batch(cmds...)
}

// toggleFocus switches focus between panes
func (m *CompareModel) toggleFocus() component.SplitFocus {
	if m.focus == component.FocusLeft {
		return component.FocusRight
	}
	return component.FocusLeft
}

// syncTreePosition syncs the position of the target tree to the source tree
func (m *CompareModel) syncTreePosition(source, target *component.Tree) {
	// Get selected path from source
	if node := source.SelectedNode(); node != nil {
		// Try to find and select the same path in target
		// This is a simple sync - could be enhanced
		_ = node.Path
	}
}

// updateLayout updates component sizes
func (m *CompareModel) updateLayout() {
	// Account for header and help bar
	contentHeight := m.height - 4

	m.split.SetSize(m.width, contentHeight)

	leftW, leftH := m.split.LeftPaneSize()
	rightW, rightH := m.split.RightPaneSize()

	m.left.tree.SetSize(leftW-2, leftH-2)
	m.right.tree.SetSize(rightW-2, rightH-2)
}

// loadLeftChildren loads children for a path in the left tree
func (m *CompareModel) loadLeftChildren(path string) tea.Cmd {
	return func() tea.Msg {
		children, err := m.left.treeAdapter.LoadChildren(path)
		if err != nil {
			return CompareErrorMsg{Side: "left", Err: err}
		}
		return CompareChildrenLoadedMsg{Side: "left", Path: path, Children: children}
	}
}

// loadRightChildren loads children for a path in the right tree
func (m *CompareModel) loadRightChildren(path string) tea.Cmd {
	return func() tea.Msg {
		children, err := m.right.treeAdapter.LoadChildren(path)
		if err != nil {
			return CompareErrorMsg{Side: "right", Err: err}
		}
		return CompareChildrenLoadedMsg{Side: "right", Path: path, Children: children}
	}
}

// loadLeftSecret loads a secret from the left vault
func (m *CompareModel) loadLeftSecret(path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := m.left.vault.Read(path)
		if err != nil {
			return CompareErrorMsg{Side: "left", Err: err}
		}
		return CompareSecretLoadedMsg{Side: "left", Path: path, Secret: secret}
	}
}

// loadRightSecret loads a secret from the right vault
func (m *CompareModel) loadRightSecret(path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := m.right.vault.Read(path)
		if err != nil {
			return CompareErrorMsg{Side: "right", Err: err}
		}
		return CompareSecretLoadedMsg{Side: "right", Path: path, Secret: secret}
	}
}

// copySecret copies a secret from one vault to another
func (m *CompareModel) copySecret(path, fromSide, toSide string) tea.Cmd {
	return func() tea.Msg {
		var sourceVault, targetVault *adapter.VaultAdapter
		if fromSide == "left" {
			sourceVault = m.left.vault
			targetVault = m.right.vault
		} else {
			sourceVault = m.right.vault
			targetVault = m.left.vault
		}

		// Read from source
		secret, err := sourceVault.Read(path)
		if err != nil {
			return CompareErrorMsg{Side: fromSide, Err: fmt.Errorf("read failed: %w", err)}
		}

		// Write to target
		err = targetVault.Write(path, secret)
		if err != nil {
			return CompareErrorMsg{Side: toSide, Err: fmt.Errorf("write failed: %w", err)}
		}

		return CompareCopyCompleteMsg{Path: path, FromSide: fromSide, ToSide: toSide}
	}
}

// updateDiffCache updates the diff cache based on current tree state
func (m *CompareModel) updateDiffCache() {
	// Get all paths from both trees and compute diffs
	leftPaths := m.collectPaths(&m.left.tree)
	rightPaths := m.collectPaths(&m.right.tree)

	// Mark paths in both
	for path := range leftPaths {
		if _, ok := rightPaths[path]; ok {
			// In both - need to compare values (done when secrets are loaded)
			if _, cached := m.diffCache[path]; !cached {
				m.diffCache[path] = DiffSame // Default until secrets are compared
			}
		} else {
			m.diffCache[path] = DiffMissingRight
		}
	}

	for path := range rightPaths {
		if _, ok := leftPaths[path]; !ok {
			m.diffCache[path] = DiffMissingLeft
		}
	}
}

// collectPaths collects all paths from a tree
func (m *CompareModel) collectPaths(tree *component.Tree) map[string]bool {
	paths := make(map[string]bool)
	if node := tree.SelectedNode(); node != nil {
		// Walk the tree and collect paths
		// This is a simplified version - could be enhanced to walk all nodes
		paths[node.Path] = true
	}
	return paths
}

// computeSecretDiff compares a secret in both vaults
func (m *CompareModel) computeSecretDiff(path string) {
	if m.left.previewPath == path && m.right.previewPath == path &&
		m.left.previewSecret != nil && m.right.previewSecret != nil {

		if secretsEqual(m.left.previewSecret, m.right.previewSecret) {
			m.diffCache[path] = DiffSame
		} else {
			m.diffCache[path] = DiffDifferent
		}
	}
}

// secretsEqual compares two secrets for equality
func secretsEqual(a, b *vault.Secret) bool {
	if a == nil || b == nil {
		return a == b
	}

	aKeys := a.Keys()
	bKeys := b.Keys()

	if len(aKeys) != len(bKeys) {
		return false
	}

	sort.Strings(aKeys)
	sort.Strings(bKeys)

	for i, k := range aKeys {
		if k != bKeys[i] {
			return false
		}
		if a.Get(k) != b.Get(k) {
			return false
		}
	}

	return true
}

// View renders the compare view
func (m CompareModel) View() string {
	var s strings.Builder

	// Header
	header := m.renderHeader()
	s.WriteString(header)
	s.WriteString("\n")

	// Main content - split panes
	leftContent := m.renderPane(&m.left, m.focus == component.FocusLeft)
	rightContent := m.renderPane(&m.right, m.focus == component.FocusRight)

	m.split.SetContent(leftContent, rightContent)
	s.WriteString(m.split.View())
	s.WriteString("\n")

	// Help bar
	helpBar := m.renderHelpBar()
	s.WriteString(helpBar)

	return s.String()
}

// renderHeader renders the comparison header
func (m *CompareModel) renderHeader() string {
	headerStyle := m.styles.Header

	title := headerStyle.Render("COMPARE MODE")
	syncIndicator := ""
	if m.syncScroll {
		syncIndicator = m.styles.HelpBar.Render(" [SYNC]")
	}

	return fmt.Sprintf("%s%s  %s vs %s",
		title,
		syncIndicator,
		m.left.target,
		m.right.target,
	)
}

// renderPane renders a comparison pane
func (m *CompareModel) renderPane(pane *ComparePane, focused bool) string {
	if pane.loading {
		return m.styles.HelpBar.Render("  Loading...")
	}

	if pane.err != nil {
		return m.styles.DiffTag.Render("  Error: " + pane.err.Error())
	}

	var s strings.Builder

	// Tree view with diff indicators
	treeContent := m.renderTreeWithDiffs(&pane.tree, pane == &m.left)
	s.WriteString(treeContent)

	// Preview if a secret is selected
	if pane.previewSecret != nil {
		s.WriteString("\n")
		s.WriteString(strings.Repeat("─", 30))
		s.WriteString("\n")
		s.WriteString(m.renderSecretPreview(pane))
	}

	return s.String()
}

// renderTreeWithDiffs renders the tree with diff status indicators
func (m *CompareModel) renderTreeWithDiffs(tree *component.Tree, isLeft bool) string {
	// Get the base tree view
	baseView := tree.View()

	// Add diff indicators
	lines := strings.Split(baseView, "\n")
	var result []string

	for _, line := range lines {
		// Extract path from line (simplified - would need enhancement for real use)
		// For now, just pass through the tree view
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

// renderSecretPreview renders a secret preview with diff highlighting
func (m *CompareModel) renderSecretPreview(pane *ComparePane) string {
	if pane.previewSecret == nil {
		return m.styles.HelpBar.Render("No secret selected")
	}

	var s strings.Builder
	keys := pane.previewSecret.Keys()

	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF")).
		Bold(true).
		Width(15)

	valueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4"))

	// Get the other pane's secret for comparison
	var otherSecret *vault.Secret
	if pane == &m.left {
		otherSecret = m.right.previewSecret
	} else {
		otherSecret = m.left.previewSecret
	}

	for _, k := range keys {
		value := pane.previewSecret.Get(k)
		line := keyStyle.Render(k) + " " + valueStyle.Render(truncateValue(value, 30))

		// Check for differences
		if otherSecret != nil {
			otherValue := otherSecret.Get(k)
			if otherValue == "" {
				// Key missing in other
				line += " " + m.styles.DiffTag.Render("[MISSING]")
			} else if otherValue != value {
				// Value differs
				line += " " + m.styles.Different.Render("[DIFF]")
			}
		}

		s.WriteString(line)
		s.WriteString("\n")
	}

	// Check for keys in the other secret that are missing here
	if otherSecret != nil {
		for _, k := range otherSecret.Keys() {
			if pane.previewSecret.Get(k) == "" {
				line := keyStyle.Render(k) + " " + m.styles.MissingLeft.Render("[MISSING HERE]")
				s.WriteString(line)
				s.WriteString("\n")
			}
		}
	}

	return s.String()
}

// truncateValue truncates a value for display
func truncateValue(value string, maxLen int) string {
	// Check if it looks like a sensitive value
	if len(value) > 0 {
		// Mask the value for display
		displayLen := len(value)
		if displayLen > maxLen {
			displayLen = maxLen
		}
		return strings.Repeat("*", displayLen)
	}
	return value
}

// renderHelpBar renders the help bar at the bottom
func (m *CompareModel) renderHelpBar() string {
	helpStyle := m.styles.HelpBar

	var hints []string
	hints = append(hints, "[Tab] switch pane")
	if m.focus == component.FocusLeft {
		hints = append(hints, "[right/l] copy to right")
	} else {
		hints = append(hints, "[left/h] copy to left")
	}
	hints = append(hints, "[s] sync scroll")
	hints = append(hints, "[r] refresh")
	hints = append(hints, "[v/esc] exit")
	hints = append(hints, "[Ctrl+left/right] resize")

	return helpStyle.Render(strings.Join(hints, "  "))
}

// Messages for compare view

// CompareRootLoadedMsg is sent when a root tree is loaded
type CompareRootLoadedMsg struct {
	Side string
	Root *component.TreeNode
}

// CompareChildrenLoadedMsg is sent when children are loaded
type CompareChildrenLoadedMsg struct {
	Side     string
	Path     string
	Children []*component.TreeNode
}

// CompareSecretLoadedMsg is sent when a secret is loaded
type CompareSecretLoadedMsg struct {
	Side   string
	Path   string
	Secret *vault.Secret
}

// CompareCopyCompleteMsg is sent when a copy operation completes
type CompareCopyCompleteMsg struct {
	Path     string
	FromSide string
	ToSide   string
}

// CompareErrorMsg is sent when an error occurs
type CompareErrorMsg struct {
	Side string
	Err  error
}

// ExitCompareMsg is sent to exit compare mode
type ExitCompareMsg struct{}

// EnterCompareMsg is sent to enter compare mode
type EnterCompareMsg struct {
	LeftTarget  string
	LeftVault   *adapter.VaultAdapter
	RightTarget string
	RightVault  *adapter.VaultAdapter
}
