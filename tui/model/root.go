package model

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/rc"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/tui/component"
	"github.com/cloudfoundry-community/safe/tui/view"
	"github.com/cloudfoundry-community/safe/vault"
)

// secretDeletedMsg is an internal message for successful secret deletion
type secretDeletedMsg struct {
	Path string
}

// TabSession represents a tab with its associated browser session
type TabSession struct {
	ID          string
	TargetAlias string
	Browser     *view.BrowserModel
	Adapter     *adapter.VaultAdapter
	Modified    bool
}

// RootModel is the main Bubble Tea model for the TUI
type RootModel struct {
	// Configuration
	config        *rc.Config
	configAdapter *adapter.ConfigAdapter

	// Active sessions (one per connected target)
	sessions     map[string]*Session
	activeTarget string

	// Vault adapters
	adapters map[string]*adapter.VaultAdapter

	// Tab management
	tabBar      component.TabBar
	tabSessions map[string]*TabSession // Map of tab ID to session
	tabCounter  int                    // Counter for generating unique tab IDs

	// Layout
	layout LayoutMode

	// Current view
	activeView ViewType

	// Target list state
	targetList         []string
	targetCursor       int
	selectingForNewTab bool // True when targets view is for opening a new tab

	// Browser view (for backwards compatibility, points to active tab's browser)
	browser *view.BrowserModel

	// Editor view
	editor *view.EditorModel

	// Compare view
	compare      *view.CompareModel
	compareLeft  string // Left target name for comparison
	compareRight string // Right target name for comparison

	// Admin view
	admin *view.AdminModel

	// Key details view
	keyDetails *view.KeyDetailsModel

	// View stack for back navigation
	viewStack []ViewType

	// Components
	statusBar component.StatusBar
	palette   component.Palette
	help      help.Model
	keys      keyMap

	// Polish components (Phase 10)
	helpOverlay component.Help
	modal       component.Modal
	spinner     component.Spinner
	clipboard   component.Clipboard
	history     component.History

	// For vim-style gt/gT navigation
	pendingG bool

	// Modal/overlay state
	showHelpOverlay   bool
	showPalette       bool
	pendingDeletePath string // Path waiting for delete confirmation
	pendingDeleteInfo struct {
		IsDir    bool
		IsSecret bool
		IsKey    bool
		KeyName  string
	}

	// Viewport dimensions
	width  int
	height int
	ready  bool
}

// keyMap defines key bindings for help display
type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	Left     key.Binding
	Right    key.Binding
	Select   key.Binding
	Help     key.Binding
	Quit     key.Binding
	Palette  key.Binding
	Back     key.Binding
	Compare  key.Binding
	Admin    key.Binding
	NewTab   key.Binding
	CloseTab key.Binding
	NextTab  key.Binding
	PrevTab  key.Binding
	// Phase 10: Polish key bindings
	Copy            key.Binding
	CopyPath        key.Binding
	CopyPathWithKey key.Binding
	Undo            key.Binding
	Redo            key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right},
		{k.Select, k.Palette, k.Back},
		{k.NewTab, k.CloseTab, k.NextTab, k.PrevTab},
		{k.Compare, k.Admin, k.Help, k.Quit},
	}
}

// NewRootModel creates a new root model
func NewRootModel(cfg *rc.Config, initialTarget string) *RootModel {
	configAdapter := adapter.NewConfigAdapter(cfg)

	// Build sorted target list
	targetList := make([]string, 0, len(cfg.Vaults))
	for alias := range cfg.Vaults {
		targetList = append(targetList, alias)
	}
	sort.Strings(targetList)

	// Find initial cursor position
	cursor := 0
	if initialTarget != "" {
		for i, alias := range targetList {
			if alias == initialTarget {
				cursor = i
				break
			}
		}
	} else if cfg.Current != "" {
		for i, alias := range targetList {
			if alias == cfg.Current {
				cursor = i
				break
			}
		}
	}

	m := &RootModel{
		config:        cfg,
		configAdapter: configAdapter,
		sessions:      make(map[string]*Session),
		adapters:      make(map[string]*adapter.VaultAdapter),
		tabSessions:   make(map[string]*TabSession),
		tabBar:        component.NewTabBar(),
		activeTarget:  initialTarget,
		layout:        LayoutTabs,
		activeView:    ViewTargets,
		targetList:    targetList,
		targetCursor:  cursor,
		statusBar:     component.NewStatusBar(),
		palette:       component.NewPalette(),
		help:          help.New(),
		keys: keyMap{
			Up: key.NewBinding(
				key.WithKeys("up", "k"),
				key.WithHelp("↑/k", "up"),
			),
			Down: key.NewBinding(
				key.WithKeys("down", "j"),
				key.WithHelp("↓/j", "down"),
			),
			Left: key.NewBinding(
				key.WithKeys("left", "h"),
				key.WithHelp("←/h", "left"),
			),
			Right: key.NewBinding(
				key.WithKeys("right", "l"),
				key.WithHelp("→/l", "right"),
			),
			Select: key.NewBinding(
				key.WithKeys("enter", "l"),
				key.WithHelp("enter", "select"),
			),
			Help: key.NewBinding(
				key.WithKeys("?"),
				key.WithHelp("?", "help"),
			),
			Quit: key.NewBinding(
				key.WithKeys("ctrl+q", "ctrl+c"),
				key.WithHelp("ctrl+q", "quit"),
			),
			Palette: key.NewBinding(
				key.WithKeys("ctrl+p"),
				key.WithHelp("ctrl+p", "commands"),
			),
			Back: key.NewBinding(
				key.WithKeys("esc", "q"),
				key.WithHelp("esc/q", "back"),
			),
			Compare: key.NewBinding(
				key.WithKeys("V"),
				key.WithHelp("V", "compare"),
			),
			Admin: key.NewBinding(
				key.WithKeys("ctrl+a"),
				key.WithHelp("ctrl+a", "admin"),
			),
			NewTab: key.NewBinding(
				key.WithKeys("ctrl+t"),
				key.WithHelp("ctrl+t", "new tab"),
			),
			CloseTab: key.NewBinding(
				key.WithKeys("ctrl+w"),
				key.WithHelp("ctrl+w", "close tab"),
			),
			NextTab: key.NewBinding(
				key.WithKeys("ctrl+tab", "tab"),
				key.WithHelp("ctrl+tab", "next tab"),
			),
			PrevTab: key.NewBinding(
				key.WithKeys("ctrl+shift+tab", "shift+tab"),
				key.WithHelp("ctrl+shift+tab", "prev tab"),
			),
			// Phase 10: Polish key bindings
			Copy: key.NewBinding(
				key.WithKeys("y"),
				key.WithHelp("y", "copy value"),
			),
			CopyPath: key.NewBinding(
				key.WithKeys("c"),
				key.WithHelp("c", "copy path"),
			),
			CopyPathWithKey: key.NewBinding(
				key.WithKeys("C"),
				key.WithHelp("C", "copy path:key"),
			),
			Undo: key.NewBinding(
				key.WithKeys("ctrl+z"),
				key.WithHelp("ctrl+z", "undo"),
			),
			Redo: key.NewBinding(
				key.WithKeys("ctrl+y", "ctrl+shift+z"),
				key.WithHelp("ctrl+y", "redo"),
			),
		},
		// Phase 10: Initialize polish components
		helpOverlay: component.NewHelp(),
		modal:       component.NewModal(),
		spinner:     component.NewSpinner(),
		clipboard:   component.NewClipboard(),
		history:     component.NewHistory(),
		// View stack for back navigation
		viewStack: make([]ViewType, 0),
		// Default dimensions until WindowSizeMsg arrives
		width:  80,
		height: 24,
	}

	// Update status bar with initial state
	m.statusBar.SetTarget("")
	m.statusBar.SetPath("")
	m.statusBar.SetMessage("Welcome to Safe TUI. Press ? for help.", component.StatusInfo)

	return m
}

// Init initializes the model
func (m *RootModel) Init() tea.Cmd {
	return nil
}

// pushView pushes current view to stack and switches to new view
func (m *RootModel) pushView(newView ViewType) {
	m.viewStack = append(m.viewStack, m.activeView)
	m.activeView = newView
}

// popView returns to previous view from stack
func (m *RootModel) popView() ViewType {
	if len(m.viewStack) == 0 {
		return ViewTargets
	}
	n := len(m.viewStack) - 1
	prev := m.viewStack[n]
	m.viewStack = m.viewStack[:n]
	m.activeView = prev
	return prev
}

// generateTabID generates a unique tab ID
func (m *RootModel) generateTabID() string {
	m.tabCounter++
	return fmt.Sprintf("tab-%d", m.tabCounter)
}

// createNewTab creates a new tab for a target
func (m *RootModel) createNewTab(targetAlias string, adapterInstance *adapter.VaultAdapter) string {
	tabID := m.generateTabID()

	// Create browser model with current window dimensions
	browser := view.NewBrowserModel(targetAlias, adapterInstance)
	browser.SetSize(m.width, m.height)

	// Create tab session
	session := &TabSession{
		ID:          tabID,
		TargetAlias: targetAlias,
		Browser:     &browser,
		Adapter:     adapterInstance,
		Modified:    false,
	}
	m.tabSessions[tabID] = session

	// Add tab to tab bar
	m.tabBar.AddTab(component.Tab{
		ID:          tabID,
		Label:       targetAlias,
		TargetAlias: targetAlias,
		Modified:    false,
		Closeable:   true,
	})

	// Set as active tab
	m.tabBar.SetActiveByID(tabID)

	// Update current browser reference
	m.browser = session.Browser

	return tabID
}

// closeTab closes a tab by index
func (m *RootModel) closeTab(index int) tea.Cmd {
	tab := m.tabBar.GetTab(index)
	if tab == nil {
		return nil
	}

	tabID := tab.ID

	// Remove session
	delete(m.tabSessions, tabID)

	// Remove from tab bar
	m.tabBar.RemoveTab(index)

	// If no tabs left, return to targets view
	if m.tabBar.TabCount() == 0 {
		m.activeView = ViewTargets
		m.browser = nil
		m.statusBar.SetTarget("")
		m.statusBar.SetMessage("All tabs closed. Select a target to open a new tab.", component.StatusInfo)
		return nil
	}

	// Update browser reference to new active tab
	activeTab := m.tabBar.GetActiveTab()
	if activeTab != nil {
		if session, ok := m.tabSessions[activeTab.ID]; ok {
			m.browser = session.Browser
			m.activeTarget = session.TargetAlias
			m.statusBar.SetTarget(session.TargetAlias)
		}
	}

	return nil
}

// switchToTab switches to a tab by index
func (m *RootModel) switchToTab(index int) {
	if index < 0 || index >= m.tabBar.TabCount() {
		return
	}

	m.tabBar.SetActiveIndex(index)
	activeTab := m.tabBar.GetActiveTab()
	if activeTab != nil {
		if session, ok := m.tabSessions[activeTab.ID]; ok {
			m.browser = session.Browser
			m.activeTarget = session.TargetAlias
			m.statusBar.SetTarget(session.TargetAlias)
			m.statusBar.SetMessage("Switched to "+session.TargetAlias, component.StatusInfo)
		}
	}
}

// Update handles messages
func (m *RootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// Debug: Log prefetch messages at entry point
	switch msg.(type) {
	case adapter.PathPrefetchCompleteMsg:
		log.Printf("[DEBUG] RootModel.Update ENTRY: PathPrefetchCompleteMsg")
	case adapter.PathPrefetchErrorMsg:
		log.Printf("[DEBUG] RootModel.Update ENTRY: PathPrefetchErrorMsg")
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		m.help.Width = msg.Width
		m.tabBar.SetWidth(msg.Width)
		m.palette.SetWidth(min(60, msg.Width-4))
		m.palette.SetHeight(msg.Height)
		// Phase 10: Update polish component sizes
		m.helpOverlay.SetSize(msg.Width, msg.Height)
		m.modal.SetSize(msg.Width, msg.Height)

		// Forward to browser so it can update its layout
		if m.browser != nil {
			var cmd tea.Cmd
			*m.browser, cmd = m.browser.Update(msg)
			return m, cmd
		}

	case tea.MouseMsg:
		return m.handleMouse(msg)

	case adapter.ConnectedMsg:
		m.adapters[msg.TargetName] = msg.Adapter
		m.statusBar.SetMessage("Connected to "+msg.TargetName, component.StatusSuccess)
		m.statusBar.SetAuth(true)

		// Check if this was for compare mode
		if m.compareLeft != "" && m.compareRight != "" &&
			m.adapters[m.compareLeft] != nil && m.adapters[m.compareRight] != nil {
			// Both targets now connected, enter compare mode
			leftVault := m.adapters[m.compareLeft]
			rightVault := m.adapters[m.compareRight]
			compare := view.NewCompareModel(m.compareLeft, leftVault, m.compareRight, rightVault)
			m.compare = &compare
			m.activeView = ViewCompare
			m.statusBar.SetMessage("Compare: "+m.compareLeft+" vs "+m.compareRight, component.StatusInfo)
			return m, m.compare.Init()
		}

		m.activeView = ViewBrowser
		// Create a new tab for this connection
		tabID := m.createNewTab(msg.TargetName, msg.Adapter)
		m.selectingForNewTab = false

		// Initialize the browser
		if session, ok := m.tabSessions[tabID]; ok {
			return m, session.Browser.Init()
		}
		return m, nil

	case adapter.ConnectionErrorMsg:
		m.statusBar.SetMessage("Connection failed: "+msg.Err.Error(), component.StatusError)
		m.selectingForNewTab = false
		return m, nil

	case view.BackToTargetsMsg:
		// Close current tab when pressing back
		if m.tabBar.TabCount() > 0 {
			return m, m.closeTab(m.tabBar.GetActiveIndex())
		}
		m.activeView = ViewTargets
		m.statusBar.SetTarget("")
		m.statusBar.SetMessage("", component.StatusInfo)
		return m, nil

	case view.KeyDetailsOpenMsg:
		// Open key details view
		log.Printf("[DEBUG] RootModel received KeyDetailsOpenMsg: SecretPath=%q, KeyName=%q, activeTarget=%q", msg.SecretPath, msg.KeyName, m.activeTarget)
		if vaultAdapter, ok := m.adapters[m.activeTarget]; ok {
			log.Printf("[DEBUG] Creating KeyDetailsModel")
			keyDetails := view.NewKeyDetailsModel(msg.SecretPath, msg.KeyName, vaultAdapter)
			m.keyDetails = &keyDetails
			m.keyDetails.SetSize(m.width, m.height)
			m.pushView(ViewKeyDetails)
			m.statusBar.SetPath(msg.SecretPath + ":" + msg.KeyName)
			m.statusBar.SetMessage("Key Details: "+msg.KeyName, component.StatusInfo)
			log.Printf("[DEBUG] Switched to ViewKeyDetails")
			return m, m.keyDetails.Init()
		}
		log.Printf("[DEBUG] No vault adapter found for target: %q", m.activeTarget)
		return m, nil

	case view.KeyDetailsCloseMsg:
		// Close key details view and return to browser
		m.keyDetails = nil
		m.popView()
		m.statusBar.SetMessage("", component.StatusInfo)
		return m, nil

	case view.KeyDetailsLoadedMsg, view.KeyDetailsErrorMsg:
		// Forward to key details view
		if m.keyDetails != nil {
			var cmd tea.Cmd
			*m.keyDetails, cmd = m.keyDetails.Update(msg)
			return m, cmd
		}

	case component.TabSwitchedMsg:
		m.switchToTab(msg.Index)
		return m, nil

	case component.TabCloseRequestMsg:
		return m, m.closeTab(msg.Index)

	case component.TabNewRequestMsg:
		// Show target selector for new tab
		m.selectingForNewTab = true
		m.activeView = ViewTargets
		m.statusBar.SetMessage("Select a target to open in a new tab", component.StatusInfo)
		return m, nil

	case view.TreeRootLoadedMsg, view.TreeChildrenLoadedMsg, view.SecretPreviewMsg, view.BrowserErrorMsg, view.SecretKeysLoadedMsg, view.KeyPreviewMsg, view.NewItemCreatedMsg:
		// Forward to browser
		if m.browser != nil {
			var cmd tea.Cmd
			*m.browser, cmd = m.browser.Update(msg)
			return m, cmd
		}

	case component.SearchQueryMsg, component.SearchCancelMsg, component.SearchConfirmMsg, component.SearchToggleModeMsg:
		// Forward search messages to browser
		if m.browser != nil {
			var cmd tea.Cmd
			*m.browser, cmd = m.browser.Update(msg)
			return m, cmd
		}

	case component.TreeExpandMsg, component.TreeSelectMsg, component.TreeExpandSecretMsg, component.TreeKeySelectMsg:
		// Forward to browser
		log.Printf("[DEBUG] RootModel received tree msg: type=%T, browser=%v", msg, m.browser != nil)
		if m.browser != nil {
			var cmd tea.Cmd
			*m.browser, cmd = m.browser.Update(msg)
			log.Printf("[DEBUG] RootModel forwarding tree msg, cmd=%v", cmd != nil)
			return m, cmd
		}
		log.Printf("[DEBUG] RootModel has no browser for tree msg!")

	case adapter.PathPrefetchCompleteMsg, adapter.PathPrefetchErrorMsg:
		// Forward path prefetch messages to browser
		log.Printf("[DEBUG] RootModel received prefetch message: type=%T, browser=%v", msg, m.browser != nil)
		if m.browser != nil {
			var cmd tea.Cmd
			*m.browser, cmd = m.browser.Update(msg)
			log.Printf("[DEBUG] RootModel forwarded prefetch message to browser")
			return m, cmd
		}
		log.Printf("[DEBUG] RootModel has no browser, message not forwarded")

	// Editor view messages
	case view.EditSecretMsg:
		// Open the editor for this secret
		if vaultAdapter, ok := m.adapters[m.activeTarget]; ok {
			editor := view.NewEditorModel(msg.Path, m.activeTarget, vaultAdapter)
			m.editor = &editor
			m.activeView = ViewEditor
			m.statusBar.SetPath(msg.Path)
			m.statusBar.SetMessage("Editing secret: "+msg.Path, component.StatusInfo)
			return m, m.editor.Init()
		}
		return m, nil

	case view.EditorSecretLoadedMsg:
		// Forward to editor
		if m.editor != nil {
			var cmd tea.Cmd
			*m.editor, cmd = m.editor.Update(msg)
			return m, cmd
		}

	case view.EditorSavedMsg:
		// Secret was saved, go back to browser
		m.activeView = ViewBrowser
		m.editor = nil
		m.statusBar.SetMessage("Secret saved: "+msg.Path, component.StatusSuccess)
		// Refresh the browser to show updated data
		if m.browser != nil {
			return m, m.browser.Init()
		}
		return m, nil

	case view.EditorSaveErrorMsg:
		// Show error but stay in editor
		m.statusBar.SetMessage("Save failed: "+msg.Err.Error(), component.StatusError)
		return m, nil

	case view.EditorCloseMsg:
		// Editor closed (with or without save)
		m.activeView = ViewBrowser
		m.editor = nil
		if msg.Saved {
			m.statusBar.SetMessage("Secret saved", component.StatusSuccess)
		} else {
			m.statusBar.SetMessage("Edit cancelled", component.StatusInfo)
		}
		return m, nil

	case view.EditorErrorMsg:
		// Forward to editor
		if m.editor != nil {
			var cmd tea.Cmd
			*m.editor, cmd = m.editor.Update(msg)
			return m, cmd
		}

	case view.GeneratedPasswordMsg:
		// Forward to editor
		if m.editor != nil {
			var cmd tea.Cmd
			*m.editor, cmd = m.editor.Update(msg)
			return m, cmd
		}

	case view.DeleteSecretMsg:
		// Handle delete request from browser - show confirmation modal
		m.pendingDeletePath = msg.Path
		m.pendingDeleteInfo.IsDir = msg.IsDir
		m.pendingDeleteInfo.IsSecret = msg.IsSecret
		m.pendingDeleteInfo.IsKey = msg.IsKey
		m.pendingDeleteInfo.KeyName = msg.KeyName
		m.showDeleteConfirmation(msg.Path, msg.IsDir)
		return m, nil

	case secretDeletedMsg:
		deleteMessage := "Deleted: " + msg.Path
		m.statusBar.SetMessage(deleteMessage, component.StatusSuccess)
		// Refresh browser and show delete message in browser view
		if m.browser != nil {
			m.browser.SetMessage(deleteMessage, false)
			return m, m.browser.Init()
		}
		return m, nil

	case component.PaletteCloseMsg:
		m.showPalette = false
		m.palette.Reset()
		return m, nil

	case component.CommandSelectedMsg:
		m.showPalette = false
		m.palette.Reset()
		return m.handleCommand(msg)

	// Compare view messages
	case view.ExitCompareMsg:
		m.activeView = ViewBrowser
		m.compare = nil
		m.statusBar.SetMessage("Exited compare mode", component.StatusInfo)
		return m, nil

	case view.CompareRootLoadedMsg, view.CompareChildrenLoadedMsg,
		view.CompareSecretLoadedMsg, view.CompareCopyCompleteMsg, view.CompareErrorMsg:
		// Forward to compare view
		if m.compare != nil {
			var cmd tea.Cmd
			*m.compare, cmd = m.compare.Update(msg)
			return m, cmd
		}

	case view.EnterCompareMsg:
		// Enter compare mode with two targets
		m.compareLeft = msg.LeftTarget
		m.compareRight = msg.RightTarget
		compare := view.NewCompareModel(msg.LeftTarget, msg.LeftVault, msg.RightTarget, msg.RightVault)
		m.compare = &compare
		m.activeView = ViewCompare
		m.statusBar.SetMessage("Compare mode: "+msg.LeftTarget+" vs "+msg.RightTarget, component.StatusInfo)
		return m, m.compare.Init()

	// Admin view messages
	case view.AdminStatusLoadedMsg, view.AdminErrorMsg, view.AdminOperationCompleteMsg:
		// Forward to admin view
		if m.admin != nil {
			var cmd tea.Cmd
			*m.admin, cmd = m.admin.Update(msg)
			return m, cmd
		}

	case view.AdminBackMsg:
		m.activeView = ViewBrowser
		m.admin = nil
		m.statusBar.SetMessage("", component.StatusInfo)
		return m, nil

	// Phase 10: Polish component messages
	case component.HelpCloseMsg:
		m.showHelpOverlay = false
		return m, nil

	case component.ModalCloseMsg:
		m.modal.Hide()
		return m, nil

	case component.ModalActionMsg:
		m.modal.Hide()
		if !msg.Cancelled {
			return m.handleModalAction(msg.Action)
		}
		return m, nil

	case component.SpinnerTickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case component.ClipboardCopiedMsg:
		if msg.Success {
			m.statusBar.SetMessage(component.GetClipboardMessage(msg), component.StatusSuccess)
		} else {
			errMsg := "Clipboard unavailable"
			if msg.Error != nil {
				errMsg = msg.Error.Error()
			}
			m.statusBar.SetMessage("Copy failed: "+errMsg, component.StatusError)
		}
		return m, nil

	case component.HistoryUndoMsg:
		return m.handleUndo()

	case component.HistoryRedoMsg:
		return m.handleRedo()

	case tea.KeyMsg:
		// If palette is open, send all keys to palette
		if m.showPalette {
			var cmd tea.Cmd
			m.palette, cmd = m.palette.Update(msg)
			return m, cmd
		}

		// Handle vim-style gt/gT for tab navigation
		if m.pendingG {
			m.pendingG = false
			switch msg.String() {
			case "t":
				// gt - next tab
				if m.tabBar.TabCount() > 1 {
					m.tabBar.NextTab()
					m.switchToTab(m.tabBar.GetActiveIndex())
				}
				return m, nil
			case "T":
				// gT - previous tab
				if m.tabBar.TabCount() > 1 {
					m.tabBar.PrevTab()
					m.switchToTab(m.tabBar.GetActiveIndex())
				}
				return m, nil
			}
			// Not gt or gT, continue with normal processing
		}

		// Check for 'g' key to start gt/gT sequence (only in browser view with tabs, not when text input active)
		if m.activeView == ViewBrowser && m.tabBar.TabCount() > 0 && msg.String() == "g" {
			if m.browser == nil || !m.browser.IsTextInputActive() {
				m.pendingG = true
				return m, nil
			}
		}

		// Handle global keys first
		if cmd := m.handleGlobalKeys(msg); cmd != nil {
			return m, cmd
		}

		// Handle tab keys in browser view
		if m.activeView == ViewBrowser {
			if cmd := m.handleTabKeys(msg); cmd != nil {
				return m, cmd
			}
		}

		// Handle view-specific keys
		switch m.activeView {
		case ViewTargets:
			return m.updateTargetsView(msg)
		case ViewBrowser:
			return m.updateBrowserView(msg)
		case ViewEditor:
			return m.updateEditorView(msg)
		case ViewAdmin:
			return m.updateAdminView(msg)
		case ViewCompare:
			return m.updateCompareView(msg)
		case ViewKeyDetails:
			return m.updateKeyDetailsView(msg)
		}
	}

	return m, tea.Batch(cmds...)
}

// handleGlobalKeys handles keys that work in any view
func (m *RootModel) handleGlobalKeys(msg tea.KeyMsg) tea.Cmd {
	// Handle help overlay first if visible
	if m.showHelpOverlay {
		var cmd tea.Cmd
		m.helpOverlay, cmd = m.helpOverlay.Update(msg)
		return cmd
	}

	// Handle modal if visible
	if m.modal.IsVisible() {
		var cmd tea.Cmd
		m.modal, cmd = m.modal.Update(msg)
		return cmd
	}

	switch {
	case key.Matches(msg, m.keys.Quit):
		return tea.Quit

	case key.Matches(msg, m.keys.Help):
		m.showHelpOverlay = !m.showHelpOverlay
		if m.showHelpOverlay {
			m.helpOverlay.SetSize(m.width, m.height)
			m.helpOverlay.Show()
		} else {
			m.helpOverlay.Hide()
		}
		return nil

	case key.Matches(msg, m.keys.Palette):
		m.showPalette = !m.showPalette
		if m.showPalette {
			m.palette.Reset()
			return m.palette.Focus()
		}
		return nil

	case key.Matches(msg, m.keys.Admin):
		// Toggle admin panel
		if m.activeView == ViewAdmin {
			m.activeView = ViewBrowser
			m.admin = nil
			m.statusBar.SetMessage("", component.StatusInfo)
		} else {
			return m.enterAdminMode()
		}
		return nil

	case key.Matches(msg, m.keys.Undo):
		_, cmd := m.handleUndo()
		return cmd

	case key.Matches(msg, m.keys.Redo):
		_, cmd := m.handleRedo()
		return cmd

	case key.Matches(msg, m.keys.Copy):
		if m.activeView == ViewBrowser && m.browser != nil && m.browser.IsTextInputActive() {
			return nil // Let browser handle it as text input
		}
		return m.handleCopyValue()

	case key.Matches(msg, m.keys.CopyPath):
		if m.activeView == ViewBrowser && m.browser != nil && m.browser.IsTextInputActive() {
			return nil
		}
		return m.handleCopyPath()

	case key.Matches(msg, m.keys.CopyPathWithKey):
		if m.activeView == ViewBrowser && m.browser != nil && m.browser.IsTextInputActive() {
			return nil
		}
		return m.handleCopyPathWithKey()
	}

	return nil
}

// handleMouse routes mouse events to the appropriate component
func (m *RootModel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	// If palette is open, forward mouse events to palette
	if m.showPalette {
		var cmd tea.Cmd
		m.palette, cmd = m.palette.Update(msg)
		return m, cmd
	}

	// If help overlay is open, close it on any click
	if m.showHelpOverlay {
		if msg.Type == tea.MouseLeft {
			m.showHelpOverlay = false
			m.helpOverlay.Hide()
		}
		return m, nil
	}

	// If modal is visible, forward to modal
	if m.modal.IsVisible() {
		var cmd tea.Cmd
		m.modal, cmd = m.modal.Update(msg)
		return m, cmd
	}

	// Route based on active view
	switch m.activeView {
	case ViewBrowser:
		// Check if click is on tab bar (Y == 0) when tabs are visible
		if m.tabBar.HasTabs() && msg.Y == 0 {
			var cmd tea.Cmd
			m.tabBar, cmd = m.tabBar.Update(msg)
			return m, cmd
		}

		// Otherwise forward to browser with adjusted Y coordinate
		if m.browser != nil {
			// Adjust Y for tab bar if present
			adjustedMsg := msg
			if m.tabBar.HasTabs() {
				adjustedMsg.Y = msg.Y - 1 // Account for tab bar
			}
			var cmd tea.Cmd
			*m.browser, cmd = m.browser.Update(adjustedMsg)
			return m, cmd
		}

	case ViewTargets:
		return m.handleTargetsMouseClick(msg)

	case ViewEditor:
		if m.editor != nil {
			var cmd tea.Cmd
			*m.editor, cmd = m.editor.Update(msg)
			return m, cmd
		}

	case ViewAdmin:
		if m.admin != nil {
			var cmd tea.Cmd
			*m.admin, cmd = m.admin.Update(msg)
			return m, cmd
		}

	case ViewCompare:
		if m.compare != nil {
			var cmd tea.Cmd
			*m.compare, cmd = m.compare.Update(msg)
			return m, cmd
		}

	case ViewKeyDetails:
		if m.keyDetails != nil {
			var cmd tea.Cmd
			*m.keyDetails, cmd = m.keyDetails.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

// handleTargetsMouseClick handles mouse clicks in the targets view
func (m *RootModel) handleTargetsMouseClick(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if msg.Type != tea.MouseLeft {
		return m, nil
	}

	// The targets view layout:
	// Line 0-1: Title "SAFE TUI" with padding
	// Line 2-3: Subtitle "VAULT TARGETS" + separator
	// Line 4+: Target items
	headerOffset := 5

	clickedIndex := msg.Y - headerOffset
	if clickedIndex >= 0 && clickedIndex < len(m.targetList) {
		m.targetCursor = clickedIndex
	}

	return m, nil
}

// enterAdminMode switches to admin view
func (m *RootModel) enterAdminMode() tea.Cmd {
	// Need to be connected to a vault
	if m.activeTarget == "" || m.adapters[m.activeTarget] == nil {
		m.statusBar.SetMessage("Connect to a vault first to access admin functions", component.StatusWarning)
		return nil
	}

	// Create admin model with current vault
	va := m.adapters[m.activeTarget]
	admin := view.NewAdminModel(m.activeTarget, va)
	m.admin = &admin
	m.activeView = ViewAdmin
	m.statusBar.SetMessage("Vault Administration - "+m.activeTarget, component.StatusInfo)

	return m.admin.Init()
}

// handleTabKeys handles tab-related keys
func (m *RootModel) handleTabKeys(msg tea.KeyMsg) tea.Cmd {
	// Skip tab navigation when text input is active
	if m.browser != nil && m.browser.IsTextInputActive() {
		return nil
	}

	switch {
	case key.Matches(msg, m.keys.NewTab):
		// Open target selector for new tab
		m.selectingForNewTab = true
		m.activeView = ViewTargets
		m.statusBar.SetMessage("Select a target to open in a new tab", component.StatusInfo)
		return nil

	case key.Matches(msg, m.keys.CloseTab):
		if m.tabBar.TabCount() > 0 {
			return m.closeTab(m.tabBar.GetActiveIndex())
		}
		return nil

	case key.Matches(msg, m.keys.NextTab):
		if m.tabBar.TabCount() > 1 {
			m.tabBar.NextTab()
			m.switchToTab(m.tabBar.GetActiveIndex())
		}
		return nil

	case key.Matches(msg, m.keys.PrevTab):
		if m.tabBar.TabCount() > 1 {
			m.tabBar.PrevTab()
			m.switchToTab(m.tabBar.GetActiveIndex())
		}
		return nil
	}

	// Handle number keys 1-9 for direct tab access
	keyStr := msg.String()
	if len(keyStr) == 1 && keyStr[0] >= '1' && keyStr[0] <= '9' {
		tabNum := int(keyStr[0] - '0')
		if tabNum <= m.tabBar.TabCount() {
			m.switchToTab(tabNum - 1)
			return nil
		}
	}

	return nil
}

// handleCommand handles a command selected from the palette
func (m *RootModel) handleCommand(msg component.CommandSelectedMsg) (tea.Model, tea.Cmd) {
	switch msg.Action {
	// Navigation actions
	case "switch_target":
		m.activeView = ViewTargets
		m.statusBar.SetMessage("Select a target", component.StatusInfo)
		return m, nil

	case "goto_path":
		// TODO: Show path input dialog
		m.statusBar.SetMessage("Go to path (not yet implemented)", component.StatusInfo)
		return m, nil

	case "refresh":
		if m.browser != nil {
			m.statusBar.SetMessage("Refreshing...", component.StatusInfo)
			return m, m.browser.Init()
		}
		return m, nil

	case "back":
		if m.activeView == ViewBrowser {
			m.activeView = ViewTargets
			m.statusBar.SetTarget("")
		}
		return m, nil

	case "parent":
		// TODO: Navigate to parent in browser
		m.statusBar.SetMessage("Go to parent (not yet implemented)", component.StatusInfo)
		return m, nil

	// Secret operations
	case "get":
		if m.browser != nil {
			if node := m.browser.SelectedNode(); node != nil && node.IsSecret {
				m.statusBar.SetMessage("Getting secret: "+node.Path, component.StatusInfo)
			}
		}
		return m, nil

	case "set":
		m.statusBar.SetMessage("Set secret (not yet implemented)", component.StatusInfo)
		return m, nil

	case "edit":
		m.statusBar.SetMessage("Edit secret (not yet implemented)", component.StatusInfo)
		return m, nil

	case "delete":
		m.statusBar.SetMessage("Delete secret (not yet implemented)", component.StatusInfo)
		return m, nil

	case "copy":
		m.statusBar.SetMessage("Copied to clipboard", component.StatusSuccess)
		return m, nil

	case "copy_path":
		m.statusBar.SetMessage("Copied path to clipboard", component.StatusSuccess)
		return m, nil

	case "move":
		m.statusBar.SetMessage("Move secret (not yet implemented)", component.StatusInfo)
		return m, nil

	case "paste":
		m.statusBar.SetMessage("Paste secret (not yet implemented)", component.StatusInfo)
		return m, nil

	case "new":
		m.statusBar.SetMessage("New secret (not yet implemented)", component.StatusInfo)
		return m, nil

	case "versions":
		m.statusBar.SetMessage("Secret versions (not yet implemented)", component.StatusInfo)
		return m, nil

	case "diff":
		m.statusBar.SetMessage("Diff secrets (not yet implemented)", component.StatusInfo)
		return m, nil

	// Generate actions
	case "gen_password":
		m.statusBar.SetMessage("Generate password (not yet implemented)", component.StatusInfo)
		return m, nil

	case "gen_ssh":
		m.statusBar.SetMessage("Generate SSH key (not yet implemented)", component.StatusInfo)
		return m, nil

	case "gen_rsa":
		m.statusBar.SetMessage("Generate RSA key (not yet implemented)", component.StatusInfo)
		return m, nil

	case "gen_ec":
		m.statusBar.SetMessage("Generate EC key (not yet implemented)", component.StatusInfo)
		return m, nil

	case "gen_dh":
		m.statusBar.SetMessage("Generate DH params (not yet implemented)", component.StatusInfo)
		return m, nil

	case "gen_uuid":
		m.statusBar.SetMessage("Generate UUID (not yet implemented)", component.StatusInfo)
		return m, nil

	case "gen_random":
		m.statusBar.SetMessage("Generate random (not yet implemented)", component.StatusInfo)
		return m, nil

	case "gen_fmt":
		m.statusBar.SetMessage("Format secret (not yet implemented)", component.StatusInfo)
		return m, nil

	// X.509 actions
	case "x509_issue":
		m.statusBar.SetMessage("Issue certificate (not yet implemented)", component.StatusInfo)
		return m, nil

	case "x509_revoke":
		m.statusBar.SetMessage("Revoke certificate (not yet implemented)", component.StatusInfo)
		return m, nil

	case "x509_show":
		m.statusBar.SetMessage("Show certificate (not yet implemented)", component.StatusInfo)
		return m, nil

	case "x509_renew":
		m.statusBar.SetMessage("Renew certificate (not yet implemented)", component.StatusInfo)
		return m, nil

	case "x509_validate":
		m.statusBar.SetMessage("Validate certificate (not yet implemented)", component.StatusInfo)
		return m, nil

	case "x509_crl":
		m.statusBar.SetMessage("Show CRL (not yet implemented)", component.StatusInfo)
		return m, nil

	case "x509_ca_init":
		m.statusBar.SetMessage("Initialize CA (not yet implemented)", component.StatusInfo)
		return m, nil

	case "x509_sign":
		m.statusBar.SetMessage("Sign CSR (not yet implemented)", component.StatusInfo)
		return m, nil

	// Admin actions
	case "init":
		m.statusBar.SetMessage("Init Vault (not yet implemented)", component.StatusInfo)
		return m, nil

	case "seal":
		m.statusBar.SetMessage("Seal Vault (not yet implemented)", component.StatusInfo)
		return m, nil

	case "unseal":
		m.statusBar.SetMessage("Unseal Vault (not yet implemented)", component.StatusInfo)
		return m, nil

	case "rekey":
		m.statusBar.SetMessage("Rekey Vault (not yet implemented)", component.StatusInfo)
		return m, nil

	case "status":
		m.statusBar.SetMessage("Vault status (not yet implemented)", component.StatusInfo)
		return m, nil

	case "auth":
		m.statusBar.SetMessage("Authenticate (not yet implemented)", component.StatusInfo)
		return m, nil

	case "token":
		m.statusBar.SetMessage("Token info (not yet implemented)", component.StatusInfo)
		return m, nil

	case "renew":
		m.statusBar.SetMessage("Renew token (not yet implemented)", component.StatusInfo)
		return m, nil

	case "policy_list":
		m.statusBar.SetMessage("List policies (not yet implemented)", component.StatusInfo)
		return m, nil

	case "policy_show":
		m.statusBar.SetMessage("Show policy (not yet implemented)", component.StatusInfo)
		return m, nil

	case "mount":
		m.statusBar.SetMessage("List mounts (not yet implemented)", component.StatusInfo)
		return m, nil

	case "target_add":
		m.statusBar.SetMessage("Add target (not yet implemented)", component.StatusInfo)
		return m, nil

	case "target_delete":
		m.statusBar.SetMessage("Delete target (not yet implemented)", component.StatusInfo)
		return m, nil

	// Utility actions
	case "export":
		m.statusBar.SetMessage("Export secrets (not yet implemented)", component.StatusInfo)
		return m, nil

	case "import":
		m.statusBar.SetMessage("Import secrets (not yet implemented)", component.StatusInfo)
		return m, nil

	case "tree":
		m.statusBar.SetMessage("Tree view (not yet implemented)", component.StatusInfo)
		return m, nil

	case "paths":
		m.statusBar.SetMessage("List paths (not yet implemented)", component.StatusInfo)
		return m, nil

	case "env":
		m.statusBar.SetMessage("Export to env (not yet implemented)", component.StatusInfo)
		return m, nil

	case "curl":
		m.statusBar.SetMessage("Curl command (not yet implemented)", component.StatusInfo)
		return m, nil

	case "exists":
		m.statusBar.SetMessage("Check exists (not yet implemented)", component.StatusInfo)
		return m, nil

	case "local":
		m.statusBar.SetMessage("Local vault (not yet implemented)", component.StatusInfo)
		return m, nil

	case "prompt":
		m.statusBar.SetMessage("Prompt for value (not yet implemented)", component.StatusInfo)
		return m, nil

	case "vault":
		m.statusBar.SetMessage("Vault subcommand (not yet implemented)", component.StatusInfo)
		return m, nil

	// TUI actions
	case "help":
		m.showHelpOverlay = !m.showHelpOverlay
		if m.showHelpOverlay {
			m.helpOverlay.SetSize(m.width, m.height)
			m.helpOverlay.Show()
		} else {
			m.helpOverlay.Hide()
		}
		return m, nil

	case "quit":
		return m, tea.Quit

	case "toggle_values":
		m.statusBar.SetMessage("Toggle values (not yet implemented)", component.StatusInfo)
		return m, nil

	case "toggle_split":
		m.statusBar.SetMessage("Toggle split (not yet implemented)", component.StatusInfo)
		return m, nil

	case "new_tab":
		m.statusBar.SetMessage("New tab (not yet implemented)", component.StatusInfo)
		return m, nil

	case "close_tab":
		m.statusBar.SetMessage("Close tab (not yet implemented)", component.StatusInfo)
		return m, nil

	case "search":
		m.statusBar.SetMessage("Search (not yet implemented)", component.StatusInfo)
		return m, nil

	default:
		m.statusBar.SetMessage("Unknown command: "+msg.Action, component.StatusWarning)
		return m, nil
	}
}

// updateTargetsView handles keys in the targets view
func (m *RootModel) updateTargetsView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		if m.targetCursor > 0 {
			m.targetCursor--
		}

	case key.Matches(msg, m.keys.Down):
		if m.targetCursor < len(m.targetList)-1 {
			m.targetCursor++
		}

	case key.Matches(msg, m.keys.Back):
		// If selecting for new tab and we have existing tabs, go back to browser
		if m.selectingForNewTab && m.tabBar.TabCount() > 0 {
			m.selectingForNewTab = false
			m.activeView = ViewBrowser
			m.statusBar.SetMessage("", component.StatusInfo)
			return m, nil
		}
		// At initial targets screen with no tabs open, quit the application
		if m.tabBar.TabCount() == 0 {
			return m, tea.Quit
		}

	case key.Matches(msg, m.keys.Select):
		if len(m.targetList) > 0 && m.targetCursor < len(m.targetList) {
			selectedTarget := m.targetList[m.targetCursor]

			// Check if we already have a tab for this target (only if not forcing new tab)
			if !m.selectingForNewTab {
				for _, session := range m.tabSessions {
					if session.TargetAlias == selectedTarget {
						// Switch to existing tab
						m.tabBar.SetActiveByID(session.ID)
						m.switchToTab(m.tabBar.GetActiveIndex())
						m.activeView = ViewBrowser
						return m, nil
					}
				}
			}

			m.activeTarget = selectedTarget
			m.statusBar.SetTarget(m.activeTarget)
			m.statusBar.SetMessage("Connecting to "+m.activeTarget+"...", component.StatusInfo)

			// Get vault config and connect
			if vaultCfg, ok := m.configAdapter.GetVaultConfig(m.activeTarget); ok {
				return m, adapter.ConnectCmd(m.activeTarget, vaultCfg)
			}

			m.activeView = ViewBrowser
			m.statusBar.SetMessage("Selected target: "+m.activeTarget, component.StatusSuccess)
		}

	case msg.String() == "g":
		// Go to top (vim: gg would need state, just use g for now)
		m.targetCursor = 0

	case msg.String() == "G":
		// Go to bottom
		if len(m.targetList) > 0 {
			m.targetCursor = len(m.targetList) - 1
		}
	}

	return m, nil
}

// updateBrowserView handles keys in the browser view
func (m *RootModel) updateBrowserView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Check for compare mode toggle
	if key.Matches(msg, m.keys.Compare) {
		return m.enterCompareMode()
	}

	// Forward to browser
	if m.browser != nil {
		var cmd tea.Cmd
		*m.browser, cmd = m.browser.Update(msg)
		return m, cmd
	}
	return m, nil
}

// enterCompareMode switches to compare view
func (m *RootModel) enterCompareMode() (tea.Model, tea.Cmd) {
	// Need at least 2 targets to compare
	if len(m.targetList) < 2 {
		m.statusBar.SetMessage("Need at least 2 targets to compare", component.StatusWarning)
		return m, nil
	}

	// Need to be connected to at least one vault
	if m.activeTarget == "" || m.adapters[m.activeTarget] == nil {
		m.statusBar.SetMessage("Connect to a vault first", component.StatusWarning)
		return m, nil
	}

	// Find a second target to compare with
	var secondTarget string
	for _, target := range m.targetList {
		if target != m.activeTarget {
			secondTarget = target
			break
		}
	}

	if secondTarget == "" {
		m.statusBar.SetMessage("No second target available for comparison", component.StatusWarning)
		return m, nil
	}

	// Check if second target is connected
	if m.adapters[secondTarget] == nil {
		// Need to connect to second target first
		m.statusBar.SetMessage("Connecting to "+secondTarget+" for comparison...", component.StatusInfo)
		if vaultCfg, ok := m.configAdapter.GetVaultConfig(secondTarget); ok {
			// Store the compare request and connect
			m.compareLeft = m.activeTarget
			m.compareRight = secondTarget
			return m, adapter.ConnectCmd(secondTarget, vaultCfg)
		}
		m.statusBar.SetMessage("Failed to get config for "+secondTarget, component.StatusError)
		return m, nil
	}

	// Both targets connected, enter compare mode
	leftVault := m.adapters[m.activeTarget]
	rightVault := m.adapters[secondTarget]

	compare := view.NewCompareModel(m.activeTarget, leftVault, secondTarget, rightVault)
	m.compare = &compare
	m.compareLeft = m.activeTarget
	m.compareRight = secondTarget
	m.activeView = ViewCompare
	m.statusBar.SetMessage("Compare: "+m.activeTarget+" vs "+secondTarget, component.StatusInfo)

	return m, m.compare.Init()
}

// updateCompareView handles keys in the compare view
func (m *RootModel) updateCompareView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Forward to compare model
	if m.compare != nil {
		var cmd tea.Cmd
		*m.compare, cmd = m.compare.Update(msg)
		return m, cmd
	}
	return m, nil
}

// updateEditorView handles keys in the editor view
func (m *RootModel) updateEditorView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Forward all keys to the editor
	if m.editor != nil {
		var cmd tea.Cmd
		*m.editor, cmd = m.editor.Update(msg)
		return m, cmd
	}
	return m, nil
}

// updateAdminView handles keys in the admin view
func (m *RootModel) updateAdminView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Forward to admin view if it exists
	if m.admin != nil {
		var cmd tea.Cmd
		*m.admin, cmd = m.admin.Update(msg)
		return m, cmd
	}

	return m, nil
}

// updateKeyDetailsView handles keys in the key details view
func (m *RootModel) updateKeyDetailsView(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Forward to key details view if it exists
	if m.keyDetails != nil {
		var cmd tea.Cmd
		*m.keyDetails, cmd = m.keyDetails.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View renders the model
func (m *RootModel) View() string {
	if !m.ready {
		return "Loading..."
	}

	var s strings.Builder

	// Render tab bar if we have tabs and are in browser view
	tabBarHeight := 0
	if m.tabBar.HasTabs() && m.activeView == ViewBrowser {
		s.WriteString(m.tabBar.View())
		s.WriteString("\n")
		tabBarHeight = 1
	}

	// Render main content based on active view
	contentHeight := m.height - 2 - tabBarHeight // Leave room for status bar and tab bar

	var content string
	switch m.activeView {
	case ViewTargets:
		content = m.renderTargetsView(contentHeight)
	case ViewBrowser:
		content = m.renderBrowserView(contentHeight)
	case ViewEditor:
		content = m.renderEditorView(contentHeight)
	case ViewAdmin:
		content = m.renderAdminView(contentHeight)
	case ViewCompare:
		content = m.renderCompareView(contentHeight)
	case ViewKeyDetails:
		content = m.renderKeyDetailsView(contentHeight)
	default:
		content = m.renderTargetsView(contentHeight)
	}

	s.WriteString(content)

	// Render status bar
	s.WriteString(m.statusBar.View(m.width))

	// Render command palette as overlay if open
	if m.showPalette {
		return m.renderWithPaletteOverlay(s.String())
	}

	// Render help overlay if open (Phase 10)
	if m.showHelpOverlay {
		return m.renderWithHelpOverlay(s.String())
	}

	// Render modal if visible (Phase 10)
	if m.modal.IsVisible() {
		return m.renderWithModalOverlay(s.String())
	}

	return s.String()
}

// renderWithHelpOverlay renders the help overlay on top of the content
func (m *RootModel) renderWithHelpOverlay(content string) string {
	// Dim the background content
	dimStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	lines := strings.Split(content, "\n")
	var dimmed strings.Builder
	for _, line := range lines {
		dimmed.WriteString(dimStyle.Render(line))
		dimmed.WriteString("\n")
	}

	// Overlay the help content
	helpView := m.helpOverlay.View()
	if helpView == "" {
		return content
	}

	return helpView
}

// renderWithModalOverlay renders the modal overlay on top of the content
func (m *RootModel) renderWithModalOverlay(content string) string {
	// Dim the background content
	dimStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	lines := strings.Split(content, "\n")
	var dimmed strings.Builder
	for _, line := range lines {
		dimmed.WriteString(dimStyle.Render(line))
		dimmed.WriteString("\n")
	}

	// Overlay the modal content
	modalView := m.modal.View()
	if modalView == "" {
		return content
	}

	return modalView
}

// renderTargetsView renders the target selection view
func (m *RootModel) renderTargetsView(height int) string {
	var s strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true).
		Padding(1, 0)

	s.WriteString(titleStyle.Render("SAFE TUI"))
	s.WriteString("\n\n")

	// Subtitle - show different message if selecting for new tab
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Bold(true)

	if m.selectingForNewTab {
		s.WriteString(headerStyle.Render("SELECT TARGET FOR NEW TAB"))
	} else {
		s.WriteString(headerStyle.Render("VAULT TARGETS"))
	}
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", 50))
	s.WriteString("\n\n")

	// List targets
	if len(m.targetList) == 0 {
		mutedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Italic(true)
		s.WriteString(mutedStyle.Render("  No targets configured. Use 'safe target' to add one."))
		s.WriteString("\n")
	} else {
		for i, alias := range m.targetList {
			v := m.config.Vaults[alias]
			isCurrent := alias == m.config.Current
			isSelected := i == m.targetCursor
			hasOpenTab := false

			// Check if this target has an open tab
			for _, session := range m.tabSessions {
				if session.TargetAlias == alias {
					hasOpenTab = true
					break
				}
			}

			// Build line
			var prefix string
			if isCurrent {
				prefix = "(*) "
			} else {
				prefix = "    "
			}

			name := alias
			// Pad name to align URLs
			for len(name) < 16 {
				name += " "
			}

			line := prefix + name + " " + v.URL

			// Add indicator for open tabs
			if hasOpenTab {
				line += " [open]"
			}

			// Apply styles
			if isSelected {
				selectedStyle := lipgloss.NewStyle().
					Background(lipgloss.Color("#7C6FE0")).
					Foreground(lipgloss.Color("#FFFFFF")).
					Bold(true).
					Width(m.width - 2)
				s.WriteString(selectedStyle.Render(line))
			} else if isCurrent {
				currentStyle := lipgloss.NewStyle().
					Foreground(lipgloss.Color("#A6E3A1"))
				s.WriteString(currentStyle.Render(line))
			} else {
				normalStyle := lipgloss.NewStyle().
					Foreground(lipgloss.Color("#CDD6F4"))
				s.WriteString(normalStyle.Render(line))
			}
			s.WriteString("\n")
		}
	}

	// Calculate padding needed
	contentLines := strings.Count(s.String(), "\n")
	paddingNeeded := height - contentLines - 3 // -3 for help line and spacing
	if paddingNeeded > 0 {
		s.WriteString(strings.Repeat("\n", paddingNeeded))
	}

	// Help hint
	s.WriteString("\n")
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))

	if m.selectingForNewTab {
		s.WriteString(hintStyle.Render("  [j/k] navigate  [Enter] open in new tab  [Esc] cancel  [?] help"))
	} else {
		s.WriteString(hintStyle.Render("  [j/k] navigate  [Enter] select  [Ctrl+T] new tab  [?] help  [q] quit"))
	}
	s.WriteString("\n")

	return s.String()
}

// renderBrowserView renders the path browser view
func (m *RootModel) renderBrowserView(height int) string {
	if m.browser != nil {
		return m.browser.View()
	}

	// Fallback if browser not initialized
	mutedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)
	return mutedStyle.Render("  Initializing browser...")
}

// renderEditorView renders the secret editor view
func (m *RootModel) renderEditorView(height int) string {
	if m.editor != nil {
		return m.editor.View()
	}

	// Fallback if editor not initialized
	mutedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)
	return mutedStyle.Render("  Initializing editor...")
}

// renderAdminView renders the admin panel view
func (m *RootModel) renderAdminView(height int) string {
	if m.admin != nil {
		return m.admin.View()
	}

	// Fallback if admin not initialized
	mutedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)
	return mutedStyle.Render("  Initializing admin panel...")
}

// renderCompareView renders the compare view
func (m *RootModel) renderCompareView(height int) string {
	if m.compare != nil {
		return m.compare.View()
	}

	// Fallback if compare not initialized
	mutedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)
	return mutedStyle.Render("  Initializing compare view...")
}

// renderKeyDetailsView renders the key details view
func (m *RootModel) renderKeyDetailsView(height int) string {
	if m.keyDetails != nil {
		return m.keyDetails.View()
	}

	// Fallback if key details not initialized
	mutedStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)
	return mutedStyle.Render("  Initializing key details...")
}

// renderWithPaletteOverlay renders the palette overlay on top of the content
func (m *RootModel) renderWithPaletteOverlay(content string) string {
	safeWidth := m.width
	if safeWidth < 1 {
		safeWidth = 80
	}
	safeHeight := m.height
	if safeHeight < 1 {
		safeHeight = 24
	}

	// Get palette view
	paletteView := m.palette.View()

	// Use lipgloss.Place to properly center the palette overlay
	// This handles ANSI codes correctly
	return lipgloss.Place(
		safeWidth,
		safeHeight,
		lipgloss.Center,
		lipgloss.Center,
		paletteView,
		lipgloss.WithWhitespaceChars(" "),
		lipgloss.WithWhitespaceForeground(lipgloss.Color("#313244")),
	)
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// =============================================================================
// Phase 10: Polish helper functions
// =============================================================================

// handleModalAction handles actions from modal dialogs
func (m *RootModel) handleModalAction(action string) (tea.Model, tea.Cmd) {
	switch action {
	case "delete":
		// Perform delete operation using pendingDeletePath
		if m.pendingDeletePath != "" {
			path := m.pendingDeletePath
			isDir := m.pendingDeleteInfo.IsDir
			isKey := m.pendingDeleteInfo.IsKey
			keyName := m.pendingDeleteInfo.KeyName

			// Clear pending state
			m.pendingDeletePath = ""
			m.pendingDeleteInfo = struct {
				IsDir    bool
				IsSecret bool
				IsKey    bool
				KeyName  string
			}{}

			// Calculate parent path for navigation after deletion
			parentPath := calculateParentPath(path)

			if vaultAdapter, ok := m.adapters[m.activeTarget]; ok {
				// Set pending select path on browser for navigation after refresh
				if m.browser != nil {
					m.browser.SetPendingSelectPath(parentPath)
				}

				if isDir {
					// Delete directory (recursive delete of all secrets underneath)
					// Use Destroy:true AND All:true to completely remove all versions and metadata
					m.statusBar.SetMessage("Deleting folder: "+path, component.StatusInfo)
					return m, func() tea.Msg {
						err := vaultAdapter.DeleteTree(path, vault.DeleteOpts{Destroy: true, All: true})
						if err != nil {
							return view.BrowserErrorMsg{Err: err}
						}
						return secretDeletedMsg{Path: path}
					}
				} else if isKey {
					// Delete a specific key from a secret
					m.statusBar.SetMessage("Deleting key: "+path+":"+keyName, component.StatusInfo)
					return m, func() tea.Msg {
						// Read secret
						secret, err := vaultAdapter.Read(path)
						if err != nil {
							return view.BrowserErrorMsg{Err: err}
						}

						// Delete key
						if !secret.Delete(keyName) {
							return view.BrowserErrorMsg{Err: fmt.Errorf("key not found: %s", keyName)}
						}

						// Write back (or delete if empty)
						if secret.Empty() {
							err = vaultAdapter.Delete(path, vault.DeleteOpts{Destroy: true, All: true})
						} else {
							err = vaultAdapter.Write(path, secret)
						}
						if err != nil {
							return view.BrowserErrorMsg{Err: err}
						}
						return secretDeletedMsg{Path: path + ":" + keyName}
					}
				} else {
					// Delete a secret - use Destroy:true AND All:true to completely remove
					m.statusBar.SetMessage("Deleting: "+path, component.StatusInfo)
					return m, func() tea.Msg {
						err := vaultAdapter.Delete(path, vault.DeleteOpts{Destroy: true, All: true})
						if err != nil {
							return view.BrowserErrorMsg{Err: err}
						}
						return secretDeletedMsg{Path: path}
					}
				}
			}
		}

	case "seal":
		// Seal vault operation
		if m.admin != nil {
			m.statusBar.SetMessage("Sealing vault...", component.StatusInfo)
			// The admin view handles the actual seal operation
		}

	case "revoke":
		// Revoke certificate operation
		m.statusBar.SetMessage("Certificate revocation not yet implemented", component.StatusWarning)

	case "close":
		// Just close the modal
		return m, nil
	}

	return m, nil
}

// handleUndo handles undo operations
func (m *RootModel) handleUndo() (tea.Model, tea.Cmd) {
	if !m.history.CanUndo() {
		m.statusBar.SetMessage("Nothing to undo", component.StatusInfo)
		return m, nil
	}

	entry := m.history.Undo()
	if entry == nil {
		return m, nil
	}

	m.statusBar.SetMessage("Undo: "+entry.Description, component.StatusInfo)

	// TODO: Implement actual undo logic based on entry.Action
	// For now, just show a message
	switch entry.Action {
	case component.ActionCreate:
		// Would delete the created secret
		m.statusBar.SetMessage("Undo create: "+entry.Path+" (not yet implemented)", component.StatusWarning)

	case component.ActionUpdate:
		// Would restore old value
		m.statusBar.SetMessage("Undo update: "+entry.Path+" (not yet implemented)", component.StatusWarning)

	case component.ActionDelete:
		// Would recreate the deleted secret
		m.statusBar.SetMessage("Undo delete: "+entry.Path+" (not yet implemented)", component.StatusWarning)

	case component.ActionRename, component.ActionMove:
		// Would rename/move back
		m.statusBar.SetMessage("Undo rename/move: "+entry.OldValue+" (not yet implemented)", component.StatusWarning)
	}

	return m, nil
}

// handleRedo handles redo operations
func (m *RootModel) handleRedo() (tea.Model, tea.Cmd) {
	if !m.history.CanRedo() {
		m.statusBar.SetMessage("Nothing to redo", component.StatusInfo)
		return m, nil
	}

	entry := m.history.Redo()
	if entry == nil {
		return m, nil
	}

	m.statusBar.SetMessage("Redo: "+entry.Description, component.StatusInfo)

	// TODO: Implement actual redo logic based on entry.Action
	// For now, just show a message
	m.statusBar.SetMessage("Redo: "+entry.Description+" (not yet implemented)", component.StatusWarning)

	return m, nil
}

// handleCopyValue handles copying a secret value to clipboard
func (m *RootModel) handleCopyValue() tea.Cmd {
	if m.activeView != ViewBrowser || m.browser == nil {
		return nil
	}

	// First check if a specific key is selected
	if secretPath, keyName, keyValue, hasKey := m.browser.SelectedKeyInfo(); hasKey {
		// If we have the value already cached, copy it directly
		if keyValue != "" {
			m.statusBar.SetMessage(fmt.Sprintf("Copied %s:%s value", secretPath, keyName), component.StatusSuccess)
			return component.CopyToClipboard(keyValue, component.ClipboardValue, secretPath, keyName)
		}
		// Value not loaded yet - need to read it from vault
		if vaultAdapter, ok := m.adapters[m.activeTarget]; ok {
			return func() tea.Msg {
				value, err := vaultAdapter.ReadKeyValue(secretPath, keyName)
				if err != nil {
					return component.ClipboardCopiedMsg{
						Success: false,
						Error:   err,
					}
				}
				return component.CopyToClipboard(value, component.ClipboardValue, secretPath, keyName)()
			}
		}
	}

	// Otherwise, get the selected node's secret
	node := m.browser.SelectedNode()
	if node == nil || !node.IsSecret {
		m.statusBar.SetMessage("Select a secret or key to copy", component.StatusWarning)
		return nil
	}

	// We need to read the secret to copy its value
	if vaultAdapter, ok := m.adapters[m.activeTarget]; ok {
		return func() tea.Msg {
			secret, err := vaultAdapter.Read(node.Path)
			if err != nil {
				return component.ClipboardCopiedMsg{
					Success: false,
					Error:   err,
				}
			}

			// Get the first key's value or the "value" key if it exists
			keys := secret.Keys()
			if len(keys) == 0 {
				return component.ClipboardCopiedMsg{
					Success: false,
					Error:   fmt.Errorf("secret has no values"),
				}
			}

			// Prefer "value" or "password" keys, otherwise use first key
			var valueKey string
			for _, k := range keys {
				if k == "value" || k == "password" {
					valueKey = k
					break
				}
			}
			if valueKey == "" {
				valueKey = keys[0]
			}

			value := secret.Get(valueKey)
			return component.CopyToClipboard(value, component.ClipboardValue, node.Path, valueKey)()
		}
	}

	return nil
}

// handleCopyPath handles copying just the path to clipboard
func (m *RootModel) handleCopyPath() tea.Cmd {
	if m.activeView != ViewBrowser || m.browser == nil {
		return nil
	}

	path := m.browser.SelectedPath()
	if path == "" {
		m.statusBar.SetMessage("Nothing selected to copy", component.StatusWarning)
		return nil
	}

	m.statusBar.SetMessage(fmt.Sprintf("Copied path: %s", path), component.StatusSuccess)
	return component.CopyPath(path)
}

// handleCopyPathWithKey handles copying path:key format to clipboard
func (m *RootModel) handleCopyPathWithKey() tea.Cmd {
	if m.activeView != ViewBrowser || m.browser == nil {
		return nil
	}

	pathWithKey := m.browser.SelectedPathWithKey()
	if pathWithKey == "" {
		m.statusBar.SetMessage("Nothing selected to copy", component.StatusWarning)
		return nil
	}

	m.statusBar.SetMessage(fmt.Sprintf("Copied: %s", pathWithKey), component.StatusSuccess)
	return component.CopyPath(pathWithKey)
}

// showDeleteConfirmation shows a delete confirmation modal
func (m *RootModel) showDeleteConfirmation(path string, isDir bool) {
	m.modal.ConfirmDelete(path, isDir)
	m.modal.SetSize(m.width, m.height)
}

// showErrorModal shows an error modal
func (m *RootModel) showErrorModal(title, message string) {
	m.modal.Error(title, message)
	m.modal.SetSize(m.width, m.height)
}

// showInfoModal shows an info modal
func (m *RootModel) showInfoModal(title, message string) {
	m.modal.Info(title, message)
	m.modal.SetSize(m.width, m.height)
}

// startLoading starts the loading spinner
func (m *RootModel) startLoading(message string) tea.Cmd {
	m.spinner.SetMessage(message)
	return m.spinner.Start()
}

// stopLoading stops the loading spinner
func (m *RootModel) stopLoading() {
	m.spinner.Stop()
}

// getHistoryStatus returns the undo/redo status for display
func (m *RootModel) getHistoryStatus() string {
	return m.history.GetStatusText()
}

// calculateParentPath returns the parent path of a given path
func calculateParentPath(path string) string {
	// Trim trailing slash if present
	path = strings.TrimSuffix(path, "/")

	// Find the last slash
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash <= 0 {
		// No parent or root level - return mount point
		return path
	}

	return path[:lastSlash]
}
