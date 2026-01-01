package view

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cloudfoundry-community/safe/tui/adapter"
	"github.com/cloudfoundry-community/safe/tui/component"
	"github.com/cloudfoundry-community/safe/vault"
)

// BrowserModel is the model for the path browser view
type BrowserModel struct {
	target      string
	vault       *adapter.VaultAdapter
	treeAdapter *adapter.TreeAdapter

	// Tree component
	tree component.Tree

	// Layout
	width  int
	height int

	// State
	loading bool
	err     error

	// New item creation state
	showNewItemForm   bool
	newItemType       NewItemType // path or secret
	newItemInput      textinput.Model
	newKeyInput       textinput.Model
	newValueInput     textinput.Model
	newItemStep       int // 0=name, 1=key, 2=value for secrets
	newItemParentPath string // Captured parent path when form opens
	message           string
	messageIsError    bool

	// Search state
	search       component.Search
	searchActive bool

	// Certificate viewer
	certViewer   component.CertViewer
	showCertView bool

	// Expand all tracking
	expandAllBase string // Path being recursively expanded (empty if not active)

	// Path to select after tree refresh (e.g., after creating a new secret)
	pendingSelectPath string

	// Keys
	keys browserKeyMap
}

// KeyVersion represents a version of a key's value (for KV v2)
type KeyVersion struct {
	Version   uint
	Value     string
	CreatedAt time.Time
	Deleted   bool
	Destroyed bool
}

// NewItemType represents the type of new item being created
type NewItemType int

const (
	NewItemPath NewItemType = iota
	NewItemSecret
)

type browserKeyMap struct {
	Up         key.Binding
	Down       key.Binding
	Expand     key.Binding
	ExpandAll  key.Binding
	Collapse   key.Binding
	Select     key.Binding
	Back       key.Binding
	Refresh    key.Binding
	Copy       key.Binding
	Edit       key.Binding
	Delete     key.Binding
	Help       key.Binding
	NewSecret  key.Binding
	NewPath    key.Binding
	Search     key.Binding
	SearchNext key.Binding
	SearchPrev key.Binding
	Inspect    key.Binding
}

func defaultBrowserKeyMap() browserKeyMap {
	return browserKeyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("k/↑", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("j/↓", "down"),
		),
		Expand: key.NewBinding(
			key.WithKeys("enter", "l", "right"),
			key.WithHelp("enter/l", "expand/select"),
		),
		ExpandAll: key.NewBinding(
			key.WithKeys("E"),
			key.WithHelp("E", "expand all"),
		),
		Collapse: key.NewBinding(
			key.WithKeys("h", "left"),
			key.WithHelp("h/←", "collapse/parent"),
		),
		Select: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "q"),
			key.WithHelp("esc/q", "back"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("R"),
			key.WithHelp("R", "refresh"),
		),
		Copy: key.NewBinding(
			key.WithKeys("y"),
			key.WithHelp("y", "copy"),
		),
		Edit: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "edit"),
		),
		Delete: key.NewBinding(
			key.WithKeys("D"),
			key.WithHelp("D", "delete"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		NewSecret: key.NewBinding(
			key.WithKeys("a"),
			key.WithHelp("a", "add secret"),
		),
		NewPath: key.NewBinding(
			key.WithKeys("ctrl+n"),
			key.WithHelp("ctrl+n", "new path"),
		),
		Search: key.NewBinding(
			key.WithKeys("/"),
			key.WithHelp("/", "search"),
		),
		SearchNext: key.NewBinding(
			key.WithKeys("n"),
			key.WithHelp("n", "next match"),
		),
		SearchPrev: key.NewBinding(
			key.WithKeys("N"),
			key.WithHelp("N", "prev match"),
		),
		Inspect: key.NewBinding(
			key.WithKeys("i"),
			key.WithHelp("i", "inspect cert"),
		),
	}
}

// NewBrowserModel creates a new browser model
func NewBrowserModel(target string, vault *adapter.VaultAdapter) BrowserModel {
	tree := component.NewTree()
	treeAdapter := adapter.NewTreeAdapter(vault)

	// Initialize text inputs for new item creation
	newItemInput := textinput.New()
	newItemInput.Placeholder = "name"
	newItemInput.Width = 40
	newItemInput.CharLimit = 100

	newKeyInput := textinput.New()
	newKeyInput.Placeholder = "key"
	newKeyInput.Width = 30
	newKeyInput.CharLimit = 100

	newValueInput := textinput.New()
	newValueInput.Placeholder = "value"
	newValueInput.Width = 40
	newValueInput.CharLimit = 1000

	return BrowserModel{
		target:        target,
		vault:         vault,
		treeAdapter:   treeAdapter,
		tree:          tree,
		keys:          defaultBrowserKeyMap(),
		width:         80, // Default width until WindowSizeMsg
		height:        24, // Default height until WindowSizeMsg
		newItemInput:  newItemInput,
		newKeyInput:   newKeyInput,
		newValueInput: newValueInput,
		search:        component.NewSearch(),
		certViewer:    component.NewCertViewer(),
	}
}

// Init initializes the browser
func (m BrowserModel) Init() tea.Cmd {
	// Start loading the root tree
	return m.loadRoot()
}

// loadRoot loads the root of the tree
func (m *BrowserModel) loadRoot() tea.Cmd {
	return func() tea.Msg {
		root, err := m.treeAdapter.BuildRootNode()
		if err != nil {
			return BrowserErrorMsg{Err: err}
		}
		return TreeRootLoadedMsg{Root: root}
	}
}

// Update handles messages
func (m BrowserModel) Update(msg tea.Msg) (BrowserModel, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		m.certViewer.SetSize(msg.Width, msg.Height)

	case tea.MouseMsg:
		// Calculate Y offset for tree content
		// Tree is rendered after: header(1) + divider(1) + optional message + optional search + border(1)
		treeYOffset := 2 // header + divider
		if m.message != "" {
			treeYOffset++
		}
		if m.searchActive || m.search.HasMatches() {
			treeYOffset++
		}
		treeYOffset++ // tree border top

		log.Printf("[DEBUG] Mouse click: Y=%d, treeYOffset=%d, adjustedY=%d, hasMessage=%v, hasSearch=%v",
			msg.Y, treeYOffset, msg.Y-treeYOffset, m.message != "", m.searchActive || m.search.HasMatches())

		// Adjust mouse coordinates for tree
		adjustedMsg := msg
		adjustedMsg.Y = msg.Y - treeYOffset

		// Only forward if click is within tree area (Y >= 0)
		if adjustedMsg.Y >= 0 {
			var cmd tea.Cmd
			m.tree, cmd = m.tree.Update(adjustedMsg)
			return m, cmd
		}
		return m, nil

	case TreeRootLoadedMsg:
		m.tree.SetRoot(msg.Root)
		m.loading = false
		// Auto-expand root
		m.tree.Expand("/")

		var cmds []tea.Cmd

		// Load children for paths that were previously expanded
		pathsNeedingLoad := m.tree.GetExpandedPathsNeedingLoad()
		for _, path := range pathsNeedingLoad {
			node := m.tree.FindNodeByPath(path)
			if node != nil {
				if node.IsDir {
					cmds = append(cmds, m.loadChildren(path))
				} else if node.IsSecret {
					cmds = append(cmds, m.loadSecretKeys(path))
				}
			}
		}

		// If there's a pending path to select (e.g., after creating a new secret)
		if m.pendingSelectPath != "" {
			path := m.pendingSelectPath
			m.pendingSelectPath = "" // Clear it
			// Navigate to and select the path
			cmds = append(cmds, m.navigateToPath(path))
		}

		if len(cmds) > 0 {
			return m, tea.Batch(cmds...)
		}
		return m, nil

	case TreeChildrenLoadedMsg:
		m.tree.SetChildren(msg.Path, msg.Children)
		m.tree.SetLoading(msg.Path, false)

		var cmds []tea.Cmd

		// Continue expand-all if active and this path is under the expand base
		if m.expandAllBase != "" {
			normalizedBase := strings.TrimSuffix(strings.TrimPrefix(m.expandAllBase, "/"), "/")
			normalizedPath := strings.TrimSuffix(strings.TrimPrefix(msg.Path, "/"), "/")
			isRoot := m.expandAllBase == "/" || m.expandAllBase == ""
			isUnder := isRoot || normalizedPath == normalizedBase || strings.HasPrefix(normalizedPath, normalizedBase+"/")

			if isUnder {
				// Expand and load the new children
				for _, child := range msg.Children {
					if child.IsDir {
						m.tree.Expand(child.Path)
						if !child.Loaded && !child.Loading {
							cmds = append(cmds, m.loadChildren(child.Path))
						}
					} else if child.IsSecret {
						m.tree.Expand(child.Path)
						if !child.Loaded && !child.Loading {
							// Secrets need loadSecretKeys, not loadChildren
							cmds = append(cmds, m.loadSecretKeys(child.Path))
						}
					}
				}
			}

			// Clear expand-all flag if no more loads pending
			if len(cmds) == 0 {
				m.expandAllBase = ""
			}
		}

		// Re-run search if active to update matches for newly loaded children
		if m.search.IsActive() && m.search.Query() != "" {
			searchModel, searchCmd := m.updateSearchMatches(component.SearchQueryMsg{
				Query:       m.search.Query(),
				PatternType: m.search.State().PatternType,
			})
			m = searchModel
			if searchCmd != nil {
				cmds = append(cmds, searchCmd)
			}
		}

		// Try to select pending path if set
		if m.pendingSelectPath != "" {
			// Try to navigate to the path (may need more loading)
			if navCmd := m.navigateToPath(m.pendingSelectPath); navCmd != nil {
				cmds = append(cmds, navCmd)
			} else {
				// Path selected successfully, clear pending
				m.pendingSelectPath = ""
			}
		}

		if len(cmds) > 0 {
			return m, tea.Batch(cmds...)
		}
		return m, nil

	case SecretPreviewMsg:
		// Secret preview is no longer used - key selection navigates to details view
		return m, nil

	case BrowserErrorMsg:
		// Silently ignore errors during expand-all operations
		if m.expandAllBase != "" {
			return m, nil
		}
		// Ignore non-critical path errors (e.g., during tree expansion)
		errStr := msg.Err.Error()
		if strings.Contains(errStr, "no secret exists at path") ||
			strings.Contains(errStr, "permission denied") ||
			strings.Contains(errStr, "no value found") {
			// These are expected when expanding paths that don't have children
			return m, nil
		}
		m.err = msg.Err
		m.loading = false
		return m, nil

	case component.TreeExpandMsg:
		// Load children for this path
		m.tree.SetLoading(msg.Path, true)
		cmds := []tea.Cmd{m.loadChildren(msg.Path)}

		// If this is a mount point and not already cached, trigger prefetch
		// Normalize path for consistent cache keys (without trailing slash)
		normalizedPath := strings.TrimSuffix(msg.Path, "/")
		log.Printf("[DEBUG] TreeExpandMsg: path=%q, normalized=%q, isMountPoint=%v, cacheLoaded=%v, cacheLoading=%v",
			msg.Path, normalizedPath, isMountPoint(msg.Path), m.tree.IsCacheLoaded(normalizedPath), m.tree.IsCacheLoading(normalizedPath))
		if isMountPoint(msg.Path) && !m.tree.IsCacheLoaded(normalizedPath) && !m.tree.IsCacheLoading(normalizedPath) {
			log.Printf("[DEBUG] Triggering prefetch for mount: %s", normalizedPath)
			m.tree.SetCacheLoading(normalizedPath, true)
			prefetchCmd := m.prefetchAllPaths(msg.Path)
			log.Printf("[DEBUG] Created prefetch command: %v", prefetchCmd != nil)
			cmds = append(cmds, prefetchCmd)
		}

		log.Printf("[DEBUG] TreeExpandMsg returning batch with %d commands", len(cmds))
		return m, tea.Batch(cmds...)

	case component.TreeSelectMsg:
		if msg.IsSecret {
			// Load the secret (for expansion to show keys)
			return m, m.loadSecret(msg.Path)
		}

	case component.TreeExpandSecretMsg:
		// Load keys for the secret to expand it
		m.tree.SetLoading(msg.Path, true)
		return m, m.loadSecretKeys(msg.Path)

	case SecretKeysLoadedMsg:
		// Build key nodes and set as children
		keyNodes := m.treeAdapter.BuildKeyNodes(msg.Path, msg.Keys)
		m.tree.SetChildren(msg.Path, keyNodes)
		m.tree.SetLoading(msg.Path, false)
		return m, nil

	case component.TreeKeySelectMsg:
		// Navigate to key details view
		log.Printf("[DEBUG] Browser received TreeKeySelectMsg: SecretPath=%q, KeyName=%q", msg.SecretPath, msg.KeyName)
		return m, func() tea.Msg {
			log.Printf("[DEBUG] Browser returning KeyDetailsOpenMsg")
			return KeyDetailsOpenMsg{
				SecretPath: msg.SecretPath,
				KeyName:    msg.KeyName,
			}
		}

	// Search messages
	case component.SearchQueryMsg:
		return m.updateSearchMatches(msg)

	case component.SearchCancelMsg:
		m.searchActive = false
		m.tree.ClearSearch()
		return m, nil

	case component.SearchConfirmMsg:
		m.searchActive = false
		// Keep matches highlighted but blur input
		return m, nil

	case component.SearchBlurMsg:
		// Tab pressed in search - keep search active but blur to allow tree navigation
		// searchActive stays true so Tab can refocus
		return m, nil

	case component.SearchToggleModeMsg:
		m.tree.SetSearchState(m.search.State())
		m.tree.ApplyFilter()
		return m, nil

	// Path prefetch messages
	case adapter.PathPrefetchCompleteMsg:
		log.Printf("[DEBUG] PathPrefetchCompleteMsg received: mount=%s, paths=%d", msg.MountPath, len(msg.Paths))
		m.tree.SetCacheLoading(msg.MountPath, false)
		m.tree.SetPathCache(msg.MountPath, msg.Paths)

		// Re-run search if active to include newly cached paths
		if m.search.IsActive() && m.search.Query() != "" {
			log.Printf("[DEBUG] Re-running search with query: %s", m.search.Query())
			return m.updateSearchMatches(component.SearchQueryMsg{
				Query:       m.search.Query(),
				PatternType: m.search.State().PatternType,
			})
		}
		return m, nil

	case adapter.PathPrefetchErrorMsg:
		log.Printf("[DEBUG] PathPrefetchErrorMsg received: mount=%s, err=%v", msg.MountPath, msg.Err)
		m.tree.SetCacheLoading(msg.MountPath, false)
		// Log the error but don't fail - search will still work with loaded paths
		// Only show warning if there's no existing message (don't overwrite success messages)
		if m.message == "" {
			m.message = fmt.Sprintf("Warning: could not prefetch paths for %s", msg.MountPath)
			m.messageIsError = false
		}
		return m, nil

	case NewItemCreatedMsg:
		m.showNewItemForm = false
		m.message = msg.Message
		m.messageIsError = false
		m.loading = true
		// Store the path to select after tree refresh
		m.pendingSelectPath = msg.Path
		// Refresh the tree to show the new item
		return m, m.loadRoot()

	case component.CertViewerCloseMsg:
		m.showCertView = false
		// Ensure search state is preserved when returning from cert viewer
		if m.search.IsActive() {
			m.searchActive = true // Ensure this flag is also set
			m.tree.SetSearchState(m.search.State())
			m.tree.ApplyFilter()
		}
		return m, nil

	case tea.KeyMsg:
		// Handle certificate viewer input when visible
		if m.showCertView {
			var cmd tea.Cmd
			m.certViewer, cmd = m.certViewer.Update(msg)
			return m, cmd
		}
		// Handle input when creating new item
		if m.showNewItemForm {
			return m.handleNewItemInput(msg)
		}

		// Handle search input when search is active
		if m.searchActive && m.search.IsFocused() {
			var cmd tea.Cmd
			m.search, cmd = m.search.Update(msg)
			return m, cmd
		}

		switch {
		// Search keybindings
		case key.Matches(msg, m.keys.Search):
			m.searchActive = true
			return m, m.search.Focus()

		case key.Matches(msg, m.keys.SearchNext):
			if m.search.HasMatches() {
				m.search.NextMatch()
				m.tree.NavigateToMatch(m.search.CurrentMatchIndex())
			}
			return m, nil

		case key.Matches(msg, m.keys.SearchPrev):
			if m.search.HasMatches() {
				m.search.PrevMatch()
				m.tree.NavigateToMatch(m.search.CurrentMatchIndex())
			}
			return m, nil

		case msg.String() == "tab":
			// Tab switches focus between search input and results
			if m.searchActive && !m.search.IsFocused() {
				return m, m.search.Focus()
			}

		case key.Matches(msg, m.keys.Back):
			// If search is active, clear it first
			if m.search.IsActive() {
				m.search.Reset()
				m.tree.ClearSearch()
				m.searchActive = false
				return m, nil
			}
			return m, func() tea.Msg {
				return BackToTargetsMsg{}
			}

		case key.Matches(msg, m.keys.Refresh):
			m.loading = true
			return m, m.loadRoot()

		case key.Matches(msg, m.keys.Copy):
			if node := m.tree.SelectedNode(); node != nil && node.IsSecret {
				return m, func() tea.Msg {
					return CopySecretMsg{Path: node.Path}
				}
			}

		case key.Matches(msg, m.keys.Edit):
			if node := m.tree.SelectedNode(); node != nil && node.IsSecret {
				return m, func() tea.Msg {
					return EditSecretMsg{Path: node.Path}
				}
			}

		case key.Matches(msg, m.keys.Delete):
			if node := m.tree.SelectedNode(); node != nil {
				return m, func() tea.Msg {
					return DeleteSecretMsg{
						Path:     node.Path,
						IsDir:    node.IsDir,
						IsSecret: node.IsSecret,
						IsKey:    node.IsKey,
						KeyName:  node.KeyName,
					}
				}
			}

		case key.Matches(msg, m.keys.NewSecret):
			m.startNewItem(NewItemSecret)
			return m, textinput.Blink

		case key.Matches(msg, m.keys.NewPath):
			m.startNewItem(NewItemPath)
			return m, textinput.Blink

		case key.Matches(msg, m.keys.ExpandAll):
			// Expand all children under selected node recursively
			var basePath string
			if node := m.tree.SelectedNode(); node != nil {
				if node.IsDir || node.IsSecret {
					basePath = node.Path
				}
			} else {
				// No selection - expand from root
				basePath = "/"
			}
			if basePath != "" {
				m.expandAllBase = basePath // Track that we're doing expand-all
				return m.expandAllUnder(basePath)
			}
		}

		// Forward to tree
		var cmd tea.Cmd
		m.tree, cmd = m.tree.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}

		// Preview selected secret
		if node := m.tree.SelectedNode(); node != nil && node.IsSecret {
			cmds = append(cmds, m.loadSecret(node.Path))
		}
	}

	return m, tea.Batch(cmds...)
}

// loadChildren loads children for a path
func (m *BrowserModel) loadChildren(path string) tea.Cmd {
	return func() tea.Msg {
		children, err := m.treeAdapter.LoadChildren(path)
		if err != nil {
			return BrowserErrorMsg{Err: err}
		}
		return TreeChildrenLoadedMsg{Path: path, Children: children}
	}
}

// expandAllUnder expands all nodes under the given path recursively
func (m BrowserModel) expandAllUnder(basePath string) (BrowserModel, tea.Cmd) {
	var cmds []tea.Cmd
	expandedPaths := make(map[string]bool)

	// Handle root case - expand all mount points
	isRoot := basePath == "/" || basePath == ""
	normalizedBase := strings.TrimSuffix(strings.TrimPrefix(basePath, "/"), "/")

	// Get all paths from cache
	caches := m.tree.GetAllPathCaches()

	// Collect all paths to expand from the cache
	var pathsToExpand []string

	if isRoot {
		// For root, expand everything in all caches
		for _, paths := range caches {
			for _, p := range paths {
				// Extract just the path part (not :key)
				pathPart := p
				if idx := strings.LastIndex(p, ":"); idx > 0 {
					pathPart = p[:idx]
				}
				pathsToExpand = append(pathsToExpand, pathPart)
			}
		}
		// Also expand root's direct children (mount points)
		if root := m.tree.GetRoot(); root != nil {
			for _, child := range root.Children {
				childPath := strings.TrimSuffix(child.Path, "/")
				pathsToExpand = append(pathsToExpand, childPath)
			}
		}
	} else {
		// For non-root, find paths under this base
		for _, paths := range caches {
			for _, p := range paths {
				// Normalize the cached path for comparison
				normalizedP := strings.TrimPrefix(p, "/")
				// Extract path part without :key
				pathPart := normalizedP
				if idx := strings.LastIndex(normalizedP, ":"); idx > 0 {
					pathPart = normalizedP[:idx]
				}

				// Check if this path is under our base path
				if pathPart == normalizedBase || strings.HasPrefix(pathPart, normalizedBase+"/") {
					pathsToExpand = append(pathsToExpand, pathPart)
				}
			}
		}
	}

	// If we have cached paths, expand them all
	for _, path := range pathsToExpand {
		// Build all ancestor paths and expand them
		parts := strings.Split(strings.Trim(path, "/"), "/")
		current := ""
		for i := 0; i < len(parts); i++ {
			if i == 0 {
				current = parts[0]
			} else {
				current = current + "/" + parts[i]
			}

			if !expandedPaths[current] {
				m.tree.Expand(current)
				m.tree.Expand(current + "/")
				expandedPaths[current] = true

				// Check if this node needs loading
				node := m.tree.FindNodeByPath(current)
				if node == nil {
					node = m.tree.FindNodeByPath(current + "/")
				}
				if node != nil && !node.Loaded && !node.Loading && node.IsDir {
					cmds = append(cmds, m.loadChildren(node.Path))
				}
			}
		}
	}

	// Now expand all currently visible nodes recursively (for nodes without cache)
	m.expandVisibleNodesRecursive(basePath, isRoot, expandedPaths, &cmds)

	if len(cmds) > 0 {
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

// expandVisibleNodesRecursive expands all visible nodes under the given path
func (m *BrowserModel) expandVisibleNodesRecursive(basePath string, isRoot bool, expanded map[string]bool, cmds *[]tea.Cmd) {
	normalizedBase := strings.TrimSuffix(strings.TrimPrefix(basePath, "/"), "/")

	// Walk through all visible nodes and expand directories and secrets
	for _, node := range m.tree.AllNodes() {
		if node == nil || (!node.IsDir && !node.IsSecret) {
			continue
		}

		nodePath := strings.TrimSuffix(strings.TrimPrefix(node.Path, "/"), "/")

		// Check if this node is under our base path
		isUnder := isRoot || nodePath == normalizedBase || strings.HasPrefix(nodePath, normalizedBase+"/")
		if !isUnder {
			continue
		}

		// Expand this node if not already
		if !expanded[nodePath] {
			m.tree.Expand(node.Path)
			expanded[nodePath] = true

			// Load children/keys if needed
			if !node.Loaded && !node.Loading {
				if node.IsDir {
					*cmds = append(*cmds, m.loadChildren(node.Path))
				} else if node.IsSecret {
					// Secrets need loadSecretKeys, not loadChildren
					*cmds = append(*cmds, m.loadSecretKeys(node.Path))
				}
			}
		}
	}
}

// loadSecret loads a secret for preview
func (m *BrowserModel) loadSecret(path string) tea.Cmd {
	return func() tea.Msg {
		secret, err := m.vault.Read(path)
		if err != nil {
			return BrowserErrorMsg{Err: err}
		}
		return SecretPreviewMsg{Path: path, Secret: secret}
	}
}

// loadSecretKeys loads keys for a secret to expand it in the tree
func (m *BrowserModel) loadSecretKeys(path string) tea.Cmd {
	return func() tea.Msg {
		keys, err := m.treeAdapter.LoadSecretKeys(path)
		if err != nil {
			return BrowserErrorMsg{Err: err}
		}
		return SecretKeysLoadedMsg{Path: path, Keys: keys}
	}
}

// prefetchAllPaths starts an async prefetch of all paths under a mount
func (m *BrowserModel) prefetchAllPaths(mountPath string) tea.Cmd {
	// Normalize path - ConstructSecrets expects path without trailing slash
	normalizedPath := strings.TrimSuffix(mountPath, "/")
	return adapter.PrefetchAllPathsCmd(m.vault, normalizedPath, true) // true = include keys
}

// updateSearchMatches updates the search matches based on the query
func (m BrowserModel) updateSearchMatches(msg component.SearchQueryMsg) (BrowserModel, tea.Cmd) {
	log.Printf("[DEBUG] updateSearchMatches called: query=%q, patternType=%v", msg.Query, msg.PatternType)
	if msg.Query == "" {
		m.search.SetMatches(nil)
		m.search.ClearError()
		m.tree.ClearSearch()
		return m, nil
	}

	// Get all searchable paths from the entire tree (including cached paths from prefetch)
	allPaths := m.tree.AllSearchablePaths()
	log.Printf("[DEBUG] AllSearchablePaths returned %d paths", len(allPaths))

	// Find matching paths
	matchedPaths, errMsg := component.MatchPaths(allPaths, msg.Query, msg.PatternType)
	log.Printf("[DEBUG] MatchPaths returned %d matches, errMsg=%q", len(matchedPaths), errMsg)

	if errMsg != "" {
		m.search.SetError(errMsg)
		m.search.SetMatches(nil)
		m.tree.ClearSearch()
		return m, nil
	}

	m.search.ClearError()

	// Store matched paths on tree for filter mode
	m.tree.SetMatchedPaths(matchedPaths)
	log.Printf("[DEBUG] SetMatchedPaths called with %d paths", len(matchedPaths))

	// Map matched paths back to visible node indices for jump mode
	matchedPathSet := make(map[string]bool)
	for _, p := range matchedPaths {
		matchedPathSet[p] = true
	}

	// In jump mode, auto-expand to reveal the first match if it's not visible
	var cmds []tea.Cmd
	searchMode := m.search.State().Mode
	log.Printf("[DEBUG] Search mode: %v, matchedPaths count: %d", searchMode, len(matchedPaths))
	if searchMode == component.SearchModeJump && len(matchedPaths) > 0 {
		// Check if first match is currently visible
		visibleNodes := m.tree.AllNodes()
		firstMatchVisible := false
		for _, node := range visibleNodes {
			nodePath := m.tree.GetFullSearchPath(node)
			if matchedPathSet[nodePath] {
				firstMatchVisible = true
				break
			}
		}

		// If first match is not visible, expand to it
		if !firstMatchVisible {
			needsLoading := m.tree.ExpandToPath(matchedPaths[0])
			// Queue loading commands for nodes that need to be loaded
			for _, path := range needsLoading {
				cmds = append(cmds, m.loadChildren(path))
			}
		}
	}

	visibleNodes := m.tree.AllNodes()
	visibleMatches := make([]int, 0)

	// In jump mode, highlight nodes whose NAME matches the search query
	// (not just nodes whose full path is in the matched set)
	for i, node := range visibleNodes {
		nodePath := m.tree.GetFullSearchPath(node)
		// Check if full path matches OR if node name contains search term
		nameMatches := false
		if searchMode == component.SearchModeJump && msg.Query != "" {
			nodeName := node.Name
			if node.IsKey {
				nodeName = node.KeyName
			}
			// Simple case-insensitive contains check for jump mode highlighting
			nameMatches = strings.Contains(strings.ToLower(nodeName), strings.ToLower(msg.Query))
		}
		if matchedPathSet[nodePath] || nameMatches {
			visibleMatches = append(visibleMatches, i)
		}
	}

	m.search.SetMatches(visibleMatches)
	m.tree.SetSearchState(m.search.State())
	log.Printf("[DEBUG] Before ApplyFilter: visibleMatches=%d", len(visibleMatches))
	m.tree.ApplyFilter()

	// After filter is applied, recalculate visible matches
	if m.search.State().Mode == component.SearchModeFilter {
		log.Printf("[DEBUG] Filter mode: recalculating visible matches")
		// In filter mode, refresh matches based on new filtered nodes
		visibleNodes = m.tree.AllNodes()
		log.Printf("[DEBUG] Filter mode: visibleNodes after ApplyFilter=%d", len(visibleNodes))
		visibleMatches = make([]int, 0)
		for i, node := range visibleNodes {
			nodePath := m.tree.GetFullSearchPath(node)
			if matchedPathSet[nodePath] {
				visibleMatches = append(visibleMatches, i)
			}
		}
		log.Printf("[DEBUG] Filter mode: final visibleMatches=%d", len(visibleMatches))
		m.search.SetMatches(visibleMatches)
		m.tree.SetSearchState(m.search.State())
	}

	// Navigate to first match if any
	if len(visibleMatches) > 0 {
		m.tree.NavigateToMatch(0)
	}
	log.Printf("[DEBUG] updateSearchMatches complete: returning with %d cmds", len(cmds))

	if len(cmds) > 0 {
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

// SetSize sets the browser dimensions
func (m *BrowserModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.updateLayout()
}

// updateLayout updates component sizes based on window size
func (m *BrowserModel) updateLayout() {
	// Tree uses full width (minus borders)
	treeWidth := m.width - 4 // -4 for borders
	m.tree.SetSize(treeWidth, m.height-6) // -6 for header/footer
}

// startNewItem initializes the new item creation flow
func (m *BrowserModel) startNewItem(itemType NewItemType) {
	m.showNewItemForm = true
	m.newItemType = itemType
	m.newItemStep = 0
	m.message = ""
	m.messageIsError = false

	// Capture the parent path NOW based on current selection
	m.newItemParentPath = m.getParentPath()

	// Reset inputs
	m.newItemInput.Reset()
	m.newKeyInput.Reset()
	m.newValueInput.Reset()

	// Set appropriate placeholder based on type
	if itemType == NewItemPath {
		m.newItemInput.Placeholder = "path name (e.g., myapp)"
	} else {
		m.newItemInput.Placeholder = "secret name (e.g., credentials)"
	}

	m.newItemInput.Focus()
}

// handleNewItemInput handles keyboard input during new item creation
func (m BrowserModel) handleNewItemInput(msg tea.KeyMsg) (BrowserModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case "esc":
		// Cancel the operation
		m.showNewItemForm = false
		m.newItemStep = 0
		return m, nil

	case "enter":
		return m.advanceNewItemStep()

	case "tab", "shift+tab":
		// Tab between fields for secrets
		if m.newItemType == NewItemSecret && m.newItemStep > 0 {
			if msg.String() == "tab" {
				if m.newItemStep == 1 {
					m.newItemStep = 2
					m.newKeyInput.Blur()
					m.newValueInput.Focus()
				}
			} else {
				if m.newItemStep == 2 {
					m.newItemStep = 1
					m.newValueInput.Blur()
					m.newKeyInput.Focus()
				}
			}
			return m, nil
		}
	}

	// Update the active input
	switch m.newItemStep {
	case 0:
		m.newItemInput, cmd = m.newItemInput.Update(msg)
	case 1:
		m.newKeyInput, cmd = m.newKeyInput.Update(msg)
	case 2:
		m.newValueInput, cmd = m.newValueInput.Update(msg)
	}

	return m, cmd
}

// advanceNewItemStep moves to the next step or creates the item
func (m BrowserModel) advanceNewItemStep() (BrowserModel, tea.Cmd) {
	switch m.newItemType {
	case NewItemPath:
		// Create path immediately after name is entered
		name := strings.TrimSpace(m.newItemInput.Value())
		if name == "" {
			m.message = "Path name cannot be empty"
			m.messageIsError = true
			return m, nil
		}
		return m, m.createNewPath(name)

	case NewItemSecret:
		switch m.newItemStep {
		case 0:
			// Move to key input (or value if key provided in name via colon)
			name := strings.TrimSpace(m.newItemInput.Value())
			if name == "" {
				m.message = "Secret name cannot be empty"
				m.messageIsError = true
				return m, nil
			}

			// Check if name contains colon (path:key syntax)
			if colonIdx := strings.LastIndex(name, ":"); colonIdx >= 0 {
				keyPart := strings.TrimSpace(name[colonIdx+1:])
				if keyPart == "" {
					m.message = "Key after colon cannot be empty"
					m.messageIsError = true
					return m, nil
				}
				// Pre-fill key and skip to value input
				m.newKeyInput.SetValue(keyPart)
				m.newItemStep = 2
				m.newItemInput.Blur()
				m.newValueInput.Focus()
				return m, textinput.Blink
			}

			m.newItemStep = 1
			m.newItemInput.Blur()
			m.newKeyInput.Focus()
			return m, textinput.Blink

		case 1:
			// Move to value input
			key := strings.TrimSpace(m.newKeyInput.Value())
			if key == "" {
				m.message = "Key cannot be empty"
				m.messageIsError = true
				return m, nil
			}
			m.newItemStep = 2
			m.newKeyInput.Blur()
			m.newValueInput.Focus()
			return m, textinput.Blink

		case 2:
			// Create the secret
			name := strings.TrimSpace(m.newItemInput.Value())
			key := strings.TrimSpace(m.newKeyInput.Value())
			value := m.newValueInput.Value() // Don't trim value, might have intentional whitespace
			return m, m.createNewSecret(name, key, value)
		}
	}

	return m, nil
}

// getParentPath returns the parent path for new items
func (m *BrowserModel) getParentPath() string {
	node := m.tree.SelectedNode()
	if node == nil {
		return "secret/"
	}

	// If it's a directory, use it directly
	if node.IsDir {
		path := node.Path
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		return path
	}

	// Otherwise, get the parent directory
	path := node.Path
	if idx := strings.LastIndex(strings.TrimSuffix(path, "/"), "/"); idx >= 0 {
		return path[:idx+1]
	}
	return "secret/"
}

// IsTextInputActive returns true if the browser has an active text input
func (m *BrowserModel) IsTextInputActive() bool {
	return m.showNewItemForm || (m.searchActive && m.search.IsFocused())
}

// createNewPath creates a new path in vault
func (m *BrowserModel) createNewPath(name string) tea.Cmd {
	parentPath := m.newItemParentPath // Use captured parent path
	newPath := parentPath + name

	return func() tea.Msg {
		// In Vault, paths are created implicitly when you write a secret
		// So we create an empty placeholder secret to establish the path
		// We'll create a path marker that indicates this is a directory
		fullPath := newPath
		if !strings.HasSuffix(fullPath, "/") {
			fullPath += "/"
		}
		// Create a .path-created marker to establish the path
		markerPath := fullPath + ".path-created"

		secret := vault.NewSecret()
		_ = secret.Set("created", "true", false)

		err := m.vault.Write(markerPath, secret)
		if err != nil {
			return BrowserErrorMsg{Err: err}
		}

		return NewItemCreatedMsg{
			Path:    newPath,
			Message: "Created path: " + newPath,
		}
	}
}

// createNewSecret creates a new secret in vault
// Supports path syntax in name:
//   - "a/b/c:d" → secret at 'parent/a/b/c' with key 'd'
//   - "a/b/c" (no colon) → secret at 'parent/a/b/c'
func (m *BrowserModel) createNewSecret(name, key, value string) tea.Cmd {
	parentPath := m.newItemParentPath // Use captured parent path
	secretPath := name

	// Check for colon delimiter (path:key syntax)
	// The key is already extracted and passed as parameter
	if colonIdx := strings.LastIndex(name, ":"); colonIdx >= 0 {
		secretPath = name[:colonIdx]
	}

	newPath := parentPath + secretPath

	return func() tea.Msg {
		secret := vault.NewSecret()
		_ = secret.Set(key, value, false)

		err := m.vault.Write(newPath, secret)
		if err != nil {
			return BrowserErrorMsg{Err: err}
		}

		return NewItemCreatedMsg{
			Path:    newPath,
			Message: "Created secret: " + newPath,
		}
	}
}

// navigateToPath expands the tree to show the given path and selects it
func (m *BrowserModel) navigateToPath(targetPath string) tea.Cmd {
	// Expand all parent nodes to make the target visible
	needsLoading := m.tree.ExpandToPath(targetPath)

	// If paths need loading, load them
	if len(needsLoading) > 0 {
		// Store the path to select after loading completes
		m.pendingSelectPath = targetPath

		// Load paths - use appropriate loader based on node type
		cmds := make([]tea.Cmd, 0, len(needsLoading))
		for _, path := range needsLoading {
			node := m.tree.FindNodeByPath(path)
			if node != nil {
				if node.IsDir {
					cmds = append(cmds, m.loadChildren(path))
				} else if node.IsSecret {
					// Secrets need loadSecretKeys, not loadChildren
					cmds = append(cmds, m.loadSecretKeys(path))
				}
			} else {
				// Node not found yet, try loadChildren as fallback
				cmds = append(cmds, m.loadChildren(path))
			}
		}
		return tea.Batch(cmds...)
	}

	// All paths loaded, try to select
	m.tree.SelectPath(targetPath)
	return nil
}

// View renders the browser
func (m BrowserModel) View() string {
	if m.loading {
		return m.renderLoading()
	}

	if m.err != nil {
		return m.renderError()
	}

	// Show certificate viewer overlay if active
	if m.showCertView {
		return m.certViewer.View()
	}

	return m.renderBrowser()
}

func (m BrowserModel) renderLoading() string {
	loadingStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)
	return loadingStyle.Render("  Loading vault contents...")
}

func (m BrowserModel) renderError() string {
	errorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F38BA8"))
	return errorStyle.Render("  Error: " + m.err.Error())
}

func (m BrowserModel) renderBrowser() string {
	var s strings.Builder

	// Header
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7C6FE0")).
		Bold(true)

	s.WriteString(headerStyle.Render("PATH BROWSER"))
	s.WriteString("  ")

	targetStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#89B4FA"))
	s.WriteString(targetStyle.Render("[" + m.target + "]"))
	s.WriteString("\n")
	dividerWidth := m.width - 2
	if dividerWidth < 1 {
		dividerWidth = 1
	}
	s.WriteString(strings.Repeat("─", dividerWidth))
	s.WriteString("\n")

	// Show message if any
	if m.message != "" {
		var msgStyle lipgloss.Style
		if m.messageIsError {
			msgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F38BA8"))
		} else {
			msgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#A6E3A1"))
		}
		s.WriteString(msgStyle.Render(m.message))
		s.WriteString("\n")
	}

	// Show new item form if active
	if m.showNewItemForm {
		s.WriteString(m.renderNewItemForm())
		return s.String()
	}

	// Show search bar if active
	if m.searchActive || m.search.HasMatches() {
		s.WriteString(m.search.ViewWithStatus())
		s.WriteString("\n")
	}

	// Tree uses full width
	treeWidth := m.width - 4 // -4 for borders
	if treeWidth < 10 {
		treeWidth = 10
	}
	treeHeight := m.height - 6
	if treeHeight < 3 {
		treeHeight = 3
	}

	// Update tree size for current layout
	m.tree.SetSize(treeWidth-2, treeHeight-2) // -2 for borders

	// Tree pane (full width)
	treePane := lipgloss.NewStyle().
		Width(treeWidth).
		Height(treeHeight).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#45475A"))

	treeContent := m.tree.View()
	s.WriteString(treePane.Render(treeContent))
	s.WriteString("\n")

	// Help hints - context aware
	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086"))
	loadingStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#F9E2AF")).
		Italic(true)

	var hints string
	if m.searchActive && m.search.IsFocused() {
		hints = "[Tab] results  [Enter] confirm  [Esc] cancel  [Ctrl+F] filter  [Ctrl+R] regex"
	} else if m.searchActive && !m.search.IsFocused() {
		hints = fmt.Sprintf("[Tab] search  [n/N] next/prev (%d/%d)  [j/k] navigate  [Esc] clear",
			m.search.CurrentMatch()+1, m.search.MatchCount())
	} else if m.search.HasMatches() {
		hints = fmt.Sprintf("[n/N] next/prev (%d/%d)  [/] search  [Esc] clear  [j/k] navigate",
			m.search.CurrentMatchIndex()+1, m.search.MatchCount())
	} else {
		hints = "[j/k] navigate  [/] search  [Enter] select  [a] add secret  [e] edit  [Esc] back"
	}

	// Show loading indicator if paths are being prefetched
	if m.tree.AnyCacheLoading() {
		hints += loadingStyle.Render("  [Loading paths...]")
	}
	s.WriteString(hintStyle.Render(hints))

	return s.String()
}

// renderNewItemForm renders the form for creating a new item
func (m BrowserModel) renderNewItemForm() string {
	var s strings.Builder

	// Form container style
	formStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#7C6FE0")).
		Padding(1, 2).
		Width(50)

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#A6ADC8")).
		Bold(true)

	inputLabelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#CDD6F4")).
		Width(10)

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Italic(true)

	var formContent strings.Builder

	// Title
	if m.newItemType == NewItemPath {
		formContent.WriteString(labelStyle.Render("NEW PATH"))
	} else {
		formContent.WriteString(labelStyle.Render("NEW SECRET"))
	}
	formContent.WriteString("\n")
	formContent.WriteString(strings.Repeat("─", 46))
	formContent.WriteString("\n\n")

	// Parent path info (use captured path from when form opened)
	formContent.WriteString(hintStyle.Render("Parent: " + m.newItemParentPath))
	formContent.WriteString("\n\n")

	// Name input (always shown)
	formContent.WriteString(inputLabelStyle.Render("Name:"))
	formContent.WriteString(m.newItemInput.View())
	formContent.WriteString("\n")

	// Key and value inputs for secrets
	if m.newItemType == NewItemSecret && m.newItemStep >= 1 {
		formContent.WriteString("\n")
		formContent.WriteString(inputLabelStyle.Render("Key:"))
		formContent.WriteString(m.newKeyInput.View())
		formContent.WriteString("\n")

		if m.newItemStep >= 2 {
			formContent.WriteString("\n")
			formContent.WriteString(inputLabelStyle.Render("Value:"))
			formContent.WriteString(m.newValueInput.View())
			formContent.WriteString("\n")
		}
	}

	// Instructions
	formContent.WriteString("\n")
	if m.newItemType == NewItemPath {
		formContent.WriteString(hintStyle.Render("[Enter] Create  [Esc] Cancel"))
	} else {
		switch m.newItemStep {
		case 0:
			formContent.WriteString(hintStyle.Render("[Enter] Next  [Esc] Cancel"))
		case 1:
			formContent.WriteString(hintStyle.Render("[Enter] Next  [Esc] Cancel"))
		case 2:
			formContent.WriteString(hintStyle.Render("[Enter] Create  [Tab] Switch field  [Esc] Cancel"))
		}
	}

	s.WriteString(formStyle.Render(formContent.String()))
	return s.String()
}

// Helper functions

// isMountPoint checks if a path is a top-level mount point
func isMountPoint(path string) bool {
	// Mount points are top-level paths like "secret/", "database/"
	// They don't contain "/" after trimming the trailing slash
	trimmed := strings.TrimSuffix(path, "/")
	return !strings.Contains(trimmed, "/")
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	sensitiveWords := []string{"password", "secret", "token", "key", "credential", "auth", "private"}
	for _, word := range sensitiveWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SelectedNode returns the currently selected tree node
func (m *BrowserModel) SelectedNode() *component.TreeNode {
	return m.tree.SelectedNode()
}

// SelectedKeyInfo returns info about the currently selected key, if any
// Returns (secretPath, keyName, keyValue, hasSelection)
func (m *BrowserModel) SelectedKeyInfo() (string, string, string, bool) {
	// Check if the currently highlighted node is a key
	if node := m.tree.SelectedNode(); node != nil && node.IsKey {
		// We have the key name but not the value (not loaded yet)
		// Return what we have - caller may need to load the value
		return node.Path, node.KeyName, "", true
	}
	return "", "", "", false
}

// HasSelectedKey returns true if a specific key is currently selected
func (m *BrowserModel) HasSelectedKey() bool {
	if node := m.tree.SelectedNode(); node != nil && node.IsKey {
		return true
	}
	return false
}

// SelectedPath returns the path of the selected node
func (m *BrowserModel) SelectedPath() string {
	if node := m.tree.SelectedNode(); node != nil {
		return node.Path
	}
	return ""
}

// SelectedPathWithKey returns the path in path:key format if a key is selected
func (m *BrowserModel) SelectedPathWithKey() string {
	if node := m.tree.SelectedNode(); node != nil {
		if node.IsKey {
			return node.Path + ":" + node.KeyName
		}
		return node.Path
	}
	return ""
}

// SetPendingSelectPath sets the path to navigate to after the next tree refresh
func (m *BrowserModel) SetPendingSelectPath(path string) {
	m.pendingSelectPath = path
}

// SetMessage sets the browser's message line
func (m *BrowserModel) SetMessage(msg string, isError bool) {
	m.message = msg
	m.messageIsError = isError
}

// Messages

// TreeRootLoadedMsg is sent when the root tree is loaded
type TreeRootLoadedMsg struct {
	Root *component.TreeNode
}

// TreeChildrenLoadedMsg is sent when children are loaded
type TreeChildrenLoadedMsg struct {
	Path     string
	Children []*component.TreeNode
}

// SecretPreviewMsg is sent when a secret is loaded for preview
type SecretPreviewMsg struct {
	Path   string
	Secret *vault.Secret
}

// BrowserErrorMsg is sent when an error occurs
type BrowserErrorMsg struct {
	Err error
}

// BackToTargetsMsg is sent to go back to targets view
type BackToTargetsMsg struct{}

// CopySecretMsg is sent when copying a secret
type CopySecretMsg struct {
	Path string
}

// EditSecretMsg is sent when editing a secret
type EditSecretMsg struct {
	Path string
}

// DeleteSecretMsg is sent when deleting a secret or path
type DeleteSecretMsg struct {
	Path     string
	IsDir    bool   // true if this is a directory/folder
	IsSecret bool   // true if this is a secret
	IsKey    bool   // true if this is a specific key within a secret
	KeyName  string // the key name if IsKey is true
}

// NewItemCreatedMsg is sent when a new path or secret is created
type NewItemCreatedMsg struct {
	Path    string
	Message string
}

// SecretKeysLoadedMsg is sent when secret keys are loaded
type SecretKeysLoadedMsg struct {
	Path string
	Keys []string
}

// KeyPreviewMsg is sent when a key's value is loaded for preview
type KeyPreviewMsg struct {
	SecretPath string
	KeyName    string
	Value      string
	Versions   []KeyVersion
	IsKVv2     bool
}
