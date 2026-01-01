package component

import (
	"log"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TreeNode represents a node in the tree
type TreeNode struct {
	Path     string
	Name     string
	IsDir    bool
	IsSecret bool
	IsKey    bool   // true if this node represents a key within a secret
	KeyName  string // the key name (for constructing path:key)
	Children []*TreeNode
	Loaded   bool
	Loading  bool
	Keys     []string
	Level    int
}

// Tree is a tree browser component
type Tree struct {
	root     *TreeNode
	nodes    []*TreeNode // Flattened visible nodes
	cursor   int
	expanded map[string]bool
	selected string
	width    int
	height   int
	offset   int // Scroll offset
	keys     treeKeyMap

	// Mouse support
	viewportY      int       // Y offset of tree in parent viewport (for mouse coordinate mapping)
	lastClickTime  time.Time // For double-click detection
	lastClickIndex int       // Index of last clicked node

	// Styling
	styles TreeStyles

	// Search state
	search        *SearchState
	matchedNodes  map[int]bool    // Quick lookup for matched node indices
	matchedPaths  map[string]bool // All matched paths (for filter mode)
	originalNodes []*TreeNode     // Pre-filter nodes (for filter mode)
	filterActive  bool            // Whether filter mode is currently applied

	// Path cache for deep search (includes unexpanded paths)
	pathCache    map[string][]string // mount path -> all paths under mount
	cacheLoading map[string]bool     // mount path -> is prefetch in progress
}

type treeKeyMap struct {
	Up       key.Binding
	Down     key.Binding
	Expand   key.Binding
	Collapse key.Binding
	Select   key.Binding
	Top      key.Binding
	Bottom   key.Binding
	PageUp   key.Binding
	PageDown key.Binding
}

// TreeStyles contains styles for the tree
type TreeStyles struct {
	Normal      lipgloss.Style
	Directory   lipgloss.Style
	Secret      lipgloss.Style
	Key         lipgloss.Style
	Selected    lipgloss.Style
	Cursor      lipgloss.Style
	Match       lipgloss.Style // Matched node (not cursor)
	MatchCursor lipgloss.Style // Matched node with cursor
}

// DefaultTreeStyles returns default tree styles
func DefaultTreeStyles() TreeStyles {
	return TreeStyles{
		Normal: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CDD6F4")),
		Directory: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#89B4FA")).
			Bold(true),
		Secret: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")),
		Key: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")), // Green for keys
		Selected: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7C6FE0")),
		Cursor: lipgloss.NewStyle().
			Background(lipgloss.Color("#45475A")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true),
		Match: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F9E2AF")).
			Bold(true),
		MatchCursor: lipgloss.NewStyle().
			Background(lipgloss.Color("#F9E2AF")).
			Foreground(lipgloss.Color("#1E1E2E")).
			Bold(true),
	}
}

func defaultTreeKeyMap() treeKeyMap {
	return treeKeyMap{
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
			key.WithHelp("enter/l", "expand"),
		),
		Collapse: key.NewBinding(
			key.WithKeys("h", "left"),
			key.WithHelp("h/←", "collapse"),
		),
		Select: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Top: key.NewBinding(
			key.WithKeys("g"),
			key.WithHelp("g", "go to top"),
		),
		Bottom: key.NewBinding(
			key.WithKeys("G"),
			key.WithHelp("G", "go to bottom"),
		),
		PageUp: key.NewBinding(
			key.WithKeys("ctrl+u", "pgup"),
			key.WithHelp("ctrl+u", "half page up"),
		),
		PageDown: key.NewBinding(
			key.WithKeys("ctrl+d", "pgdown"),
			key.WithHelp("ctrl+d", "half page down"),
		),
	}
}

// NewTree creates a new tree component
func NewTree() Tree {
	return Tree{
		expanded:     make(map[string]bool),
		keys:         defaultTreeKeyMap(),
		styles:       DefaultTreeStyles(),
		width:        40, // Default width
		height:       20, // Default height
		matchedNodes: make(map[int]bool),
		matchedPaths: make(map[string]bool),
		pathCache:    make(map[string][]string),
		cacheLoading: make(map[string]bool),
	}
}

// SetRoot sets the root node of the tree
func (t *Tree) SetRoot(root *TreeNode) {
	t.root = root

	// Clear ALL state to prevent stale data and re-expansion loops
	t.pathCache = make(map[string][]string)
	t.cacheLoading = make(map[string]bool)
	t.expanded = make(map[string]bool)

	// Clear search state - matches may reference deleted nodes
	t.matchedNodes = make(map[int]bool)
	t.matchedPaths = make(map[string]bool)
	t.originalNodes = nil
	t.filterActive = false

	t.refresh()
}

// SetSize sets the dimensions of the tree
func (t *Tree) SetSize(width, height int) {
	t.width = width
	t.height = height
}

// Init initializes the tree
func (t Tree) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (t Tree) Update(msg tea.Msg) (Tree, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		return t.handleMouse(msg)

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, t.keys.Up):
			t.moveUp()

		case key.Matches(msg, t.keys.Down):
			t.moveDown()

		case key.Matches(msg, t.keys.Expand):
			if t.cursor < len(t.nodes) {
				node := t.nodes[t.cursor]
				log.Printf("[DEBUG] Tree Expand: cursor=%d, node.Path=%q, node.Name=%q, IsDir=%v, IsSecret=%v, IsKey=%v, KeyName=%q",
					t.cursor, node.Path, node.Name, node.IsDir, node.IsSecret, node.IsKey, node.KeyName)
				// Check IsKey FIRST since keys should immediately open details (defensive check)
				if node.IsKey {
					// Select the key - opens key details view
					return t, func() tea.Msg {
						return TreeKeySelectMsg{
							SecretPath: node.Path,
							KeyName:    node.KeyName,
						}
					}
				} else if node.IsDir {
					t.expanded[node.Path] = true
					t.refresh()
					// Return a command to load children if not loaded
					if !node.Loaded && !node.Loading {
						return t, func() tea.Msg {
							return TreeExpandMsg{Path: node.Path}
						}
					}
				} else if node.IsSecret {
					// Toggle expansion to show keys, or select if already expanded
					if t.expanded[node.Path] {
						// Already expanded - select the secret
						return t, func() tea.Msg {
							return TreeSelectMsg{Path: node.Path, IsSecret: true}
						}
					}
					t.expanded[node.Path] = true
					t.refresh()
					if !node.Loaded && !node.Loading {
						return t, func() tea.Msg {
							return TreeExpandSecretMsg{Path: node.Path}
						}
					}
				} else {
					// Select the secret (fallback)
					return t, func() tea.Msg {
						return TreeSelectMsg{Path: node.Path, IsSecret: true}
					}
				}
			}

		case key.Matches(msg, t.keys.Collapse):
			if t.cursor < len(t.nodes) {
				node := t.nodes[t.cursor]
				if t.expanded[node.Path] {
					// Collapse this node
					t.expanded[node.Path] = false
					t.refresh()
				} else if node.Level > 0 {
					// Go to parent
					t.goToParent()
				}
			}

		case key.Matches(msg, t.keys.Top):
			t.cursor = 0
			t.offset = 0

		case key.Matches(msg, t.keys.Bottom):
			if len(t.nodes) > 0 {
				t.cursor = len(t.nodes) - 1
				t.ensureVisible()
			}

		case key.Matches(msg, t.keys.PageUp):
			t.cursor -= t.height / 2
			if t.cursor < 0 {
				t.cursor = 0
			}
			t.ensureVisible()

		case key.Matches(msg, t.keys.PageDown):
			t.cursor += t.height / 2
			if t.cursor >= len(t.nodes) {
				t.cursor = len(t.nodes) - 1
			}
			if t.cursor < 0 {
				t.cursor = 0
			}
			t.ensureVisible()
		}
	}

	return t, nil
}

// View renders the tree
func (t Tree) View() string {
	if t.root == nil || len(t.nodes) == 0 {
		mutedStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6C7086")).
			Italic(true)
		return mutedStyle.Render("  Loading...")
	}

	var s strings.Builder

	// Calculate visible range
	visibleHeight := t.height
	if visibleHeight <= 0 {
		visibleHeight = 20
	}

	start := t.offset
	end := start + visibleHeight
	if end > len(t.nodes) {
		end = len(t.nodes)
	}

	for i := start; i < end; i++ {
		node := t.nodes[i]
		line := t.renderNode(node, i, i == t.cursor)
		s.WriteString(line)
		s.WriteString("\n")
	}

	return s.String()
}

// renderNode renders a single tree node
func (t *Tree) renderNode(node *TreeNode, nodeIndex int, isCursor bool) string {
	var s strings.Builder

	// Check if this node is a search match
	isMatch := t.matchedNodes[nodeIndex]

	// Indentation
	indent := strings.Repeat("  ", node.Level)
	s.WriteString(indent)

	// Expansion indicator
	// Check IsKey FIRST since keys should NEVER show arrows (defensive check)
	if node.IsKey {
		s.WriteString("  ") // Keys are indented without icon
	} else if node.IsDir {
		if t.expanded[node.Path] {
			s.WriteString("▼ ")
		} else {
			s.WriteString("▶ ")
		}
	} else if node.IsSecret {
		if t.expanded[node.Path] {
			s.WriteString("▼ ")
		} else {
			s.WriteString("● ")
		}
	} else {
		s.WriteString("  ")
	}

	// Node name
	var name string
	if node.IsKey {
		name = ":" + node.KeyName // Display as :keyname
	} else {
		name = node.Name
		if node.IsDir && !strings.HasSuffix(name, "/") {
			name += "/"
		}
	}

	// Apply style based on cursor and match state
	var style lipgloss.Style
	if isCursor && isMatch {
		style = t.styles.MatchCursor
	} else if isCursor {
		style = t.styles.Cursor
	} else if isMatch {
		style = t.styles.Match
	} else if node.IsDir {
		style = t.styles.Directory
	} else if node.IsSecret {
		style = t.styles.Secret
	} else if node.IsKey {
		style = t.styles.Key
	} else {
		style = t.styles.Normal
	}

	if isCursor {
		// Full line highlight for cursor
		lineContent := s.String() + name
		padding := t.width - lipgloss.Width(lineContent) - 2
		if padding > 0 {
			lineContent += strings.Repeat(" ", padding)
		}
		return style.Render(lineContent)
	}

	s.WriteString(style.Render(name))
	return s.String()
}

// moveUp moves the cursor up
func (t *Tree) moveUp() {
	if t.cursor > 0 {
		t.cursor--
		t.ensureVisible()
	}
}

// moveDown moves the cursor down
func (t *Tree) moveDown() {
	if t.cursor < len(t.nodes)-1 {
		t.cursor++
		t.ensureVisible()
	}
}

// ensureVisible ensures the cursor is within the visible area
func (t *Tree) ensureVisible() {
	if t.cursor < t.offset {
		t.offset = t.cursor
	}
	if t.cursor >= t.offset+t.height {
		t.offset = t.cursor - t.height + 1
	}
	if t.offset < 0 {
		t.offset = 0
	}
}

// goToParent moves to the parent node
func (t *Tree) goToParent() {
	if t.cursor >= len(t.nodes) {
		return
	}

	node := t.nodes[t.cursor]
	if node.Level == 0 {
		return
	}

	// For keys, the parent is the secret node with the same path
	if node.IsKey {
		for i, n := range t.nodes {
			if n.Path == node.Path && n.IsSecret {
				t.cursor = i
				t.ensureVisible()
				return
			}
		}
		return
	}

	// Find parent path
	parts := strings.Split(strings.TrimSuffix(node.Path, "/"), "/")
	if len(parts) <= 1 {
		return
	}
	parentPath := strings.Join(parts[:len(parts)-1], "/")

	// Find parent in nodes
	for i, n := range t.nodes {
		if n.Path == parentPath || n.Path == parentPath+"/" {
			t.cursor = i
			t.ensureVisible()
			return
		}
	}
}

// SetViewportY sets the Y offset of the tree in the parent viewport
// This is used for accurate mouse coordinate mapping
func (t *Tree) SetViewportY(y int) {
	t.viewportY = y
}

// handleMouse handles mouse events
func (t Tree) handleMouse(msg tea.MouseMsg) (Tree, tea.Cmd) {
	switch msg.Type {
	case tea.MouseLeft:
		// Calculate which node was clicked, accounting for viewport offset
		relativeY := msg.Y - t.viewportY
		clickedIndex := t.offset + relativeY

		log.Printf("[DEBUG] Tree click: Y=%d, viewportY=%d, offset=%d, relativeY=%d, clickedIndex=%d, nodeCount=%d",
			msg.Y, t.viewportY, t.offset, relativeY, clickedIndex, len(t.nodes))

		if clickedIndex >= 0 && clickedIndex < len(t.nodes) {
			node := t.nodes[clickedIndex]
			log.Printf("[DEBUG] Tree selecting node: path=%q, name=%q, isDir=%v, isSecret=%v",
				node.Path, node.Name, node.IsDir, node.IsSecret)

			// Detect double-click: same index within 500ms
			now := time.Now()
			isDoubleClick := clickedIndex == t.lastClickIndex && now.Sub(t.lastClickTime) < 500*time.Millisecond
			t.lastClickTime = now
			t.lastClickIndex = clickedIndex

			t.cursor = clickedIndex
			t.ensureVisible()

			// Calculate the X position where the expand/collapse icon is
			// Each level adds 2 spaces of indent, then the icon is 2 chars (▼ or ▶)
			indent := node.Level * 2
			iconStart := indent
			iconEnd := indent + 2

			// Check if click was on expand/collapse icon OR if it was a double-click
			if msg.X >= iconStart && msg.X < iconEnd || isDoubleClick {
				// Toggle expand/collapse
				if node.IsKey {
					// Keys open key details view
					return t, func() tea.Msg {
						return TreeKeySelectMsg{
							SecretPath: node.Path,
							KeyName:    node.KeyName,
						}
					}
				} else if node.IsDir {
					if t.expanded[node.Path] {
						t.expanded[node.Path] = false
						t.refresh()
					} else {
						t.expanded[node.Path] = true
						t.refresh()
						// Return a command to load children if not loaded
						if !node.Loaded && !node.Loading {
							return t, func() tea.Msg {
								return TreeExpandMsg{Path: node.Path}
							}
						}
					}
				} else if node.IsSecret {
					if t.expanded[node.Path] {
						t.expanded[node.Path] = false
						t.refresh()
					} else {
						t.expanded[node.Path] = true
						t.refresh()
						if !node.Loaded && !node.Loading {
							return t, func() tea.Msg {
								return TreeExpandSecretMsg{Path: node.Path}
							}
						}
					}
				}
			}
			// Single click on the node text just selects it (cursor already set above)
		}

	case tea.MouseWheelUp:
		// Scroll up
		t.offset -= 3
		if t.offset < 0 {
			t.offset = 0
		}
		// Keep cursor in view
		if t.cursor >= t.offset+t.height {
			t.cursor = t.offset + t.height - 1
		}

	case tea.MouseWheelDown:
		// Scroll down
		maxOffset := len(t.nodes) - t.height
		if maxOffset < 0 {
			maxOffset = 0
		}
		t.offset += 3
		if t.offset > maxOffset {
			t.offset = maxOffset
		}
		// Keep cursor in view
		if t.cursor < t.offset {
			t.cursor = t.offset
		}
	}

	return t, nil
}

// refresh rebuilds the flattened node list
func (t *Tree) refresh() {
	t.nodes = make([]*TreeNode, 0)
	if t.root != nil {
		t.flattenNode(t.root, 0)
	}

	// Ensure cursor is within valid bounds
	if t.cursor >= len(t.nodes) {
		t.cursor = len(t.nodes) - 1
	}
	if t.cursor < 0 {
		t.cursor = 0
	}

	// Ensure cursor is visible
	t.ensureVisible()
}

// flattenNode recursively flattens the tree
func (t *Tree) flattenNode(node *TreeNode, level int) {
	node.Level = level
	t.nodes = append(t.nodes, node)

	if t.expanded[node.Path] && node.Children != nil {
		for _, child := range node.Children {
			t.flattenNode(child, level+1)
		}
	}
}

// SelectedNode returns the currently selected node
func (t *Tree) SelectedNode() *TreeNode {
	if t.cursor < len(t.nodes) {
		return t.nodes[t.cursor]
	}
	return nil
}

// SelectedPath returns the path of the selected node
func (t *Tree) SelectedPath() string {
	if node := t.SelectedNode(); node != nil {
		return node.Path
	}
	return ""
}

// IsExpanded returns whether a path is expanded
func (t *Tree) IsExpanded(path string) bool {
	return t.expanded[path]
}

// Expand expands a node
func (t *Tree) Expand(path string) {
	t.expanded[path] = true
	t.refresh()
}

// Collapse collapses a node
func (t *Tree) Collapse(path string) {
	t.expanded[path] = false
	t.refresh()
}

// ExpandToPath expands all ancestor paths to reveal a target path
// This is used to auto-expand the tree when navigating to a search match
// Returns a list of paths that need their children loaded
func (t *Tree) ExpandToPath(targetPath string) []string {
	if t.root == nil {
		return nil
	}

	// Handle path:key format - extract just the path part
	pathPart := targetPath
	hasKeyPart := false
	if idx := strings.LastIndex(targetPath, ":"); idx > 0 {
		pathPart = targetPath[:idx]
		hasKeyPart = true
	}

	// Split into segments
	pathPart = strings.Trim(pathPart, "/")
	parts := strings.Split(pathPart, "/")

	needsLoading := make([]string, 0)
	currentNode := t.root
	currentPath := ""

	// Walk through each segment, expanding as we go
	for i := 0; i < len(parts); i++ {
		segment := parts[i]
		if i == 0 {
			currentPath = segment
		} else {
			currentPath = currentPath + "/" + segment
		}

		// Mark as expanded
		t.expanded[currentPath] = true
		t.expanded[currentPath+"/"] = true

		// Try to find this segment in current node's children
		var foundChild *TreeNode
		for _, child := range currentNode.Children {
			childName := strings.TrimSuffix(child.Path, "/")
			// Check if this child matches the current path
			if child.Path == currentPath || child.Path == currentPath+"/" || childName == currentPath {
				foundChild = child
				break
			}
		}

		if foundChild != nil {
			// If this node's children haven't been loaded, we need to load them
			if !foundChild.Loaded && !foundChild.Loading && (foundChild.IsDir || foundChild.IsSecret) {
				needsLoading = append(needsLoading, foundChild.Path)
			}
			currentNode = foundChild
		} else {
			// Child doesn't exist yet - parent needs to be loaded first
			if currentNode.Path != "/" && !currentNode.Loaded && !currentNode.Loading {
				needsLoading = append(needsLoading, currentNode.Path)
			}
			// Can't continue walking - child doesn't exist
			break
		}
	}

	// If targeting a key and we reached the secret, ensure it's expanded and loaded
	// This handles the case where the secret might be marked as loaded but keys weren't fetched
	if hasKeyPart && currentNode != nil && currentNode.IsSecret {
		t.expanded[currentNode.Path] = true
		// If secret has no children (keys), it needs loading even if marked as Loaded
		// This can happen if loadChildren was incorrectly called instead of loadSecretKeys
		if len(currentNode.Children) == 0 && !currentNode.Loading {
			// Check if already in needsLoading to avoid duplicates
			alreadyQueued := false
			for _, p := range needsLoading {
				if p == currentNode.Path {
					alreadyQueued = true
					break
				}
			}
			if !alreadyQueued {
				needsLoading = append(needsLoading, currentNode.Path)
			}
		}
	}

	t.refresh()
	return needsLoading
}

// SetChildren sets the children of a node
func (t *Tree) SetChildren(path string, children []*TreeNode) {
	node := t.findNode(path)
	if node != nil {
		node.Children = children
		node.Loaded = true
		node.Loading = false
		t.refresh()
	}
}

// SetLoading marks a node as loading
func (t *Tree) SetLoading(path string, loading bool) {
	node := t.findNode(path)
	if node != nil {
		node.Loading = loading
	}
}

// findNode finds a node by path
func (t *Tree) findNode(path string) *TreeNode {
	return t.findNodeRecursive(t.root, path)
}

func (t *Tree) findNodeRecursive(node *TreeNode, path string) *TreeNode {
	if node == nil {
		return nil
	}
	if node.Path == path {
		return node
	}
	for _, child := range node.Children {
		if found := t.findNodeRecursive(child, path); found != nil {
			return found
		}
	}
	return nil
}

// Messages

// TreeExpandMsg is sent when a node should be expanded
type TreeExpandMsg struct {
	Path string
}

// TreeSelectMsg is sent when a node is selected
type TreeSelectMsg struct {
	Path     string
	IsSecret bool
}

// TreeCollapseMsg is sent when a node should be collapsed
type TreeCollapseMsg struct {
	Path string
}

// TreeExpandSecretMsg is sent when a secret should be expanded to show its keys
type TreeExpandSecretMsg struct {
	Path string
}

// TreeKeySelectMsg is sent when a key is selected
type TreeKeySelectMsg struct {
	SecretPath string // Path to the secret
	KeyName    string // Name of the selected key
}

// Search-related methods

// SetSearchState updates the search state and rebuilds the matched nodes map
func (t *Tree) SetSearchState(state *SearchState) {
	t.search = state
	t.matchedNodes = make(map[int]bool)

	if state != nil && state.Active && len(state.Matches) > 0 {
		for _, idx := range state.Matches {
			t.matchedNodes[idx] = true
		}
	}
}

// ClearSearch clears the search state
func (t *Tree) ClearSearch() {
	t.search = nil
	t.matchedNodes = make(map[int]bool)
	t.matchedPaths = make(map[string]bool)
	t.filterActive = false

	// Restore original nodes if filter was active
	if t.originalNodes != nil {
		t.nodes = t.originalNodes
		t.originalNodes = nil
	}
}

// SetMatchedPaths sets the paths that matched the search query
func (t *Tree) SetMatchedPaths(paths []string) {
	t.matchedPaths = make(map[string]bool)
	for _, p := range paths {
		t.matchedPaths[p] = true
	}
}

// ApplyFilter filters nodes based on search matches (Filter mode)
func (t *Tree) ApplyFilter() {
	if t.search == nil || !t.search.Active || t.search.Mode != SearchModeFilter {
		// Restore original if filter was previously active
		if t.filterActive && t.originalNodes != nil {
			t.nodes = t.originalNodes
			t.originalNodes = nil
			t.filterActive = false
			// Recalculate match indices for restored nodes
			if t.search != nil && t.search.Active {
				t.recalculateMatches()
			}
		}
		return
	}

	// Store original nodes if not already stored
	if t.originalNodes == nil {
		t.originalNodes = t.nodes
	}

	// Build filtered list including matched nodes and their ancestors
	t.nodes = t.buildFilteredNodes()
	t.filterActive = true

	// Recalculate match indices for filtered nodes
	t.recalculateMatches()

	// Adjust cursor if needed
	if t.cursor >= len(t.nodes) {
		t.cursor = len(t.nodes) - 1
	}
	if t.cursor < 0 {
		t.cursor = 0
	}
	t.ensureVisible()
}

// buildFilteredNodes creates the filtered node list with matched nodes and ancestors
func (t *Tree) buildFilteredNodes() []*TreeNode {
	if len(t.matchedPaths) == 0 {
		return []*TreeNode{}
	}

	// In filter mode, show a flat list of all matched paths with full path names
	// This makes it easy to see exactly what matched
	filtered := make([]*TreeNode, 0, len(t.matchedPaths))

	// Collect all matched paths and sort them
	matchedList := make([]string, 0, len(t.matchedPaths))
	for matchedPath := range t.matchedPaths {
		matchedList = append(matchedList, matchedPath)
	}
	sort.Strings(matchedList)

	for _, matchedPath := range matchedList {
		// Determine what type of node it is
		isKey := strings.Contains(matchedPath, ":")
		pathPart := matchedPath
		keyName := ""
		if isKey {
			idx := strings.LastIndex(matchedPath, ":")
			pathPart = matchedPath[:idx]
			keyName = matchedPath[idx+1:]
		}

		// For filter mode, show the FULL path as the display name
		displayName := matchedPath

		node := &TreeNode{
			Path:     pathPart,
			Name:     displayName, // Full path for filter mode
			IsDir:    false,
			IsSecret: !isKey, // Only true when NOT a key
			IsKey:    isKey,
			KeyName:  keyName,
			Level:    0,    // Flat list - all at level 0
			Loaded:   isKey, // Keys are leaf nodes, mark as loaded; secrets are not loaded
		}

		filtered = append(filtered, node)
	}

	return filtered
}

// collectFilteredNodes recursively collects nodes that should be shown in filter mode
func (t *Tree) collectFilteredNodes(node *TreeNode, level int, includePaths map[string]bool, result *[]*TreeNode, existingPaths map[string]bool) {
	if node == nil {
		return
	}

	// Check if this node or any of its descendants match
	nodePath := t.GetFullSearchPath(node)
	shouldInclude := includePaths[node.Path] || includePaths[nodePath]

	// Also check if this is an ancestor of a match
	if !shouldInclude {
		for matchPath := range includePaths {
			if strings.HasPrefix(matchPath, node.Path) {
				shouldInclude = true
				break
			}
		}
	}

	if shouldInclude && node.Path != "/" {
		node.Level = level
		*result = append(*result, node)
		// Track this path as existing in the tree
		existingPaths[node.Path] = true
		existingPaths[nodePath] = true // Also track full path (path:key format)
	}

	// Always check children for matches
	for _, child := range node.Children {
		childPath := t.GetFullSearchPath(child)
		childMatches := includePaths[child.Path] || includePaths[childPath]

		// Check if any descendant matches
		if !childMatches {
			for matchPath := range includePaths {
				if strings.HasPrefix(matchPath, child.Path) {
					childMatches = true
					break
				}
			}
		}

		if childMatches {
			nextLevel := level
			if node.Path != "/" {
				nextLevel = level + 1
			}
			t.collectFilteredNodes(child, nextLevel, includePaths, result, existingPaths)
		}
	}
}

// recalculateMatches recalculates the matchedNodes map for current node indices
func (t *Tree) recalculateMatches() {
	t.matchedNodes = make(map[int]bool)

	if t.search == nil || len(t.matchedPaths) == 0 {
		return
	}

	// Find matching indices in current nodes using matchedPaths
	newMatches := make([]int, 0)
	for i, node := range t.nodes {
		nodePath := t.GetFullSearchPath(node)
		if t.matchedPaths[nodePath] || t.matchedPaths[node.Path] {
			t.matchedNodes[i] = true
			newMatches = append(newMatches, i)
		}
	}

	// Update search state matches for navigation
	if t.search != nil {
		t.search.Matches = newMatches
		if t.search.MatchCursor >= len(newMatches) {
			t.search.MatchCursor = 0
		}
	}
}

// NavigateToMatch moves cursor to the specified match index
func (t *Tree) NavigateToMatch(matchIndex int) {
	if t.search == nil || len(t.search.Matches) == 0 {
		return
	}

	if matchIndex >= 0 && matchIndex < len(t.search.Matches) {
		nodeIdx := t.search.Matches[matchIndex]
		if nodeIdx < len(t.nodes) {
			t.cursor = nodeIdx
			t.ensureVisible()
		}
	}
}

// SelectPath moves cursor to the node at the specified path
func (t *Tree) SelectPath(targetPath string) bool {
	// Normalize path - remove trailing slash for comparison
	normalizedTarget := strings.TrimSuffix(targetPath, "/")

	// Check if target is a key (path:keyname format)
	var targetKeyName string
	if idx := strings.LastIndex(normalizedTarget, ":"); idx > 0 {
		targetKeyName = normalizedTarget[idx+1:]
		normalizedTarget = normalizedTarget[:idx]
	}

	for i, node := range t.nodes {
		nodePath := strings.TrimSuffix(node.Path, "/")

		// For key nodes, match both path and key name
		if node.IsKey && targetKeyName != "" {
			if nodePath == normalizedTarget && node.KeyName == targetKeyName {
				t.cursor = i
				t.ensureVisible()
				return true
			}
		} else if nodePath == normalizedTarget && targetKeyName == "" {
			t.cursor = i
			t.ensureVisible()
			return true
		}
	}
	return false
}

// GetFullSearchPath returns the full searchable path for a node (path:key format for keys)
func (t *Tree) GetFullSearchPath(node *TreeNode) string {
	if node.IsKey {
		return node.Path + ":" + node.KeyName
	}
	return node.Path
}

// AllNodes returns all currently visible nodes
func (t *Tree) AllNodes() []*TreeNode {
	return t.nodes
}

// AllSearchablePaths returns all searchable paths from the entire tree structure
// This includes paths from the cache (prefetched) and loaded nodes
func (t *Tree) AllSearchablePaths() []string {
	seen := make(map[string]bool)
	paths := make([]string, 0)

	// Add cached paths first (these include all paths from expanded mounts)
	if t.pathCache != nil {
		for _, cachedPaths := range t.pathCache {
			for _, p := range cachedPaths {
				if !seen[p] {
					seen[p] = true
					paths = append(paths, p)
				}
			}
		}
	}

	// Add paths from loaded tree nodes (may include paths not in cache)
	if t.root != nil {
		t.collectAllPathsWithSeen(t.root, &paths, seen)
	}

	return paths
}

// collectAllPathsWithSeen recursively collects paths, skipping already seen ones
func (t *Tree) collectAllPathsWithSeen(node *TreeNode, paths *[]string, seen map[string]bool) {
	if node == nil {
		return
	}

	// Add this node's path (skip root "/" as it's not searchable)
	if node.Path != "/" {
		nodePath := t.GetFullSearchPath(node)
		if !seen[nodePath] {
			seen[nodePath] = true
			*paths = append(*paths, nodePath)
		}
	}

	// Recursively collect from all children, whether expanded or not
	for _, child := range node.Children {
		t.collectAllPathsWithSeen(child, paths, seen)
	}
}

// collectAllPaths recursively collects all paths from the tree structure
func (t *Tree) collectAllPaths(node *TreeNode, paths *[]string) {
	if node == nil {
		return
	}

	// Add this node's path (skip root "/" as it's not searchable)
	if node.Path != "/" {
		*paths = append(*paths, t.GetFullSearchPath(node))
	}

	// Recursively collect from all children, whether expanded or not
	for _, child := range node.Children {
		t.collectAllPaths(child, paths)
	}
}

// IsFilterActive returns whether filter mode is currently active
func (t *Tree) IsFilterActive() bool {
	return t.filterActive
}

// MatchCount returns the number of matches
func (t *Tree) MatchCount() int {
	if t.search == nil {
		return 0
	}
	return len(t.search.Matches)
}

// Path cache management methods

// SetPathCache stores the prefetched paths for a mount
func (t *Tree) SetPathCache(mountPath string, paths []string) {
	if t.pathCache == nil {
		t.pathCache = make(map[string][]string)
	}
	t.pathCache[mountPath] = paths
}

// GetPathCache returns the cached paths for a mount
func (t *Tree) GetPathCache(mountPath string) ([]string, bool) {
	if t.pathCache == nil {
		return nil, false
	}
	paths, ok := t.pathCache[mountPath]
	return paths, ok
}

// IsCacheLoading returns whether a mount's paths are being prefetched
func (t *Tree) IsCacheLoading(mountPath string) bool {
	if t.cacheLoading == nil {
		return false
	}
	return t.cacheLoading[mountPath]
}

// SetCacheLoading sets the loading state for a mount's path prefetch
func (t *Tree) SetCacheLoading(mountPath string, loading bool) {
	if t.cacheLoading == nil {
		t.cacheLoading = make(map[string]bool)
	}
	if loading {
		t.cacheLoading[mountPath] = true
	} else {
		delete(t.cacheLoading, mountPath)
	}
}

// IsCacheLoaded returns whether a mount's paths have been cached
func (t *Tree) IsCacheLoaded(mountPath string) bool {
	if t.pathCache == nil {
		return false
	}
	_, ok := t.pathCache[mountPath]
	return ok
}

// AnyCacheLoading returns true if any mount is currently being prefetched
func (t *Tree) AnyCacheLoading() bool {
	if t.cacheLoading == nil {
		return false
	}
	return len(t.cacheLoading) > 0
}

// GetAllPathCaches returns all cached paths organized by mount
func (t *Tree) GetAllPathCaches() map[string][]string {
	if t.pathCache == nil {
		return make(map[string][]string)
	}
	return t.pathCache
}

// GetRoot returns the root node
func (t *Tree) GetRoot() *TreeNode {
	return t.root
}

// FindNodeByPath finds a node by its path (public wrapper)
func (t *Tree) FindNodeByPath(path string) *TreeNode {
	// Try exact match first
	if node := t.findNode(path); node != nil {
		return node
	}
	// Try with/without trailing slash
	if node := t.findNode(path + "/"); node != nil {
		return node
	}
	trimmed := strings.TrimSuffix(path, "/")
	return t.findNode(trimmed)
}

// GetExpandedPathsNeedingLoad returns paths that are marked as expanded
// but whose nodes need their children loaded
func (t *Tree) GetExpandedPathsNeedingLoad() []string {
	var paths []string

	// Check all visible nodes for expanded but not loaded
	for _, node := range t.nodes {
		if node == nil {
			continue
		}
		// Check if this node is expanded but children not loaded
		if t.expanded[node.Path] && !node.Loaded && !node.Loading {
			if node.IsDir || node.IsSecret {
				paths = append(paths, node.Path)
			}
		}
	}

	return paths
}
