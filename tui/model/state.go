package model

import (
	"github.com/cloudfoundry-community/safe/rc"
	"github.com/cloudfoundry-community/safe/vault"
)

// ViewType represents different views in the TUI
type ViewType int

const (
	ViewTargets ViewType = iota
	ViewBrowser
	ViewEditor
	ViewAdmin
	ViewCompare
	ViewKeyDetails
)

// LayoutMode represents the layout configuration
type LayoutMode int

const (
	LayoutSingle LayoutMode = iota
	LayoutTabs
	LayoutSplitVertical
	LayoutSplitHorizontal
)

// Session represents a connection to a vault target
type Session struct {
	Alias     string
	Config    *rc.Vault
	Vault     *vault.Vault
	Connected bool
	Sealed    bool
	Loading   bool
	LastError error

	// Tree state
	Tree      *TreeNode
	Expanded  map[string]bool
	Selected  string
	ScrollPos int

	// Cache
	SecretCache map[string]*vault.Secret

	// Current context
	CurrentPath string
}

// NewSession creates a new session for a target
func NewSession(alias string, cfg *rc.Vault) *Session {
	return &Session{
		Alias:       alias,
		Config:      cfg,
		Expanded:    make(map[string]bool),
		SecretCache: make(map[string]*vault.Secret),
		CurrentPath: "/",
	}
}

// TreeNode represents a node in the vault path tree
type TreeNode struct {
	Path     string
	Name     string
	IsDir    bool
	IsSecret bool
	Children []*TreeNode
	Loaded   bool
	Loading  bool
	Keys     []string
	Level    int
}

// FlattenVisible returns a flat list of visible nodes for rendering
func (n *TreeNode) FlattenVisible(expanded map[string]bool, level int) []*TreeNode {
	result := make([]*TreeNode, 0)
	n.Level = level
	result = append(result, n)

	if expanded[n.Path] && n.Children != nil {
		for _, child := range n.Children {
			result = append(result, child.FlattenVisible(expanded, level+1)...)
		}
	}

	return result
}

// FindByPath finds a node by its path
func (n *TreeNode) FindByPath(path string) *TreeNode {
	if n.Path == path {
		return n
	}
	for _, child := range n.Children {
		if found := child.FindByPath(path); found != nil {
			return found
		}
	}
	return nil
}

// TabState represents a tab in the tab bar
type TabState struct {
	ID          string
	Label       string
	TargetAlias string
	Modified    bool
	Closeable   bool
}

// StatusLevel indicates severity of status messages
type StatusLevel int

const (
	StatusInfo StatusLevel = iota
	StatusSuccess
	StatusWarning
	StatusError
)

// StatusBarState holds status bar information
type StatusBarState struct {
	Message string
	Level   StatusLevel
	Target  string
	Path    string
	Auth    bool
	Sealed  bool
}

// ModalState holds modal dialog state
type ModalState struct {
	Title   string
	Content string
	Actions []ModalAction
	Active  int
}

// ModalAction represents an action button in a modal
type ModalAction struct {
	ID     string
	Label  string
	Key    string
	Danger bool
}
