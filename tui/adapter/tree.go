package adapter

import (
	"sort"
	"strings"

	"github.com/cloudfoundry-community/safe/tui/component"
	"github.com/cloudfoundry-community/safe/vault"
)

// TreeAdapter converts vault data to tree nodes
type TreeAdapter struct {
	vault *VaultAdapter
}

// NewTreeAdapter creates a new tree adapter
func NewTreeAdapter(vault *VaultAdapter) *TreeAdapter {
	return &TreeAdapter{vault: vault}
}

// BuildRootNode creates the root node for the tree
func (t *TreeAdapter) BuildRootNode() (*component.TreeNode, error) {
	// Get all mounts
	mounts, err := t.vault.Mounts("kv")
	if err != nil {
		// Try generic mounts as fallback
		mounts, err = t.vault.Mounts("generic")
		if err != nil {
			return nil, err
		}
	}

	root := &component.TreeNode{
		Path:     "/",
		Name:     "/",
		IsDir:    true,
		Loaded:   true,
		Children: make([]*component.TreeNode, 0, len(mounts)),
	}

	// Add mounts as children
	for _, mount := range mounts {
		child := &component.TreeNode{
			Path:   mount,
			Name:   mount,
			IsDir:  true,
			Loaded: false,
		}
		root.Children = append(root.Children, child)
	}

	// Sort children
	sort.Slice(root.Children, func(i, j int) bool {
		return root.Children[i].Name < root.Children[j].Name
	})

	return root, nil
}

// LoadChildren loads children for a path
func (t *TreeAdapter) LoadChildren(path string) ([]*component.TreeNode, error) {
	// Use ListAlive to filter out soft-deleted secrets
	children, err := t.vault.ListAlive(path)
	if err != nil {
		return nil, err
	}

	nodes := make([]*component.TreeNode, 0, len(children))

	for _, child := range children {
		if child == "" {
			continue
		}

		childPath := strings.TrimSuffix(path, "/") + "/" + strings.TrimSuffix(child, "/")
		isDir := strings.HasSuffix(child, "/")
		name := strings.TrimSuffix(child, "/")

		node := &component.TreeNode{
			Path:     childPath,
			Name:     name,
			IsDir:    isDir,
			IsSecret: !isDir,
			Loaded:   false,
		}

		nodes = append(nodes, node)
	}

	// Sort: directories first, then alphabetically
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].IsDir != nodes[j].IsDir {
			return nodes[i].IsDir
		}
		return nodes[i].Name < nodes[j].Name
	})

	return nodes, nil
}

// LoadSecretKeys loads keys for a secret
func (t *TreeAdapter) LoadSecretKeys(path string) ([]string, error) {
	secret, err := t.vault.Read(path)
	if err != nil {
		return nil, err
	}

	return secret.Keys(), nil
}

// BuildKeyNodes builds tree nodes for secret keys
func (t *TreeAdapter) BuildKeyNodes(secretPath string, keys []string) []*component.TreeNode {
	nodes := make([]*component.TreeNode, 0, len(keys))

	for _, keyName := range keys {
		node := &component.TreeNode{
			Path:     secretPath, // Parent secret path
			Name:     ":" + keyName,
			IsDir:    false, // Keys are never directories
			IsSecret: false, // Keys are not secrets (they're inside secrets)
			IsKey:    true,
			KeyName:  keyName,
			Loaded:   true, // Keys are leaf nodes
		}
		nodes = append(nodes, node)
	}

	// Sort alphabetically by key name
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].KeyName < nodes[j].KeyName
	})

	return nodes
}

// BuildTreeFromSecrets builds a tree from vault.Secrets
func (t *TreeAdapter) BuildTreeFromSecrets(secrets vault.Secrets) *component.TreeNode {
	root := &component.TreeNode{
		Path:     "/",
		Name:     "/",
		IsDir:    true,
		Loaded:   true,
		Children: make([]*component.TreeNode, 0),
	}

	// Build tree structure from secrets
	nodeMap := make(map[string]*component.TreeNode)
	nodeMap["/"] = root

	for _, entry := range secrets {
		t.insertPath(root, nodeMap, entry.Path)
	}

	return root
}

// insertPath inserts a path into the tree
func (t *TreeAdapter) insertPath(root *component.TreeNode, nodeMap map[string]*component.TreeNode, path string) {
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")

	current := root
	currentPath := ""

	for i, part := range parts {
		if part == "" {
			continue
		}

		if currentPath == "" {
			currentPath = part
		} else {
			currentPath = currentPath + "/" + part
		}

		isLast := i == len(parts)-1

		// Check if node exists
		if existing, ok := nodeMap[currentPath]; ok {
			current = existing
			continue
		}

		// Create new node
		node := &component.TreeNode{
			Path:     currentPath,
			Name:     part,
			IsDir:    !isLast,
			IsSecret: isLast,
			Loaded:   true,
			Children: make([]*component.TreeNode, 0),
		}

		// Add to parent
		current.Children = append(current.Children, node)
		nodeMap[currentPath] = node
		current = node
	}

	// Sort children at each level
	t.sortChildren(root)
}

// sortChildren recursively sorts children
func (t *TreeAdapter) sortChildren(node *component.TreeNode) {
	if node.Children == nil {
		return
	}

	sort.Slice(node.Children, func(i, j int) bool {
		if node.Children[i].IsDir != node.Children[j].IsDir {
			return node.Children[i].IsDir
		}
		return node.Children[i].Name < node.Children[j].Name
	})

	for _, child := range node.Children {
		t.sortChildren(child)
	}
}
