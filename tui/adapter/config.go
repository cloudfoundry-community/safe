package adapter

import (
	"sort"

	"github.com/cloudfoundry-community/safe/rc"
)

// TargetInfo contains display information about a vault target
type TargetInfo struct {
	Alias      string
	URL        string
	Current    bool
	HasToken   bool
	Namespace  string
	SkipVerify bool
}

// ConfigAdapter provides TUI-friendly access to safe configuration
type ConfigAdapter struct {
	config *rc.Config
}

// NewConfigAdapter creates a new config adapter
func NewConfigAdapter(cfg *rc.Config) *ConfigAdapter {
	return &ConfigAdapter{config: cfg}
}

// ListTargets returns a sorted list of all targets
func (c *ConfigAdapter) ListTargets() []TargetInfo {
	targets := make([]TargetInfo, 0, len(c.config.Vaults))

	for alias, v := range c.config.Vaults {
		targets = append(targets, TargetInfo{
			Alias:      alias,
			URL:        v.URL,
			Current:    alias == c.config.Current,
			HasToken:   v.Token != "",
			Namespace:  v.Namespace,
			SkipVerify: v.SkipVerify,
		})
	}

	// Sort by alias
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Alias < targets[j].Alias
	})

	return targets
}

// CurrentTarget returns the name of the current target
func (c *ConfigAdapter) CurrentTarget() string {
	return c.config.Current
}

// GetTarget returns information about a specific target
func (c *ConfigAdapter) GetTarget(alias string) (*TargetInfo, bool) {
	v, ok := c.config.Vaults[alias]
	if !ok {
		return nil, false
	}

	return &TargetInfo{
		Alias:      alias,
		URL:        v.URL,
		Current:    alias == c.config.Current,
		HasToken:   v.Token != "",
		Namespace:  v.Namespace,
		SkipVerify: v.SkipVerify,
	}, true
}

// GetVaultConfig returns the raw vault configuration for connecting
func (c *ConfigAdapter) GetVaultConfig(alias string) (*rc.Vault, bool) {
	v, ok := c.config.Vaults[alias]
	return v, ok
}

// SetCurrentTarget sets the current target
func (c *ConfigAdapter) SetCurrentTarget(alias string) error {
	if _, ok := c.config.Vaults[alias]; !ok {
		return nil // Target doesn't exist
	}
	c.config.Current = alias
	return c.Save()
}

// Save persists the configuration to disk
func (c *ConfigAdapter) Save() error {
	return c.config.Write()
}

// Config returns the underlying config
func (c *ConfigAdapter) Config() *rc.Config {
	return c.config
}
