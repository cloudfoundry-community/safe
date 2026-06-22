package rc

import (
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"

	fmt "github.com/jhunt/go-ansi"
	"gopkg.in/yaml.v2"
)

var toCleanup []string
var cleanupLock sync.Mutex
var cleanupSignalOnce sync.Once

type Config struct {
	Version int               `yaml:"version"`
	Current string            `yaml:"current"`
	Vaults  map[string]*Vault `yaml:"vaults"`
	Options Options           `yaml:"options"`
}

type Options struct {
	ManageVaultToken bool `yaml:"manage_vault_token"`
}

type Vault struct {
	URL         string   `yaml:"url"`
	Token       string   `yaml:"token"`
	CACerts     []string `yaml:"ca_certs,omitempty"`
	SkipVerify  bool     `yaml:"skip_verify,omitempty"`
	NoStrongbox bool     `yaml:"no_strongbox,omitempty"`
	Namespace   string   `yaml:"namespace,omitempty"`
}

type oldConfig struct {
	Current    string                 `yaml:"Current"`
	Targets    map[string]interface{} `yaml:"Targets"`
	Aliases    map[string]string      `yaml:"Aliases"`
	SkipVerify map[string]bool        `yaml:"SkipVerify"`
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("USERPROFILE")
		if home == "" {
			home = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		}
		return home
	}
	return os.Getenv("HOME")
}

func saferc() string {
	return fmt.Sprintf("%s/.saferc", userHomeDir())
}

func svtoken() string {
	return fmt.Sprintf("%s/.svtoken", userHomeDir())
}

func (legacy *oldConfig) convert() Config {
	c := Config{
		Version: 1,
		Current: legacy.Current,
		Vaults:  make(map[string]*Vault),
	}

	for alias, url := range legacy.Aliases {
		v := &Vault{
			URL: url,
		}
		if skip, ok := legacy.SkipVerify[url]; ok {
			v.SkipVerify = skip
		}
		if token, ok := legacy.Targets[url]; ok && token != nil {
			v.Token = token.(string)
		}
		c.Vaults[alias] = v
	}

	return c
}

func Read() (Config, error) {
	var c Config

	b, err := os.ReadFile(saferc())
	if err != nil {
		if os.IsNotExist(err) {
			return Config{Version: 1}, nil
		}
		return Config{}, err
	}

	if err = yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("could not parse config: %w", err)
	}
	if c.Version == 0 {
		var legacy oldConfig
		if err = yaml.Unmarshal(b, &legacy); err != nil {
			return Config{}, fmt.Errorf("could not parse legacy config: %w", err)
		}
		c = legacy.convert()
	}

	return c, nil
}

func Apply(use string) (Config, error) {
	c, err := Read()
	if err != nil {
		return Config{}, err
	}

	if err := c.Apply(use); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) Write() error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	err = os.WriteFile(saferc(), b, 0600)
	if err != nil {
		return err
	}

	v, err := c.Vault("")
	if err != nil {
		return err
	}
	if v == nil {
		_ = os.Remove(svtoken())
		return nil
	}

	sv := struct {
		Vault      string `yaml:"vault"` /* this is different than Vault.URL */
		Token      string `yaml:"token"`
		SkipVerify bool   `yaml:"skip_verify"`
		CACerts    string `yaml:"ca_certs,omitempty"`
		Namespace  string `yaml:"namespace,omitempty"`
	}{
		Vault:      v.URL,
		Token:      v.Token,
		SkipVerify: v.SkipVerify,
		CACerts:    strings.Join(v.CACerts, "\n"),
		Namespace:  v.Namespace,
	}
	b, err = yaml.Marshal(sv)
	if err != nil {
		return err
	}
	if c.Options.ManageVaultToken {
		_ = os.WriteFile(fmt.Sprintf("%s/.vault-token", userHomeDir()), []byte(v.Token), 0600)
	}

	return os.WriteFile(svtoken(), b, 0600)
}

// Returns the path of the file that the certificates were written into
func writeTempCACerts(certs []string) (string, error) {
	cleanupLock.Lock()
	defer cleanupLock.Unlock()

	caFile, err := os.CreateTemp("", "safe-ca-cert")
	if err != nil {
		return "", fmt.Errorf("Could not write CAs to a temp file: %w", err)
	}
	// Best-effort close guard for early-return error paths below.
	// The success path uses an explicit checked close instead.
	closed := false
	defer func() {
		if !closed {
			_ = caFile.Close()
		}
	}()

	toWrite := strings.Join(certs, "\n")
	_, err = caFile.WriteString(toWrite)
	if err != nil {
		return "", fmt.Errorf("Could not write CA certs into temporary file: %w", err)
	}

	// Explicit close with error check on the success path so a flush failure
	// is not silently dropped (errcheck baseline; also catches Windows quirks).
	closed = true
	if err = caFile.Close(); err != nil {
		return "", fmt.Errorf("could not close CA cert temp file: %w", err)
	}

	toCleanup = append(toCleanup, caFile.Name())

	// Install the interrupt handler exactly once, regardless of how many
	// targets write CA certs, so we don't accumulate a goroutine and signal
	// channel per call. On interrupt, remove every temp file then terminate.
	cleanupSignalOnce.Do(func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		go func() {
			if _, ok := <-sigChan; ok {
				Cleanup()
				os.Exit(1)
			}
		}()
	})

	return caFile.Name(), nil
}

func (c *Config) Apply(use string) error {
	v, err := c.Vault(use)
	if err != nil {
		return err
	}

	if v != nil {
		_ = os.Setenv("VAULT_ADDR", v.URL)
		_ = os.Setenv("VAULT_TOKEN", v.Token)
		if v.SkipVerify {
			_ = os.Setenv("VAULT_SKIP_VERIFY", "1")
		}
		if len(v.CACerts) > 0 {
			filename, err := writeTempCACerts(v.CACerts)
			if err != nil {
				return err
			}
			_ = os.Setenv("VAULT_CACERT", filename)
		}
		if v.Namespace != "" {
			_ = os.Setenv("VAULT_NAMESPACE", v.Namespace)
		}
	} else {
		if os.Getenv("VAULT_TOKEN") == "" {
			tokenFile := fmt.Sprintf("%s/.vault-token", os.Getenv("HOME"))
			b, err := os.ReadFile(tokenFile) // #nosec G304,G703 - Reading user's vault token from standard location
			if err == nil {
				_ = os.Setenv("VAULT_TOKEN", strings.TrimSpace(string(b)))
			}
		}
	}
	return nil
}

func (c *Config) SetCurrent(alias string, reskip bool) error {
	v, ok, err := c.Find(alias)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Unknown target '%s'", alias)
	}
	c.Current = alias
	if reskip {
		v.SkipVerify = true
	}
	return nil
}

func (c *Config) SetTarget(alias string, config Vault) error {
	if c.Vaults == nil {
		c.Vaults = make(map[string]*Vault)
	}

	c.Current = alias
	if existingAlias, found := c.Vaults[alias]; found {
		if config.URL == existingAlias.URL {
			config.Token = existingAlias.Token
		}
	}

	c.Vaults[alias] = &config
	return nil
}

func (c *Config) SetToken(token string) error {
	if c.Current == "" {
		return fmt.Errorf("No target selected")
	}
	v, ok, _ := c.Find(c.Current)
	if !ok {
		return fmt.Errorf("Unknown target '%s'", c.Current)
	}
	v.Token = token
	return nil
}

func (c *Config) URL() string {
	if v, ok, _ := c.Find(c.Current); ok {
		return v.URL
	}
	return ""
}

func (c *Config) Verified() bool {
	if v, ok, _ := c.Find(c.Current); ok {
		return !v.SkipVerify
	}
	return false
}

func (c *Config) HasStrongbox() bool {
	if v, ok, _ := c.Find(c.Current); ok {
		return !v.NoStrongbox
	}
	return false
}

func (c *Config) CACerts() []string {
	if v, ok, _ := c.Find(c.Current); ok {
		return v.CACerts
	}
	return nil
}

func (c *Config) Namespace() string {
	if v, ok, _ := c.Find(c.Current); ok {
		return v.Namespace
	}
	return ""
}

func (c *Config) Find(alias string) (*Vault, bool, error) {
	if v, ok := c.Vaults[alias]; ok {
		return v, true, nil
	}

	var v *Vault
	n := 0
	want := strings.TrimSuffix(alias, "/")

	for _, maybe := range c.Vaults {
		if strings.TrimSuffix(maybe.URL, "/") == want {
			n++
			v = maybe
		}
	}
	if n == 1 {
		return v, true, nil
	}
	if n > 1 {
		return nil, true, fmt.Errorf("More than one target for Vault at '%s' (maybe try an alias?)", alias)
	}

	return nil, false, nil
}

func (c *Config) Vault(which string) (*Vault, error) {
	if which == "" {
		which = c.Current
	}

	if which == "" {
		return nil, nil /* not an error */
	}

	v, ok, err := c.Find(which)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("Current target '%s' not found in ~/.saferc", which)
	}
	return v, nil
}

// Cleanup will clean up any temporary files that the rc package may have made.
// Cleanup is thread-safe and can be called multiple times.
func Cleanup() {
	cleanupLock.Lock()
	for _, filename := range toCleanup {
		_ = os.Remove(filename)
	}

	toCleanup = nil
	cleanupLock.Unlock()
}
