package rc

import (
	"errors"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"

	"github.com/cloudfoundry-community/safe/pkg/yamlenc"
	fmt "github.com/jhunt/go-ansi"
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
	URL        string   `yaml:"url"`
	Token      string   `yaml:"token"`
	CACerts    []string `yaml:"ca_certs,omitempty"`
	SkipVerify bool     `yaml:"skip_verify,omitempty"`

	// Strongbox opts a target into the Strongbox seal-state service on port
	// :8484. Older configs wrote a no_strongbox key instead, with the
	// opposite default: Strongbox was on unless no_strongbox: true.
	// UnmarshalYAML honors that key when the file has it, so an upgrade
	// does not silently disarm Strongbox for every pre-existing target; a
	// file with neither key gets the new opt-in default (false).
	Strongbox bool   `yaml:"strongbox,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
}

// UnmarshalYAML translates the legacy no_strongbox key into Strongbox when
// the key is present in the document, and leaves Strongbox at its zero value
// (the new opt-in default) when it is not. Marshal only ever writes the
// strongbox key, so the translated intent -- not the legacy key -- is what a
// subsequent write persists.
func (v *Vault) UnmarshalYAML(unmarshal func(any) error) error {
	type vaultAlias Vault
	if err := unmarshal((*vaultAlias)(v)); err != nil {
		return err
	}

	var legacy struct {
		NoStrongbox *bool `yaml:"no_strongbox"`
	}
	// The decoder replays the same node into a second target; unrecognized
	// keys (url, token, ...) are ignored here just as strongbox is ignored
	// above by vaultAlias, which has no no_strongbox field.
	if err := unmarshal(&legacy); err != nil {
		return err
	}
	if legacy.NoStrongbox != nil {
		v.Strongbox = !*legacy.NoStrongbox
	}
	return nil
}

type oldConfig struct {
	Current    string            `yaml:"Current"`
	Targets    map[string]any    `yaml:"Targets"`
	Aliases    map[string]string `yaml:"Aliases"`
	SkipVerify map[string]bool   `yaml:"SkipVerify"`
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

	if err = yamlenc.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("could not parse config: %s", yamlenc.ErrorMessage(err))
	}
	if c.Version == 0 {
		var legacy oldConfig
		if err = yamlenc.Unmarshal(b, &legacy); err != nil {
			return Config{}, fmt.Errorf("could not parse legacy config: %s", yamlenc.ErrorMessage(err))
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

// Update applies a single mutation to the persisted configuration. It takes
// the config write lock, reads the current on-disk state, invokes mutate on
// it, writes the result atomically, and releases the lock.
//
// Reading under the lock, immediately before mutating, is what makes a
// concurrent writer's delta survive: each mutation lands on the latest file,
// not on whatever this process read at startup. Keep mutate to the mutation
// itself -- the lock is held for its duration, so no prompts, no network I/O,
// nothing slower than the file writes it protects.
func Update(mutate func(c *Config) error) error {
	return withLock(func() error {
		c, err := Read()
		if err != nil {
			return err
		}
		if err := mutate(&c); err != nil {
			return err
		}
		return c.write()
	})
}

func (c *Config) write() error {
	b, err := yamlenc.Marshal(c)
	if err != nil {
		return err
	}

	// Resolve the current target and marshal ~/.svtoken's content before
	// replacing any file. c.Vault("") fails when Current names a target that
	// is missing or ambiguous; catching that here means the failure aborts
	// with nothing written, instead of leaving ~/.saferc replaced while
	// ~/.svtoken -- and the token tools like Genesis read from it -- goes
	// stale and the caller is told the write failed.
	v, err := c.Vault("")
	if err != nil {
		return err
	}

	var svBytes []byte
	if v != nil {
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
		svBytes, err = yamlenc.Marshal(sv)
		if err != nil {
			return err
		}
	}

	if err := writeFileAtomic(saferc(), b, 0600); err != nil {
		return err
	}

	if v == nil {
		if err := os.Remove(svtoken()); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	// .vault-token before .svtoken, with both attempted and both reported:
	// managing ~/.vault-token is an explicit operator opt-in, and failing it
	// silently leaves the Vault CLI authenticated as whoever wrote it last.
	var tokenErr error
	if c.Options.ManageVaultToken {
		tokenErr = writeFileAtomic(fmt.Sprintf("%s/.vault-token", userHomeDir()), []byte(v.Token), 0600)
	}
	return errors.Join(tokenErr, writeFileAtomic(svtoken(), svBytes, 0600))
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

// applied are the environment variables Apply sets from a target. Only the
// address and the token are set unconditionally: the rest are set when the
// target carries them and left alone when it does not, so that the standard
// Vault variables a caller exported still hold for a target that says nothing
// about them.
var applied = []string{
	"VAULT_ADDR",
	"VAULT_TOKEN",
	"VAULT_SKIP_VERIFY",
	"VAULT_CACERT",
	"VAULT_NAMESPACE",
}

// Env is what the environment held before a target was applied to it.
type Env []envVar

type envVar struct {
	name  string
	value string
	set   bool
}

// SnapshotEnv records the variables Apply sets, so that a caller applying more
// than one target can put the environment back between them. Without it the
// second target inherits everything the first one carried and it does not --
// skipped verification, a CA bundle, a namespace -- and is talked to on terms
// that are not its own.
func SnapshotEnv() Env {
	env := make(Env, 0, len(applied))
	for _, name := range applied {
		value, set := os.LookupEnv(name)
		env = append(env, envVar{name: name, value: value, set: set})
	}
	return env
}

// Restore returns the environment to what it held when it was recorded.
func (e Env) Restore() {
	for _, v := range e {
		if v.set {
			_ = os.Setenv(v.name, v.value)
			continue
		}
		_ = os.Unsetenv(v.name)
	}
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

// SetCurrent selects the target named by either its alias or its URL. What it
// records is the alias, because that is the name the rest of the config is
// keyed by: a URL stored here resolves only for as long as exactly one target
// still carries it, so deleting that target leaves a selection that names
// nothing and every later command reporting a missing current target.
func (c *Config) SetCurrent(name string, reskip bool) error {
	alias, ok, err := c.Alias(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Unknown target '%s'", name)
	}
	c.Current = alias
	if reskip {
		c.Vaults[alias].SkipVerify = true
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
	return c.SetTokenFor(c.Current, token)
}

// SetTokenFor stores a token against a named target without making it the
// current one. Commands that honour -T need that separation: -T names a Vault
// for one command, and moving the current target would outlive the command,
// since Write persists it.
func (c *Config) SetTokenFor(alias, token string) error {
	if alias == "" {
		return fmt.Errorf("No target selected")
	}
	v, ok, _ := c.Find(alias)
	if !ok {
		return fmt.Errorf("Unknown target '%s'", alias)
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
		return v.Strongbox
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

// Alias resolves a name -- either an alias or the URL of a target -- to the
// alias that target is stored under. Callers that change the config need the
// key rather than the target it points at, and a name reaches the same target
// here as it does everywhere else.
func (c *Config) Alias(name string) (string, bool, error) {
	if _, ok := c.Vaults[name]; ok {
		return name, true, nil
	}

	var alias string
	n := 0
	want := strings.TrimSuffix(name, "/")

	for maybeAlias, maybe := range c.Vaults {
		if strings.TrimSuffix(maybe.URL, "/") == want {
			n++
			alias = maybeAlias
		}
	}
	if n == 1 {
		return alias, true, nil
	}
	if n > 1 {
		return "", true, fmt.Errorf("More than one target for Vault at '%s' (maybe try an alias?)", name)
	}

	return "", false, nil
}

func (c *Config) Find(alias string) (*Vault, bool, error) {
	name, ok, err := c.Alias(alias)
	if err != nil || !ok {
		return nil, ok, err
	}
	return c.Vaults[name], true, nil
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
