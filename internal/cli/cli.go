package cli

import (
	"crypto/x509"
	"errors"
	"os"
	"strconv"
	"strings"

	fmt "github.com/jhunt/go-ansi"
	gocli "github.com/jhunt/go-cli"
	env "github.com/jhunt/go-envirotron"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// Build metadata, populated by Main from values the main package receives
// via -ldflags. Empty in plain `go build` and `go test` runs.
var (
	Version   string
	BuildTime string
	GitCommit string
)

// CLI carries the parsed options and command runner shared by all command
// handlers. Each handler is a method on *CLI.
type CLI struct {
	opt *Options
	r   *Runner
}

// Sentinel errors returned by connectOrErr so the CLI layer can render the
// matching guidance. connect maps these to the user-facing messages.
var (
	errNoVaultTarget    = errors.New("not targeting a Vault")
	errNotAuthenticated = errors.New("not authenticated to a Vault")
)

// connectOrErr builds a Vault client from the standard VAULT_* environment.
// It returns a sentinel error (errNoVaultTarget or errNotAuthenticated) or the
// underlying vault.NewVault error instead of exiting, so the connection logic
// is unit testable. The CLI wrapper connect renders guidance and exits.
func connectOrErr(auth bool) (*vault.Vault, error) {
	var caCertPool *x509.CertPool
	if os.Getenv("VAULT_CACERT") != "" {
		contents, err := os.ReadFile(os.Getenv("VAULT_CACERT")) // #nosec G703 -- VAULT_CACERT is a standard Vault environment variable controlled by the user
		if err != nil {
			return nil, fmt.Errorf("could not read CA certificates from %s: %w", os.Getenv("VAULT_CACERT"), err)
		}

		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(contents)
	}

	url := os.Getenv("VAULT_ADDR")
	if url == "" {
		return nil, errNoVaultTarget
	}

	skipVerify := os.Getenv("VAULT_SKIP_VERIFY")
	// Parse VAULT_SKIP_VERIFY with Go/Vault-compatible bool semantics:
	// "false", "0", "no", "off" all disable skip; parse failure is conservative (do not skip).
	skipVerifyBool, parseErr := strconv.ParseBool(skipVerify)
	if parseErr != nil {
		skipVerifyBool = false
	}
	conf := vault.VaultConfig{
		URL:        url,
		Token:      os.Getenv("VAULT_TOKEN"),
		Namespace:  os.Getenv("VAULT_NAMESPACE"),
		SkipVerify: skipVerifyBool,
		CACerts:    caCertPool,
	}

	if auth && conf.Token == "" {
		return nil, errNotAuthenticated
	}

	v, err := vault.NewVault(conf)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// connect builds a Vault client, printing guidance and exiting on failure. It
// preserves the original CLI behavior; the testable core is connectOrErr.
func connect(auth bool) *vault.Vault {
	v, err := connectOrErr(auth)
	if err == nil {
		return v
	}

	switch {
	case errors.Is(err, errNoVaultTarget):
		_, _ = fmt.Fprintf(os.Stderr, "@R{You are not targeting a Vault.}\n")
		_, _ = fmt.Fprintf(os.Stderr, "Try @C{safe target https://your-vault alias}\n")
		_, _ = fmt.Fprintf(os.Stderr, " or @C{safe target alias}\n")
	case errors.Is(err, errNotAuthenticated):
		_, _ = fmt.Fprintf(os.Stderr, "@R{You are not authenticated to a Vault.}\n")
		_, _ = fmt.Fprintf(os.Stderr, "Try @C{safe auth ldap}\n")
		_, _ = fmt.Fprintf(os.Stderr, " or @C{safe auth github}\n")
		_, _ = fmt.Fprintf(os.Stderr, " or @C{safe auth okta}\n")
		_, _ = fmt.Fprintf(os.Stderr, " or @C{safe auth oidc}\n")
		_, _ = fmt.Fprintf(os.Stderr, " or @C{safe auth token}\n")
		_, _ = fmt.Fprintf(os.Stderr, " or @C{safe auth userpass}\n")
		_, _ = fmt.Fprintf(os.Stderr, " or @C{safe auth approle}\n")
	default:
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
	}
	rc.Cleanup()
	os.Exit(1)
	return nil
}

// usesStrongbox reports whether a command should look for Strongbox alongside
// the Vault it is acting on. A nil target means no Vault is configured and the
// address came from the environment, where there is no flag to consult.
func usesStrongbox(target *rc.Vault) bool {
	return target != nil && !target.NoStrongbox
}

// targetAddress is the address the client returned by connect is talking to.
// rc.Apply sets it from the target the command named, so it holds for -T and
// for an environment-only configuration alike, where the config has no
// address to offer.
func targetAddress() string {
	return os.Getenv("VAULT_ADDR")
}

type Options struct {
	Insecure     bool `cli:"-k, --insecure"`
	Version      bool `cli:"-v, --version"`
	Help         bool `cli:"-h, --help"`
	Clobber      bool `cli:"--clobber, --no-clobber"`
	SkipIfExists bool
	Quiet        bool `cli:"--quiet"`

	// Behavour of -T must chain through -- separated commands.  There is code
	// that relies on this.  Will default to $SAFE_TARGET if it exists, or
	// the current safe target otherwise.
	UseTarget string `cli:"-T, --target" env:"SAFE_TARGET"`

	HelpCommand    struct{} `cli:"help"`
	VersionCommand struct{} `cli:"version"`

	Envvars struct{} `cli:"envvars"`
	Targets struct {
		JSON bool `cli:"--json"`
	} `cli:"targets"`

	Status struct {
		ErrorIfSealed bool `cli:"-e, --err-sealed"`
	} `cli:"status"`

	Unseal struct{} `cli:"unseal"`
	Seal   struct{} `cli:"seal"`
	Env    struct {
		ForBash bool `cli:"--bash"`
		ForFish bool `cli:"--fish"`
		ForJSON bool `cli:"--json"`
	} `cli:"env"`

	Auth struct {
		Path string `cli:"-p, --path"`
		JSON bool   `cli:"--json"`
	} `cli:"auth, login"`

	Logout struct{} `cli:"logout"`
	Renew  struct{} `cli:"renew"`
	Ask    struct{} `cli:"ask"`
	Set    struct{} `cli:"set, write"`
	Paste  struct{} `cli:"paste"`
	Exists struct{} `cli:"exists, check"`

	Local struct {
		As       string   `cli:"--as"`
		File     string   `cli:"-f, --file"`
		Memory   bool     `cli:"-m, --memory"`
		Port     int      `cli:"-p, --port"`
		Config   []string `cli:"-c, --config"`
		Listener []string `cli:"-l, --listener"`
	} `cli:"local"`

	Init struct {
		Single    bool `cli:"-s, --single"`
		NKeys     int  `cli:"--keys"`
		Threshold int  `cli:"--threshold"`
		JSON      bool `cli:"--json"`
		Sealed    bool `cli:"--sealed"`
		NoMount   bool `cli:"--no-mount"`
		Persist   bool `cli:"--persist, --no-persist"`
	} `cli:"init"`

	Rekey struct {
		NKeys     int      `cli:"--keys, --num-unseal-keys"`
		Threshold int      `cli:"--threshold, --keys-to-unseal"`
		GPG       []string `cli:"--gpg"`
		Persist   bool     `cli:"--persist, --no-persist"`
	} `cli:"rekey"`

	Get struct {
		KeysOnly bool `cli:"--keys"`
		Yaml     bool `cli:"--yaml"`
	} `cli:"get, read, cat"`

	Versions struct{} `cli:"versions,revisions"`

	List struct {
		Single bool `cli:"-1"`
		Quick  bool `cli:"-q, --quick"`
	} `cli:"ls"`

	Paths struct {
		ShowKeys bool `cli:"--keys"`
		Quick    bool `cli:"-q, --quick"`
	} `cli:"paths"`

	Tree struct {
		ShowKeys   bool `cli:"--keys"`
		HideLeaves bool `cli:"-d, --hide-leaves"`
		Quick      bool `cli:"-q, --quick"`
	} `cli:"tree"`

	Values struct {
		ShowKeys    bool     `cli:"--keys"`
		AllVersions bool     `cli:"-a, --all-versions"`
		Deleted     bool     `cli:"-d, --deleted"`
		Paths       []string `cli:"-p, --path"`
	} `cli:"values"`

	Target struct {
		JSON        bool     `cli:"--json"`
		Interactive bool     `cli:"-i, --interactive"`
		Strongbox   bool     `cli:"-s, --strongbox, --no-strongbox"`
		CACerts     []string `cli:"--ca-cert"`
		Namespace   string   `cli:"-n, --namespace"`

		Delete struct{} `cli:"delete, rm"`
	} `cli:"target"`

	Delete struct {
		Recurse bool `cli:"-R, -r, --recurse"`
		Force   bool `cli:"-f, --force"`
		Destroy bool `cli:"-D, -d, --destroy"`
		All     bool `cli:"-a, --all"`
	} `cli:"delete, rm"`

	Undelete struct {
		All bool `cli:"-a, --all"`
	} `cli:"undelete, unrm, urm"`

	Revert struct {
		Deleted bool `cli:"-d, --deleted"`
	} `cli:"revert"`

	Export struct {
		All     bool `cli:"-a, --all"`
		Deleted bool `cli:"-d, --deleted"`
		//These do nothing but are kept for backwards-compat
		OnlyAlive bool `cli:"-o, --only-alive"`
		Shallow   bool `cli:"-s, --shallow"`
	} `cli:"export"`

	Import struct {
		IgnoreDestroyed bool `cli:"-I, --ignore-destroyed"`
		IgnoreDeleted   bool `cli:"-i, --ignore-deleted"`
		Shallow         bool `cli:"-s, --shallow"`
	} `cli:"import"`

	Move struct {
		Recurse bool `cli:"-R, -r, --recurse"`
		Force   bool `cli:"-f, --force"`
		Deep    bool `cli:"-d, --deep"`
	} `cli:"move, rename, mv"`

	Copy struct {
		Recurse bool `cli:"-R, -r, --recurse"`
		Force   bool `cli:"-f, --force"`
		Deep    bool `cli:"-d, --deep"`
	} `cli:"copy, cp"`

	Gen struct {
		Policy string `cli:"-p, --policy"`
		Length int    `cli:"-l, --length"`
	} `cli:"gen, auto, generate"`

	SSH     struct{} `cli:"ssh"`
	RSA     struct{} `cli:"rsa"`
	DHParam struct{} `cli:"dhparam, dhparams, dh"`
	Prompt  struct{} `cli:"prompt"`
	Vault   struct{} `cli:"vault!"`
	Fmt     struct{} `cli:"fmt"`

	Curl struct {
		DataOnly bool `cli:"--data-only"`
	} `cli:"curl"`

	UUID   struct{} `cli:"uuid"`
	Option struct{} `cli:"option"`

	X509 struct {
		Validate struct {
			CA         bool     `cli:"-A, --ca"`
			SignedBy   string   `cli:"-i, --signed-by"`
			NotRevoked bool     `cli:"-R, --not-revoked"`
			Revoked    bool     `cli:"-r, --revoked"`
			NotExpired bool     `cli:"-E, --not-expired"`
			Expired    bool     `cli:"-e, --expired"`
			Name       []string `cli:"-n, --for"`
			Bits       []int    `cli:"-b, --bits"`
		} `cli:"validate, check"`

		Issue struct {
			CA           bool     `cli:"-A, --ca"`
			Subject      string   `cli:"-s, --subj, --subject"`
			Type         string   `cli:"--type"`
			Bits         int      `cli:"-b, --bits"`
			Curve        string   `cli:"--curve"`
			SignedBy     string   `cli:"-i, --signed-by"`
			Name         []string `cli:"-n, --name"`
			TTL          string   `cli:"-t, --ttl"`
			KeyUsage     []string `cli:"-u, --key-usage"`
			SigAlgorithm string   `cli:"-l, --sig-algorithm"`
		} `cli:"issue"`

		Revoke struct {
			SignedBy string `cli:"-i, --signed-by"`
		} `cli:"revoke"`

		Renew struct {
			Subject      string   `cli:"-s, --subj, --subject"`
			Name         []string `cli:"-n, --name"`
			SignedBy     string   `cli:"-i, --signed-by"`
			TTL          string   `cli:"-t, --ttl"`
			KeyUsage     []string `cli:"-u, --key-usage"`
			SigAlgorithm string   `cli:"-l, --sig-algorithm"`
		} `cli:"renew"`

		Reissue struct {
			Subject      string   `cli:"-s, --subj, --subject"`
			Name         []string `cli:"-n, --name"`
			Type         string   `cli:"--type"`
			Bits         int      `cli:"-b, --bits"`
			Curve        string   `cli:"--curve"`
			SignedBy     string   `cli:"-i, --signed-by"`
			TTL          string   `cli:"-t, --ttl"`
			KeyUsage     []string `cli:"-u, --key-usage"`
			SigAlgorithm string   `cli:"-l, --sig-algorithm"`
		} `cli:"reissue"`

		Show struct {
		} `cli:"show"`

		CRL struct {
			Renew bool `cli:"--renew"`
		} `cli:"crl"`
	} `cli:"x509"`
}

func Main(version, buildTime, gitCommit string) {
	Version = version
	BuildTime = buildTime
	GitCommit = gitCommit

	var opt Options
	opt.Gen.Policy = "a-zA-Z0-9"

	opt.Clobber = true

	opt.Init.Persist = true
	opt.Rekey.Persist = true

	opt.Target.Strongbox = true

	go Signals()

	r := NewRunner()

	c := &CLI{opt: &opt, r: r}

	r.Dispatch("version", &Help{
		Summary: "Print the version of the safe CLI",
		Usage:   "safe version",
		Type:    AdministrativeCommand,
	}, c.cmdVersion)

	r.Dispatch("help", nil, c.cmdHelp)

	r.Dispatch("envvars", nil, c.cmdEnvvars)

	r.Dispatch("targets", &Help{
		Summary: "List all targeted Vaults",
		Usage:   "safe targets",
		Type:    AdministrativeCommand,
	}, c.cmdTargets)

	r.Dispatch("target", &Help{
		Summary: "Target a new Vault, or set your current Vault target",
		Description: `Target a new Vault if URL and ALIAS are provided, or set
your current Vault target if just ALIAS is given. If the single argument form
if provided, the following flags are valid:

-k (--insecure) specifies to skip x509 certificate validation. This only has an
effect if the given URL uses an HTTPS scheme.

-s (--strongbox) specifies that the targeted Vault has a strongbox deployed at
its IP on port :8484. This is true by default. --no-strongbox will cause commands
that would otherwise use strongbox to run against only the targeted Vault.

-n (--namespace) specifies a Vault Enterprise namespace to run commands against
for this target.

--ca-cert can be either a PEM-encoded certificate value or filepath to a
PEM-encoded certificate. The given certificate will be trusted as the signing
certificate to the certificate served by the Vault server. This flag can be
provided multiple times to provide multiple CA certificates.
`,
		Usage: "safe [-k] [--[no]-strongbox] [-n] [--ca-cert] target [URL] [ALIAS] | safe target -i",
		Type:  AdministrativeCommand,
	}, c.cmdTarget)

	r.Dispatch("target delete", &Help{
		Summary: "Forget about a targeted Vault",
		Usage:   "safe target delete ALIAS",
		Type:    DestructiveCommand,
	}, c.cmdTargetDelete)

	r.Dispatch("status", &Help{
		Summary: "Print the status of the current target's backend nodes",
		Type:    AdministrativeCommand,
		Usage:   "safe status",
		Description: `
Returns the seal status of each node in the Vault cluster.

If strongbox is configured for this target, then strongbox is queried for seal
status of all nodes in the cluster. If strongbox is disabled for the target,
the /sys/health endpoint is queried for the target box to return the health of
just this Vault instance.

The following options are recognized:

	-e, --err-sealed  Causes safe to exit with a non-zero code if any of the
	                  queried Vaults are sealed.
		`,
	}, c.cmdStatus)

	r.Dispatch("local", &Help{
		Summary: "Run a local vault",
		Usage:   "safe local (--memory|--file path/to/dir) [--as name] [--port port] [--config key=value ...] [--listener key=value ...]",
		Description: `
Spins up a new Vault instance.

By default, an unused port between 8201 and 9999 (inclusive) will be selected as
the Vault listening port. You may manually specify a port with the -p/--port
flag.

The new Vault will be initialized with a single seal key, targeted with
a catchy name, authenticated by the new root token, and populated with a
secret/handshake!

If you just need a transient Vault for testing or experimentation, and
don't particularly care about the contents of the Vault, specify the
--memory/-m flag and get an in-memory backend.

If, on the other hand, you want to keep the Vault around, possibly
spinning it down when not in use, specify the --file/-f flag, and give it
the path to a directory to use for the file backend.  The files created
by the mechanism will be encrypted.  You will be given the seal key for
subsequent activations of the Vault.

To tune the generated Vault configuration, pass key=value pairs:

  -c/--config key=value     Set a top-level configuration option, e.g.
                            --config max_json_string_value_length=8388608
  -l/--listener key=value   Set an option on the tcp listener stanza, e.g.
                            --listener proxy_protocol_behavior=use_always

Both flags may be repeated.  Values that look like integers, floats, or
booleans are written unquoted; everything else is quoted as a string.  A
key matching a default (disable_mlock, address, tls_disable) overrides it.
safe only checks that each pair is well-formed; Vault validates the rest,
and its error is reported if the server refuses to start.
`,
		Type: AdministrativeCommand,
	}, c.cmdLocal)

	r.Dispatch("init", &Help{
		Summary: "Initialize a new vault",
		Usage:   "safe init [--keys #] [--threshold #] [--single] [--json] [--no-mount] [--sealed]",
		Description: `
Initializes a brand new Vault backend, generating new seal keys, and an
initial root token.  This information will be printed out, so that you
can save it somewhere secure (encrypted drive, password manager, etc.)

By default, Vault is initialized with 5 unseal keys, 3 of which are
required to unseal the Vault after a restart.  You can adjust this via
the --keys and --threshold options.  The --single option is a shortcut
for specifying a single key and a threshold of 1.

Once the Vault is initialized, safe will unseal it automatically, using
the newly minted seal keys, unless you pass it the --sealed option.
The root token will also be stored in the ~/.saferc file, saving you the
trouble of calling 'safe auth token' yourself.

The --json flag causes 'safe init' to print out the seal keys and initial
root token in a machine-friendly JSON format, that looks like this:

    {
      "root_token": "05f28556-db0a-f76f-3c26-40de20f28cee"
      "seal_keys": [
        "jDuvcXg7s4QnjHjwN9ydSaFtoMj8YZWrO8hRFWT2PoqT",
        "XiE5cq0+AsUcK8EK8GomCsMdylixwWa8tM2L991OHcry",
        "F9NbroyispQTCMHBWBD5+lYxMEms5hntwsrxcdZx1+3w",
        "3scP3yIdfLv9mr0YbxZRClpPNSf5ohVpWmxrpRQ/a9JM",
        "NosOaAjZzvcdHKBvtaqLDRwWSG6/XkLwgZHvnIvAhOC5"
      ]
    }

This can be used to automate the setup of Vaults for test/dev purposes,
which can be quite handy.

By default, the seal keys will also be stored in the Vault itself,
unless you specify the --no-persist flag.  They will be written to
secret/vault/seal/keys, as key1, key2, ... keyN. Note that if
--sealed is also set, this option is ignored (since the Vault will
remain sealed).

In more recent versions of Vault, the "secret" mount is not mounted
by default. Safe will ensure that the mount is mounted anyway unless
the --no-mount option is given. The flag will not unmount an existing
secret mount in versions of Vault which mount "secret" by default.
Note that if --sealed is also set, this option is ignored (since the
Vault will remain sealed).

`,
		Type: AdministrativeCommand,
	}, c.cmdInit)

	r.Dispatch("unseal", &Help{
		Summary: "Unseal the current target",
		Usage:   "safe unseal",
		Type:    AdministrativeCommand,
	}, c.cmdUnseal)

	r.Dispatch("seal", &Help{
		Summary: "Seal the current target",
		Usage:   "safe seal",
		Type:    AdministrativeCommand,
	}, c.cmdSeal)

	r.Dispatch("env", &Help{
		Summary: "Print the environment variables for the current target",
		Usage:   "safe env",
		Description: `
Print the environment variables representing the current target.

 --bash   Format the environment variables to be used by Bash.

 --fish   Format the environment variables to be used by fish.

 --json   Format the environment variables in json format.

Please note that if you specify --json, --bash or --fish then the output will be
written to STDOUT instead of STDERR to make it easier to consume.
		`,
		Type: AdministrativeCommand,
	}, c.cmdEnv)

	r.Dispatch("auth", &Help{
		Summary: "Authenticate to the current target",
		Usage:   "safe auth [--path <value>] (token|github|oidc|ldap|okta|userpass|approle)",
		Description: `
Set the authentication token sent when talking to the Vault.

Supported auth backends are:

token     Set the Vault authentication token directly.
github    Provide a Github personal access (oauth) token.
ldap      Provide LDAP user credentials.
okta      Provide Okta user credentials.
oidc      Complete OIDC auth flow
userpass  Provide a username and password registered with the UserPass backend.
approle   Provide a client ID and client secret registered with the AppRole backend.
status    Get information about current authentication status

Flags:
  -p, --path  Set the path of the auth backend mountpoint. For those who are
              familiar with the API, this is the part that comes after v1/auth.
              Defaults to the name of auth type (e.g. "userpass"), which is
              the default when creating auth backends with the Vault CLI.
  -j, --json  For auth status, returns the information as a JSON object.
`,
		Type: AdministrativeCommand,
	}, c.cmdAuth)

	r.Dispatch("logout", &Help{
		Summary: "Forget the authentication token of the currently targeted Vault",
		Usage:   "safe logout\n",
		Type:    AdministrativeCommand,
	}, c.cmdLogout)

	r.Dispatch("renew", &Help{
		Summary: "Renew one or more authentication tokens",
		Usage:   "safe renew [all]\n",
		Type:    AdministrativeCommand,
	}, c.cmdRenew)

	r.Dispatch("ask", &Help{
		Summary: "Create or update an insensitive configuration value",
		Usage:   "safe ask PATH NAME=[VALUE] [NAME ...]",
		Type:    DestructiveCommand,
		Description: `
Update a single path in the Vault with new or updated named attributes.
Any existing name/value pairs not specified on the command-line will
be left alone, with their original values.

You will be prompted to provide (without confirmation) any values that
are omitted. Unlike the 'safe set' and 'safe paste' commands, data entry
is NOT obscured.
`,
	}, c.cmdAsk)

	r.Dispatch("set", &Help{
		Summary: "Create or update a secret",
		Usage:   "safe set PATH NAME=[VALUE] [NAME ...]",
		Type:    DestructiveCommand,
		Description: `
Update a single path in the Vault with new or updated named attributes.
Any existing name/value pairs not specified on the command-line will be
left alone, with their original values.

Values can be provided a number of different ways.

    safe set secret/path key=value

Will set "key" to "value", but that exposes the value in the process table
(and possibly in shell history files).  This is normally fine for usernames,
IP addresses, and other public information.

If this worries you, leave off the '=value', and safe will prompt you.

    safe set secret/path key

Some secrets perfer to live on disk, in files.  Certificates, private keys,
really long secrets that are tough to type, etc.  For those, you can use
the '@' notation:

    safe set secret/path key@path/to/file

This causes safe to read the file 'path/to/file', relative to the current
working directory, and insert the contents into the Vault.
`,
	}, c.cmdSet)

	r.Dispatch("paste", &Help{
		Summary: "Create or update a secret",
		Usage:   "safe paste PATH NAME=[VALUE] [NAME ...]",
		Type:    DestructiveCommand,
		Description: `
Works just like 'safe set', updating a single path in the Vault with new or
updated named attributes.  Any existing name/value pairs not specified on the
command-line will be left alone, with their original values.

You will be prompted to provide any values that are omitted, but unlike the
'safe set' command, you will not be asked to confirm those values.  This makes
sense when you are pasting in credentials from an external password manager
like 1password or Lastpass.
`,
	}, c.cmdPaste)

	r.Dispatch("exists", &Help{
		Summary: "Check to see if a secret exists in the Vault",
		Usage:   "safe exists PATH",
		Type:    NonDestructiveCommand,
		Description: `
When you want to see if a secret has been defined, but don't need to know
what its value is, you can use 'safe exists'.  PATH can either be a partial
path (i.e. 'secret/accounts/users/admin') or a fully-qualified path that
incudes a name (like 'secret/accounts/users/admin:username').

'safe exists' does not produce any output, and is suitable for use in scripts.

The process will exit 0 (zero) if PATH exists in the current Vault.
Otherwise, it will exit 1 (one).  If unrelated errors, like network timeouts,
certificate validation failure, etc. occur, they will be printed as well.
`,
	}, c.cmdExists)

	r.Dispatch("get", &Help{
		Summary: "Retrieve the key/value pairs (or just keys) of one or more paths",
		Usage:   "safe get [--keys] [--yaml] PATH [PATH ...]",
		Description: `
Allows you to retrieve one or more values stored in the given secret, or just the
valid keys.  It operates in the following modes:

If a single path is specified that does not include a :key suffix, the output
will be the key:value pairs for that secret, in YAML format.  It will not include
the specified path as the base hash key; instead, it will be output as a comment
behind the document indicator (---).  To force it to include the full path as
the root key, specify --yaml.

If a single path is specified including the :key suffix, the single value of that
path:key will be output in string format.  To force the use of the fully qualified
{path: {key: value}} output in YAML format, use --yaml option.

If a single path is specified along with --keys, the list of keys for that given
path will be returned.  If that path does not contain any secrets (ie its not a
leaf node or does not exist), it will output nothing, but will not error.  If a
specific key is specified, it will output only that key if it exists, otherwise
nothing. You can specify --yaml to force YAML output.

If you specify more than one path, output is forced to be YAML, with the primary
hash key being the requested path (not including the key if provided).  If --keys
is specified, the next level will contain the keys found under that path; if the
path included a key component, only the specified keys will be present.  Without
the --keys option, the key: values for each found (or requested) key for the path
will be output.

If an invalid key or path is requested, an error will be output and nothing else
unless the --keys option is specified.  In that case, the error will be displayed
as a warning, but the output will be provided with an empty array for missing
paths/keys.
`,
		Type: NonDestructiveCommand,
	}, c.cmdGet)

	r.Dispatch("versions", &Help{
		Summary: "Print information about the versions of one or more paths",
		Usage:   "safe versions PATH [PATHS...]",
		Type:    NonDestructiveCommand,
	}, c.cmdVersions)

	r.Dispatch("ls", &Help{
		Summary: "Print the keys and sub-directories at one or more paths",
		Usage:   "safe ls [-1|-q] [PATH ...]",
		Type:    NonDestructiveCommand,
		Description: `
	Specifying the -1 flag will print one result per line.

	A secret is listed only if its newest version can still be read, which
	costs one version lookup per secret. The lookup reads version metadata
	and not the secret, so listing a folder needs no access to the values
	in it. Specifying the -q flag skips the lookup, which is quicker on a
	large folder and lists the secrets that have been marked as deleted
	along with the rest. Only a kv v2 mount keeps versions, so neither the
	check nor -q does anything on a kv v1 mount.
`,
	}, c.cmdLs)

	r.Dispatch("tree", &Help{
		Summary: "Print a tree listing of one or more paths",
		Usage:   "safe tree [-d|-q|--keys] [PATH ...]",
		Type:    NonDestructiveCommand,
		Description: `
Walks the hierarchy of secrets stored underneath a given path, listing all
reachable name/value pairs and displaying them in a tree format.  If '-d' is
given, only the containing folders will be printed; this more concise output
can be useful when you're trying to get your bearings. If '-q' is given, safe
will not look up the versions of each secret on a kv v2 mount to see whether
the newest one has been marked as deleted. This may cause secrets which would
404 in an attempt to read them to appear in the tree, but is often considerably
quicker for larger vaults. This flag does nothing for kv v1 mounts. With
'--keys' the lookup is made anyway, since the keys are reached through it, so
'-q' then changes which secrets are listed without saving any work. If '--keys'
is given, the keys within each secret will be displayed inline with the secret
name in the format:
<secret-name>: key1, key2, key3
`,
	}, c.cmdTree)

	r.Dispatch("paths", &Help{
		Summary: "Print all of the known paths, one per line",
		Usage:   "safe paths [-q|--keys] PATH [PATH ...]",
		Type:    NonDestructiveCommand,
		Description: `
Walks the hierarchy of secrets stored underneath a given path, listing all
reachable name/value pairs and displaying them in a list. If '-q' is given,
safe will not look up the versions of each secret on a kv v2 mount to see
whether the newest one has been marked as deleted. This may cause secrets which
would 404 in an attempt to read them to appear in the listing, but is often
considerably quicker for larger vaults. This flag does nothing for kv v1
mounts. With '--keys' the lookup is made anyway, since the keys are reached
through it, so '-q' then changes which secrets are listed without saving any
work.
`}, c.cmdPaths)

	r.Dispatch("values", &Help{
		Summary: "Find secrets containing specified values",
		Usage:   "safe values [--keys] [-ad] [-p PATH ...] [VALUE ...]",
		Type:    NonDestructiveCommand,
		Description: `
Searches the hierarchy of secrets for any whose stored values equal one of
the given values. Matching is exact, case-sensitive, and against whole
values; no substring or pattern matching is performed. Only the latest live
version of each secret is inspected -- secrets whose newest version has been
deleted or destroyed are not searched.

-a (--all-versions) searches every readable version of each secret instead,
which is what an audit of a leaked value wants: a credential that was
rotated away still sits in the history. Each match is then reported as
path^version, so a hit on a superseded version can be told apart from one on
the value in use and read back exactly as printed. Only the versions that can
be read without writing are searched; add -d for the deleted ones. On a kv v1
mount, where a secret has only the one version, this reports every match as
version 1.

-d (--deleted) searches deleted versions too, by undeleting each one, reading
it, and deleting it again -- the same cycle safe export -d uses. It writes to
the Vault to answer the question, and an interrupted search can leave a
version undeleted, so reach for it when a leaked credential has to be tracked
down wherever it landed. Destroyed versions are gone and are searched by
neither flag. Matches carry their version number under -d as well, since a
match may be sitting in a version that is no longer live.

Search locations are given with -p (--path), which may be repeated to search
several subtrees. The flag value must be a separate argument; the --path=x
form is not supported. If no -p is given, the search defaults to the
'secret' mount. The root of each search path must be readable or the command
fails. Subtrees the authenticated token cannot read are skipped, and a count
of skipped subtrees is reported on standard error, since skipped subtrees
mean the results may be incomplete.

Every non-flag argument is a value to search for. A value of @- reads the
value from standard input, @FILE reads it from FILE, and a leading @@
escapes a literal @. Values beginning with '-' cannot be passed on the
command line; supply them via @FILE, @-, or the prompt. If no values are
given, safe prompts for a single value without echoing it, which also keeps
the value out of shell history and process listings.

By default each matching secret path is printed once per line; with --keys,
each match is printed as path:key instead.
`}, c.cmdValues)

	r.Dispatch("delete", &Help{
		Summary: "Remove one or more path from the Vault",
		Usage:   "safe delete [-rfDa] PATH [PATH ...]",
		Type:    DestructiveCommand,
		Description: `
-d (--destroy) will cause KV v2 secrets to be destroyed instead of
being marked as deleted. For KV v1 backends, this would do nothing.
-a (--all) will delete (or destroy) all versions of the secret instead
of just the specified (or latest if unspecified) version.
`}, c.cmdDelete)

	r.Dispatch("undelete", &Help{
		Summary: "Undelete a soft-deleted secret from a V2 backend",
		Usage:   "safe undelete PATH [PATH ...]",
		Type:    DestructiveCommand,
		Description: `
If no version is specified, this attempts to undelete the newest version of the secret
This does not error if the specified version exists but is not deleted
This errors if the secret or version does not exist, of if the particular version has
been irrevocably destroyed. An error also occurs if a key is specified.

-a (--all) undeletes all versions of the given secret.
`}, c.cmdUndelete)

	r.Dispatch("revert", &Help{
		Summary: "Revert a secret to a previous version",
		Usage:   "safe revert PATH VERSION",
		Type:    DestructiveCommand,
		Description: `
-d (--deleted) will handle deleted versions by undeleting them, reading them, and then
redeleting them.
`}, c.cmdRevert)

	r.Dispatch("export", &Help{
		Summary: "Export one or more subtrees for migration / backup purposes",
		Usage:   "safe export [-ad] PATH [PATH ...]",
		Type:    NonDestructiveCommand,
		Description: `
Normally, the export will get only the latest version of each secret, and encode it in a format that is backwards-
compatible with pre-1.0.0 versions of safe (and newer versions).
-a (--all) will encode all versions of each secret. This will cause the export to use the V2 format, which is
incompatible with versions of safe prior to v1.0.0
-d (--deleted) will cause safe to undelete, read, and then redelete deleted secrets in order to encode them in the
backup. Without this, deleted versions will be ignored.
`}, c.cmdExport)

	r.Dispatch("import", &Help{
		Summary: "Import name/value pairs into the current Vault",
		Usage:   "safe import <backup/file.json",
		Type:    DestructiveCommand,
		Description: `
-I (--ignore-destroyed) will keep destroyed versions from being replicated in the import by
rting garbage data and then destroying it (which is originally done to preserve version numbering).
-i (--ignore-deleted) will ignore deleted versions from being written during the import.
-s (--shallow) will write only the latest version for each secret.
`}, c.cmdImport)

	r.Dispatch("move", &Help{
		Summary: "Move a secret from one path to another",
		Usage:   "safe move [-rfd] OLD-PATH NEW-PATH",
		Type:    DestructiveCommand,
		Description: `
Specifying the --deep (-d) flag will cause versions to be grabbed from the source
and overwrite all versions of the secret at the destination.
`}, c.cmdMove)

	r.Dispatch("copy", &Help{
		Summary: "Copy a secret from one path to another",
		Usage:   "safe copy [-rfd] OLD-PATH NEW-PATH",
		Type:    DestructiveCommand,
		Description: `
Specifying the --deep (-d) flag will cause all living versions to be grabbed from the source
and overwrite all versions of the secret at the destination.
`}, c.cmdCopy)

	r.Dispatch("gen", &Help{
		Summary: "Generate a random password",
		Usage:   "safe gen [-l <length>] [-p] PATH:KEY [PATH:KEY ...]",
		Type:    DestructiveCommand,
		Description: `
LENGTH defaults to 64 characters.

The following options are recognized:

  -l, --length  Specify the length of the random string to generate
	-p, --policy  Specify a regex character grouping for limiting characters used
	              to generate the password (e.g --policy a-z0-9)
`,
	}, c.cmdGen)

	r.Dispatch("uuid", &Help{
		Summary:     "Generate a new UUIDv4",
		Usage:       "safe uuid PATH[:KEY]",
		Type:        DestructiveCommand,
		Description: ``,
	}, c.cmdUuid)

	r.Dispatch("option", &Help{
		Summary: "View or edit global safe CLI options",
		Usage:   "safe option [optionname=value]",
		Type:    AdministrativeCommand,
		Description: `
Currently available options are:

@G{manage_vault_token}    If set to true, then when logging in or switching targets,
                      the '.vault-token' file in your $HOME directory that the Vault CLI uses will be
                      updated.
`,
	}, c.cmdOption)

	r.Dispatch("ssh", &Help{
		Summary: "Generate one or more new SSH RSA keypair(s)",
		Usage:   "safe ssh [NBITS] PATH [PATH ...]",
		Type:    DestructiveCommand,
		Description: `
For each PATH given, a new SSH RSA public/private keypair will be generated,
with a key strength of NBITS (which defaults to 2048).  The private keys will
be stored under the 'private' name, as a PEM-encoded RSA private key, and the
public key, formatted for use in an SSH authorized_keys file, under 'public'.
`,
	}, c.cmdSsh)

	r.Dispatch("rsa", &Help{
		Summary: "Generate a new RSA keypair",
		Usage:   "safe rsa [NBITS] PATH [PATH ...]",
		Type:    DestructiveCommand,
		Description: `
For each PATH given, a new RSA public/private keypair will be generated with a,
key strength of NBITS (which defaults to 2048).  The private keys will be stored
under the 'private' name, and the public key under the 'public' name.  Both will
be PEM-encoded.
`,
	}, c.cmdRsa)

	r.Dispatch("dhparam", &Help{
		Summary: "Generate Diffie-Helman key exchange parameters",
		Usage:   "safe dhparam [NBITS] PATH",
		Type:    DestructiveCommand,
		Description: `
NBITS defaults to 2048.
`,
	}, c.cmdDhparam)

	r.Dispatch("prompt", &Help{
		Summary: "Print a prompt (useful for scripting safe command sets)",
		Usage:   "safe echo Your Message Here:",
		Type:    NonDestructiveCommand,
	}, c.cmdPrompt)

	r.Dispatch("vault", &Help{
		Summary: "Run arbitrary Vault CLI commands against the current target",
		Usage:   "safe vault ...",
		Type:    DestructiveCommand,
	}, c.cmdVault)

	r.Dispatch("rekey", &Help{
		Summary: "Re-key your Vault with new unseal keys",
		Usage:   "safe rekey [--gpg email@address ...] [--keys #] [--threshold #]",
		Type:    DestructiveCommand,
		Description: `
Rekeys Vault with new unseal keys. This will require a quorum
of existing unseal keys to accomplish. This command can be used
to change the nubmer of unseal keys being generated via --keys,
as well as the number of keys required to unseal the Vault via
--threshold.

If --gpg flags are provided, they will be used to look up in the
local GPG keyring public keys to give Vault for encrypting the new
unseal keys (one pubkey per unseal key). Output will have the
encrypted unseal keys, matched up with the email address associated
with the public key that it was encrypted with. Additionally, a
backup of the encrypted unseal keys is located at sys/rekey/backup
in Vault.

If no --gpg flags are provided, the output will include the raw
unseal keys, and should be treated accordingly.

By default, the new seal keys will also be stored in the Vault itself,
unless you specify the --no-persist flag.  They will be written to
secret/vault/seal/keys, as key1, key2, ... keyN.
`,
	}, c.cmdRekey)

	r.Dispatch("fmt", &Help{
		Summary: "Reformat an existing name/value pair, into a new name",
		Usage:   "safe fmt FORMAT PATH OLD-NAME NEW-NAME",
		Type:    DestructiveCommand,
		Description: `
Take the value stored at PATH/OLD-NAME, format it a different way, and
then save it at PATH/NEW-NAME.  This can be useful for generating a new
password (via 'safe gen') and then crypt'ing it for use in /etc/shadow,
using the 'crypt-sha512' format.

Supported formats:

    base64          Base64 encodes the value
    bcrypt          Salt and hash the value, using bcrypt (Blowfish, in crypt format).
    crypt-md5       Salt and hash the value, using MD5, in crypt format (legacy).
    crypt-sha256    Salt and hash the value, using SHA-256, in crypt format.
    crypt-sha512    Salt and hash the value, using SHA-512, in crypt format.

`,
	}, c.cmdFmt)

	r.Dispatch("curl", &Help{
		Summary: "Issue arbitrary HTTP requests to the current Vault (for diagnostics)",
		Usage:   "safe curl [OPTIONS] METHOD REL-URI [DATA]",
		Type:    DestructiveCommand,
		Description: `
This is a debugging and diagnostics tool.  You should not need to use
'safe curl' for normal operation or interaction with a Vault.

The following OPTIONS are recognized:

  --data-only         Show only the response body, hiding the response headers.

METHOD must be one of GET, LIST, POST, or PUT.

REL-URI is the relative URI (the path component, starting with the first
forward slash) of the resource you wish to access.

DATA should be a JSON string, since almost all of the Vault API handlers
deal exclusively in JSON payloads.  GET requests should not have DATA.
Query string parameters should be appended to REL-URI, instead of being
sent as DATA.
`,
	}, c.cmdCurl)

	r.Dispatch("x509", &Help{
		Summary: "Issue / Revoke X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 <command> [OPTIONS]",
		Type:    HiddenCommand,
		Description: `
x509 provides a handful of sub-commands for issuing, signing and revoking
SSL/TLS X.509 Certificates.  It does not utilize the pki Vault backend;
instead, all certificates and RSA keys are generated by the CLI itself,
and stored wherever you tell it to.

Here are the supported commands:

  @G{x509 issue} [OPTIONS] path/to/store/cert/in

    Issues a new X.509 certificate, which can be either self-signed,
    or signed by another CA certificate, elsewhere in the Vault.
    You can control the subject name, alternate names (DNS, email and
    IP addresses), Key Usage, Extended Key Usage, and TTL/expiry.


  @G{x509 revoke} [OPTIONS] path/to/cert

    Revokes an X.509 certificate that was issued by one of our CAs.


  @G{x509 crl} [OPTIONS] path/to/ca

    Manages a certificate revocation list, primarily to renew it
    (resigning it for freshness / liveness).


  @G{x509 validate} [OPTIONS] path/to/cert

    Validate a certificate in the Vault, checking to make sure that
    its private and public keys match, checking CA signatories,
    expiration, name applicability, etc.

  @G{x509 show} path/to/cert [path/to/other/cert ...]

    Print out a human-readable description of the certificate,
    including its subject name, issuer (CA), expiration and lifetime,
    and what domains, email addresses, and IP addresses it represents.

  @G{x509 reissue} [OPTIONS] path/to/certificate

    Regenerate the certificate and key at the given path.

  @G{x509 renew} [OPTIONS] path/to/certificate

    Renew the certificate at the given path
`,
	}, c.cmdX509)

	r.Dispatch("x509 validate", &Help{
		Summary: "Validate an X.509 Certificate / Private Key",
		Usage:   "safe x509 validate [OPTIONS} path/to/certificate/or/ca",
		Type:    NonDestructiveCommand,
		Description: `
Certificate validation can be checked in many ways, and this utility
provides most of them, including:

  - Certificate matches private key (default)
  - Certificate was signed by a given CA (--signed-by x)
  - Certificate is not revoked by its CA (--not-revoked)
  - Certificate is not expired (--not-expired)
  - Certificate is valid for a given name / IP / email address (--for)
  - RSA Private Key strength,in bits (--bits)

If any of the selected validations fails, safe will immediately exit
with a non-zero exit code to signal failure.  This can be used in scripts
to check certificates and alter behavior depending on their validity.

If the validations pass, safe will continue on to execute subsequent
sub-commands.

For revocation and expiry checks there are both positive validations (i.e.
this certificate *is* expired) and negative validations (not revoked).
This approach allows you to validate that the certificate you revoked is
actually revoked, while still validating that the certificate and key match,
CA signing constraints, etc.

The following options are recognized:

  -A, --ca            Check that this is a Certificate Authority, with the
                      ability to sign other certifictes.

  -i, --signed-by X   The path to the CA that signed this certificate.
                      safe will check that the CA is the one who signed
                      the certificate, and that the signature is valid.

  -R, --not-revoked   Verify that the certificate has not been revoked
                      by its signing CA.  This makes little sense with
                      self-signed certificates.  Requires the --signed-by
                      option to be specified.

  -r, --revoked       The opposite of --not-revoked; Verify that the CA
                      has revoked the certificate.  Requires --signed-by.

  -E, --not-expired   Check that the certificate is still valid, according
                      to its NotBefore / NotAfter values.

  -e, --expired       Check that the certificate is either not yet valid,
                      or is no longer valid.

  -n, --for N         Check a name / IP / email address against the CN
                      and subject alternate names (of the correct type),
                      to see if the certificate was issued for this name.
                      This can be specified multiple times, in which case
                      all checks must pass for safe to exit zero.

  -b, --bits N        Check that the private key for this certificate
                      has the specified key size (in bits).  This can be
                      specified more than once, in which case any match
                      will pass validation.  For ECDSA keys this is the
                      curve size (256, 384, or 521); for Ed25519 it is
                      always 256.
`,
	}, c.cmdX509Validate)

	r.Dispatch("x509 issue", &Help{
		Summary: "Issue X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 issue [OPTIONS] --name cn.example.com path/to/certificate",
		Type:    DestructiveCommand,
		Description: `
Issue a new X.509 Certificate

The following options are recognized:

  -A, --ca            This certificate is a CA, and can
                      sign other certificates.

  -s, --subject       The subject name for this certificate.
                      i.e. /cn=www.example.com/c=us/st=ny...
                      If not specified, the first '--name'
                      will be used as a lone CN=...

  -i, --signed-by     Path in the Vault where the CA certificate
                      (and signing key) can be found.
                      Without this option, 'x509 issue' creates
                      self-signed certificates.

  -n, --name          Subject Alternate Name(s) for this
                      certificate.  These can be domain names,
                      IP addresses or email address -- safe will
                      figure out how to properly encode them.
                      Can (and probably should) be specified
                      more than once.

      --type          The key algorithm: 'rsa' (default), 'ec'
                      (ECDSA), or 'ed25519'.

  -b, --bits N        RSA key strength, in bits.  The only valid
                      arguments are 1024 (highly discouraged),
                      2048 and 4096.  Defaults to 4096.  Only
                      applies to '--type rsa'.

      --curve         The ECDSA curve: 'p256' (default), 'p384',
                      or 'p521'.  Only applies to '--type ec'.

  -t, --ttl           How long the new certificate will be valid
                      for.  Specified in units h (hours), m (months)
                      d (days) or y (years).  1m = 30d and 1y = 365d
                      Defaults to 10y for CA certificates and 2y otherwise.

  -u, --key-usage     An x509 key usage or extended key usage. Can be specified
                      once for each desired usage. Valid key usage values are:
                      'digital_signature', 'non_repudiation', 'key_encipherment',
                      'data_encipherment', 'key_agreement', 'key_cert_sign',
                      'crl_sign', 'encipher_only', or 'decipher_only'. Valid
                      extended key usages are 'client_auth', 'server_auth', 'code_signing',
                      'email_protection', or 'timestamping'. The default extended
                      key usages are 'server_auth' and 'client_auth'. CA certs
                      will additionally have the default key usages of key_cert_sign
                      and crl_sign. Specifying any key usages manually will override
                      all of these defaults. To specify no key usages, add 'no' as the
                      only key usage.

  -l, --sig-algorithm The algorithm that the certificate will be signed
                      with. Valid values are md5-rsa, sha1-rsa, sha256-rsa
                      sha384-rsa, sha512-rsa, sha256-rsapss, sha384-rsapss,
                      sha512-rsapss, dsa-sha1, dsa-sha256, ecdsa-sha1,
                      ecdsa-sha256, ecdsa-sha384, and ecdsa-sha512. Defaults
                      to sha512-rsa.
`,
	}, c.cmdX509Issue)

	r.Dispatch("x509 reissue", &Help{
		Summary: "Reissue X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 reissue [OPTIONS] path/to/certificate",
		Type:    DestructiveCommand,
		Description: `
Reissues an X.509 Certificate with a new key.

The following options are recognized:

  -s, --subject       The subject name for this certificate.
                      i.e. /cn=www.example.com/c=us/st=ny...
                      Unlike in x509 issue, the subject will not automatically
                      take the first SAN - if you want to update it, you will
											need to specify this flag explicitly. Use caution when
                      changing the subject of a CA cert, as it will
                      invalidate the chain of trust between the CA and
                      certificates it has signed for many client implementations.

  -n, --name          Subject Alternate Name(s) for this
                      certificate.  These can be domain names,
                      IP addresses or email address -- safe will
                      figure out how to properly encode them.
                      Can (and probably should) be specified
											more than once. This flag will not append additional SANs,
											it will act as an exhaustive list in the same way that
                      it would for a new issue command.

      --type          The key algorithm: 'rsa', 'ec' (ECDSA), or
                      'ed25519'.  Defaults to the existing
                      certificate's key algorithm.

  -b, --bits  N       RSA key strength, in bits.  The only valid
                      arguments are 1024 (highly discouraged),
                      2048 and 4096.  Defaults to the last value used
                      to (re)issue the certificate.  Only applies to
                      '--type rsa'.

      --curve         The ECDSA curve: 'p256', 'p384', or 'p521'.
                      Only applies to '--type ec'.  Defaults to the
                      existing certificate's curve.

  -i, --signed-by     Path in the Vault where the CA certificate
                      (and signing key) can be found.  If this is not
                      provided, a sibling secret named 'ca' will used
                      if it exists. This should be the same CA that
                      originally signed the certificate, but does not
                      have to be.

  -t, --ttl           How long the new certificate will be valid
                      for.  Specified in units h (hours), m (months)
                      d (days) or y (years).  1m = 30d and 1y = 365d
                      Defaults to the last TTL used to issue or renew
                      the certificate.

  -u, --key-usage     An x509 key usage or extended key usage. Can be specified
                      once for each desired usage. Valid key usage values are:
                      'digital_signature', 'non_repudiation', 'key_encipherment',
                      'data_encipherment', 'key_agreement', 'key_cert_sign',
                      'crl_sign', 'encipher_only', or 'decipher_only'. Valid
                      extended key usages are 'client_auth', 'server_auth', 'code_signing',
                      'email_protection', or 'timestamping'. The default extended
                      key usages are 'server_auth' and 'client_auth'. CA certs
                      will additionally have the default key usages of key_cert_sign
                      and crl_sign. Specifying any key usages manually will override
                      all of these defaults. To specify no key usages, add 'no' as the
											only key usage.

  -l, --sig-algorithm The algorithm that the certificate will be signed
                      with. Valid values are md5-rsa, sha1-rsa, sha256-rsa
                      sha384-rsa, sha512-rsa, sha256-rsapss, sha384-rsapss,
                      sha512-rsapss, dsa-sha1, dsa-sha256, ecdsa-sha1,
                      ecdsa-sha256, ecdsa-sha384, and ecdsa-sha512. Defaults
                      to sha512-rsa.
`,
	}, c.cmdX509Reissue)

	r.Dispatch("x509 renew", &Help{
		Summary: "Renew X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 renew [OPTIONS] path/to/certificate",
		Type:    DestructiveCommand,
		Description: `
Renew an X.509 Certificate with existing key

The following options are recognized:
  -s, --subject       The subject name for this certificate.
                      i.e. /cn=www.example.com/c=us/st=ny...
                      Unlike in x509 issue, the subject will not automatically
                      take the first SAN - if you want to update it, you will
                      need to specify this flag explicitly. Use caution when
                      changing the subject of a CA cert, as it will
                      invalidate the chain of trust between the CA and
                      certificates it has signed for many client implementations.

  -n, --name          Subject Alternate Name(s) for this
                      certificate.  These can be domain names,
                      IP addresses or email address -- safe will
                      figure out how to properly encode them.
                      Can (and probably should) be specified
                      more than once. This flag will not append additional SANs,
                      it will act as an exhaustive list in the same way that
                      it would for a new issue command.

  -i, --signed-by   	Path in the Vault where the CA certificate
                      (and signing key) can be found.  If this is not
                      provided, a sibling secret named 'ca' will used
                      if it exists.  This should be the same CA that
                      originally signed the certificate, but does not
                      have to be.

  -t, --ttl           How long the new certificate will be valid
                      for.  Specified in units h (hours), m (months)
                      d (days) or y (years).  1m = 30d and 1y = 365d
                      Defaults to the last TTL used to issue or renew
                      the certificate.

  -u, --key-usage     An x509 key usage or extended key usage. Can be specified
                      once for each desired usage. Valid key usage values are:
                      'digital_signature', 'non_repudiation', 'key_encipherment',
                      'data_encipherment', 'key_agreement', 'key_cert_sign',
                      'crl_sign', 'encipher_only', or 'decipher_only'. Valid
                      extended key usages are 'client_auth', 'server_auth', 'code_signing',
                      'email_protection', or 'timestamping'. The default extended
                      key usages are 'server_auth' and 'client_auth'. CA certs
                      will additionally have the default key usages of key_cert_sign
                      and crl_sign. Specifying any key usages manually will override
                      all of these defaults. To specify no key usages, add 'no' as the
											only key usage.

  -l, --sig-algorithm The algorithm that the certificate will be signed
                      with. Valid values are md5-rsa, sha1-rsa, sha256-rsa
                      sha384-rsa, sha512-rsa, sha256-rsapss, sha384-rsapss,
                      sha512-rsapss, dsa-sha1, dsa-sha256, ecdsa-sha1,
                      ecdsa-sha256, ecdsa-sha384, and ecdsa-sha512. Defaults
                      to sha512-rsa.
`,
	}, c.cmdX509Renew)

	r.Dispatch("x509 revoke", &Help{
		Summary: "Revoke X.509 Certificates and Certificate Authorities",
		Usage:   "safe x509 revoke [OPTIONS] path/to/certificate",
		Type:    DestructiveCommand,
		Description: `
Revoke an X.509 Certificate via its Certificate Authority

The following options are recognized:

  -i, --signed-by   Path in the Vault where the CA certificate that
                    signed the certificate to revoke resides.
`,
	}, c.cmdX509Revoke)

	r.Dispatch("x509 show", &Help{
		Summary: "Show the details of an X.509 Certificate",
		Usage:   "safe x509 show path [path ...]",
		Type:    NonDestructiveCommand,
		Description: `
When dealing with lots of different X.509 Certificates, it is important
to be able to identify what lives at each path in the vault.  This command
prints out information about a certificate, including:

  - Who issued it?
  - Is it a Certificate Authority?
  - What names / IPs is it valid for?
  - When does it expire?

`,
	}, c.cmdX509Show)

	r.Dispatch("x509 crl", &Help{
		Summary: "Manage a X.509 Certificate Authority Revocation List",
		Usage:   "safe x509 crl --renew path",
		Type:    DestructiveCommand,
		Description: `
Each X.509 Certificate Authority (especially those generated by
'safe issue --ca') carries with a list of certificates it has revoked,
by certificate serial number.  This command lets you manage that CRL.

Currently, only the --renew option is supported, and it is required:

  --renew           Sign and update the validity dates of the CRL,
                    without modifying the list of revoked certificates.
`,
	}, c.cmdX509Crl)

	env.Override(&opt)
	p, err := gocli.NewParser(&opt, os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}

	if opt.Version {
		_ = r.Execute("version")
		return
	}
	if opt.Help { //-h was given as a global arg
		_ = r.Execute("help")
		return
	}

	for p.Next() {
		opt.SkipIfExists = !opt.Clobber

		if opt.Version {
			_ = r.Execute("version")
			return
		}

		if p.Command == "" { //No recognized command was found
			_ = r.Execute("help")
			return
		}

		if opt.Help { // -h or --help was given after a command
			_ = r.Execute("help", p.Command)
			continue
		}

		_ = os.Unsetenv("VAULT_SKIP_VERIFY")
		_ = os.Unsetenv("SAFE_SKIP_VERIFY")
		if opt.Insecure {
			_ = os.Setenv("VAULT_SKIP_VERIFY", "1")
			_ = os.Setenv("SAFE_SKIP_VERIFY", "1")
		}

		err = r.Execute(p.Command, p.Args...)
		rc.Cleanup()
		if err != nil {
			var usageErr *UsageError
			if errors.As(err, &usageErr) {
				r.PrintUsage(os.Stderr, usageErr.Topic)
			} else if strings.HasPrefix(err.Error(), "USAGE") {
				_, _ = fmt.Fprintf(os.Stderr, "@Y{%s}\n", err)
			} else {
				_, _ = fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
			}
			os.Exit(1)
		}
	}

	//If there were no args given, the above loop that would try to give help
	// doesn't execute at all, so we catch it here.
	if p.Command == "" {
		_ = r.Execute("help")
	}

	if err = p.Error(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		os.Exit(1)
	}
}

func recursively(cmd string, args ...string) bool {
	y := prompt.Normal("Recursively @R{%s} @C{%s} @Y{(y/n)} ", cmd, strings.Join(args, " "))
	y = strings.TrimSpace(y)
	return y == "y" || y == "yes"
}

// For versions of safe 0.10+
// Older versions just use a map[string]map[string]string
type exportFormat struct {
	ExportVersion uint `json:"export_version"`
	//map from path string to map from version number to version info
	Data               map[string]exportSecret `json:"data"`
	RequiresVersioning map[string]bool         `json:"requires_versioning"`
}

type exportSecret struct {
	FirstVersion uint            `json:"first,omitempty"`
	Versions     []exportVersion `json:"versions"`
}

type exportVersion struct {
	Deleted   bool              `json:"deleted,omitempty"`
	Destroyed bool              `json:"destroyed,omitempty"`
	Value     map[string]string `json:"value,omitempty"`
}
