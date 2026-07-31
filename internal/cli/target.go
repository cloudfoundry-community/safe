package cli

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/cloudfoundry-community/vaultkv"
	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func (c *CLI) cmdTargets(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if len(args) != 0 {
		return r.Usage("targets")
	}

	if opt.UseTarget != "" {
		_, _ = fmt.Fprintf(os.Stderr, "@Y{Specifying --target to the targets command makes no sense; ignoring...}\n")
	}

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}
	if opt.Targets.JSON {
		type vault struct {
			Name      string `json:"name"`
			URL       string `json:"url"`
			Verify    bool   `json:"verify"`
			Namespace string `json:"namespace,omitempty"`
			Strongbox bool   `json:"strongbox"`
		}
		vaults := make([]vault, 0)

		//Sorted, like the listing this is the machine-readable half of. Ranging
		// over the map put the targets in a different order on every run, which
		// is no use to anything diffing or reviewing the output.
		names := make([]string, 0, len(cfg.Vaults))
		for name := range cfg.Vaults {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			details := cfg.Vaults[name]
			vaults = append(vaults, vault{
				Name:      name,
				URL:       details.URL,
				Verify:    !details.SkipVerify,
				Namespace: details.Namespace,
				Strongbox: !details.NoStrongbox,
			})
		}
		b, err := json.MarshalIndent(vaults, "", "  ")
		if err != nil {
			return err
		}
		_, _ = fmt.Printf("%s\n", string(b))
		return nil
	}

	wide := 0
	keys := make([]string, 0)
	for name := range cfg.Vaults {
		keys = append(keys, name)
		if len(name) > wide {
			wide = len(name)
		}
	}

	currentFmt := fmt.Sprintf("(*) @G{%%-%ds}\t@R{%%s} @Y{%%s}\n", wide)
	otherFmt := fmt.Sprintf("    %%-%ds\t@R{%%s} %%s\n", wide)
	hasCurrent := ""
	if cfg.Current != "" {
		hasCurrent = " - current target indicated with a (*)"
	}

	_, _ = fmt.Fprintf(os.Stderr, "\nKnown Vault targets%s:\n", hasCurrent)
	sort.Strings(keys)
	for _, name := range keys {
		t := cfg.Vaults[name]
		skip := "           "
		if t.SkipVerify {
			skip = " (noverify)"
		} else if strings.HasPrefix(t.URL, "http:") {
			skip = " (insecure)"
		}
		format := otherFmt
		if name == cfg.Current {
			format = currentFmt
		}
		_, _ = fmt.Fprintf(os.Stderr, format, name, skip, t.URL)
	}
	_, _ = fmt.Fprintf(os.Stderr, "\n")
	return nil
}

// isVaultAddress reports whether s reads as the address of a Vault rather than
// as a name for one. safe speaks to Vault over HTTP, so an address is what
// carries one of those two schemes and a host to reach.
func isVaultAddress(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	//A scheme is case-insensitive and comes back from url.Parse in lower case,
	// so HTTPS:// is read as the address it is.
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// targetArgs reads the two-argument form of `safe target', which gives an
// address a name, in either order. The two used to be told apart by looking
// for a literal http:// or https:// on the second one and swapping when it was
// missing, so an address typed without its scheme was taken for a name and the
// name for an address: the target was filed under the address, pointing at the
// alias, and every command run against it went to port 80 of nowhere in
// particular.
func targetArgs(first, second string) (alias, address string, err error) {
	switch {
	case isVaultAddress(second):
		return first, second, nil
	case isVaultAddress(first):
		return second, first, nil
	}
	return "", "", fmt.Errorf("neither `%s' nor `%s' is the address of a Vault: an address carries the scheme it is reached over, as in `safe target https://vault.example.com %s'", first, second, first)
}

func (c *CLI) cmdTarget(command string, args ...string) error {
	opt := c.opt
	r := c.r

	var cfg rc.Config
	if !opt.Target.Interactive && len(args) == 0 {
		var err error
		cfg, err = rc.Apply(opt.UseTarget)
		if err != nil {
			return err
		}
	} else {
		var err error
		cfg, err = rc.Read()
		if err != nil {
			return err
		}
	}
	skipverify := os.Getenv("SAFE_SKIP_VERIFY") == "1"

	if opt.UseTarget != "" {
		_, _ = fmt.Fprintf(os.Stderr, "@Y{Specifying --target to the target command makes no sense; ignoring...}\n")
	}

	printTarget := func() {
		u := cfg.URL()
		_, _ = fmt.Fprintf(os.Stderr, "Currently targeting @C{%s} at @C{%s}\n", cfg.Current, u)
		if !cfg.Verified() {
			_, _ = fmt.Fprintf(os.Stderr, "@R{Skipping TLS certificate validation}\n")
		}
		if cfg.Namespace() != "" {
			_, _ = fmt.Fprintf(os.Stderr, "Using namespace @C{%s}\n", cfg.Namespace())
		}
		if cfg.HasStrongbox() {
			urlAsURL, err := url.Parse(u)
			_, _ = fmt.Fprintf(os.Stderr, "Uses Strongbox")
			if err == nil {
				_, _ = fmt.Fprintf(os.Stderr, " at @C{%s}", vault.StrongboxURL(urlAsURL))
			}
			_, _ = fmt.Fprintf(os.Stderr, "\n")
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Does not use Strongbox\n")
		}
		_, _ = fmt.Fprintf(os.Stderr, "\n")
	}

	if opt.Target.Interactive {
		for {
			if len(cfg.Vaults) == 0 {
				_, _ = fmt.Fprintf(os.Stderr, "@R{No Vaults have been targeted yet.}\n\n")
				_, _ = fmt.Fprintf(os.Stderr, "You will need to target a Vault manually first.\n\n")
				_, _ = fmt.Fprintf(os.Stderr, "Try something like this:\n")
				_, _ = fmt.Fprintf(os.Stderr, "     @C{safe target ops https://address.of.your.vault}\n")
				_, _ = fmt.Fprintf(os.Stderr, "     @C{safe auth (github|token|ldap|okta|userpass)}\n")
				_, _ = fmt.Fprintf(os.Stderr, "\n")
				rc.Cleanup()
				os.Exit(1)
			}
			_ = r.Execute("targets")

			_, _ = fmt.Fprintf(os.Stderr, "Which Vault would you like to target?\n")
			t := prompt.Normal("@G{> }")
			err := cfg.SetCurrent(t, skipverify)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "@R{%s}\n", err)
				continue
			}
			err = cfg.Write()
			if err != nil {
				return err
			}
			if !opt.Quiet {
				skip := ""
				if !cfg.Verified() {
					skip = " (skipping TLS certificate verification)"
				}
				_, _ = fmt.Fprintf(os.Stderr, "Now targeting @C{%s} at @C{%s}@R{%s}\n\n", cfg.Current, cfg.URL(), skip)
			}
			return nil
		}
	}
	if len(args) == 0 {
		if !opt.Quiet {
			if opt.Target.JSON {
				var out struct {
					Name      string `json:"name"`
					URL       string `json:"url"`
					Verify    bool   `json:"verify"`
					Strongbox bool   `json:"strongbox"`
				}
				if cfg.Current != "" {
					out.Name = cfg.Current
					out.URL = cfg.URL()
					out.Verify = cfg.Verified()
					out.Strongbox = cfg.HasStrongbox()
				}
				b, err := json.MarshalIndent(&out, "", "  ")
				if err != nil {
					return err
				}
				_, _ = fmt.Printf("%s\n", string(b))
				return nil
			}

			if cfg.Current == "" {
				_, _ = fmt.Fprintf(os.Stderr, "@R{No Vault currently targeted}\n")
			} else {
				printTarget()
			}
		}
		return nil
	}
	if len(args) == 1 {
		err := cfg.SetCurrent(args[0], skipverify)
		if err != nil {
			return err
		}
		//Saved before it is reported: a home directory that cannot be written
		// to used to be answered with the new target on the screen and the old
		// one still in the file.
		if err := cfg.Write(); err != nil {
			return err
		}
		if !opt.Quiet {
			printTarget()
		}
		return nil
	}

	if len(args) == 2 {
		alias, url, err := targetArgs(args[0], args[1])
		if err != nil {
			return err
		}

		caCerts := []string{}
		for _, input := range opt.Target.CACerts {
			const errorPrefix = "Error reading CA certificates"
			p, _ := pem.Decode([]byte(input))
			// If not a PEM block, try to interpret it as a filepath pointing to
			// a file that contains a PEM block.
			if p == nil {
				pemData, err := os.ReadFile(input) // #nosec G304 - User-specified certificate file path
				if err != nil {
					return fmt.Errorf("%s: While reading from file `%s': %s", errorPrefix, input, err.Error())
				}

				p, _ = pem.Decode([]byte(pemData))
				if p == nil {
					return fmt.Errorf("%s: File contents could not be parsed as PEM-encoded data", errorPrefix)
				}
			}

			_, err := x509.ParseCertificate(p.Bytes)
			if err != nil {
				return fmt.Errorf("%s: While parsing certificate ASN.1 DER data: %s", errorPrefix, err.Error())
			}

			toWrite := pem.EncodeToMemory(p)
			caCerts = append(caCerts, string(toWrite))
		}

		err = cfg.SetTarget(alias, rc.Vault{
			URL:         url,
			SkipVerify:  skipverify,
			NoStrongbox: !opt.Target.Strongbox,
			Namespace:   opt.Target.Namespace,
			CACerts:     caCerts,
		})
		if err != nil {
			return err
		}
		if err := cfg.Write(); err != nil {
			return err
		}
		if !opt.Quiet {
			printTarget()
		}
		return nil
	}

	return r.Usage("target")
}

func (c *CLI) cmdTargetDelete(command string, args ...string) error {
	opt := c.opt
	r := c.r

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}
	if len(args) != 1 {
		return r.Usage("target delete")
	}

	//Resolving the name rather than deleting the map key directly: every
	// other target command reaches a target by alias or by URL, and a delete
	// that quietly matched neither reported success while leaving the target,
	// and the token stored with it, in place.
	alias, ok, err := cfg.Alias(args[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Unknown target '%s'", args[0])
	}

	delete(cfg.Vaults, alias)
	//The selection is compared by resolving it rather than by matching the
	// alias: a config written before it was recorded by alias names the current
	// target by URL, and a URL stops naming anything once the target carrying
	// it is gone. Left as it was, the selection would name a Vault that is not
	// in the file, which every later command -- including the write below --
	// reports as a missing current target.
	if _, ok, _ := cfg.Alias(cfg.Current); !ok {
		cfg.Current = ""
	}

	return cfg.Write()
}

func (c *CLI) cmdStatus(command string, args ...string) error {
	opt := c.opt

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}
	tgt, err := cfg.Vault(opt.UseTarget)
	if err != nil {
		return err
	}
	v := connect(false)

	type status struct {
		addr   string
		sealed bool
	}

	var statuses []status

	if usesStrongbox(tgt) {
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%w; are you targeting a `safe' installation?", err)
		}

		for addr, state := range st {
			statuses = append(statuses, status{addr, state == "sealed"})
		}
	} else {
		isSealed, err := v.Sealed()
		if err != nil {
			return err
		}

		statuses = append(statuses, status{targetAddress(), isSealed})
	}

	var hasSealed bool

	for _, s := range statuses {
		if s.sealed {
			hasSealed = true
			_, _ = fmt.Printf("@R{%s is sealed}\n", s.addr)
		} else {
			_, _ = fmt.Printf("@G{%s is unsealed}\n", s.addr)
		}
	}

	if opt.Status.ErrorIfSealed && hasSealed {
		return fmt.Errorf("There are sealed Vaults")
	}

	return nil
}

// shellQuote wraps s in single quotes, where a shell takes every character
// for itself, and ends and reopens the quoting around any single quote in s.
// safe env --bash is meant to be handed to eval, and a value written bare was
// read as shell source rather than as a value: a namespace of
// "prod dev; rm -rf x" printed
//
//	\export VAULT_NAMESPACE=prod dev; rm -rf x;
//
// which eval ran, setting the namespace to "prod" and doing the rest.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishQuote is shellQuote for fish, which reads a backslash inside single
// quotes as an escape where sh does not, so a backslash has to be doubled and
// a single quote is escaped in place rather than by leaving the quoting.
func fishQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "'", `\'`)
	return "'" + s + "'"
}

// envVar is one of the variables safe env reports. They are held in a slice
// rather than a map because a map is walked in a different order every time,
// and safe env --bash written to a file gave a different file on each run.
type envVar struct {
	name  string
	value string
}

func (c *CLI) cmdEnv(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if opt.Env.ForBash && opt.Env.ForFish && opt.Env.ForJSON {
		_ = r.Help(os.Stderr, "env")
		_, _ = fmt.Fprintf(os.Stderr, "@R{Only specify one of --json, --bash OR --fish.}\n")
		rc.Cleanup()
		os.Exit(1)
	}
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	skipVerify := os.Getenv("VAULT_SKIP_VERIFY")
	namespace := os.Getenv("VAULT_NAMESPACE")
	vars := []envVar{
		{"VAULT_ADDR", addr},
		{"VAULT_TOKEN", token},
		{"VAULT_SKIP_VERIFY", skipVerify},
		{"VAULT_NAMESPACE", namespace},
	}

	switch {
	case opt.Env.ForBash:
		for _, v := range vars {
			if v.value != "" {
				_, _ = fmt.Fprintf(os.Stdout, "\\export %s=%s;\n", v.name, shellQuote(v.value))
			} else {
				_, _ = fmt.Fprintf(os.Stdout, "\\unset %s;\n", v.name)
			}
		}
	case opt.Env.ForFish:
		for _, v := range vars {
			if v.value == "" {
				_, _ = fmt.Fprintf(os.Stdout, "set -u %s;\n", v.name)
			} else {
				_, _ = fmt.Fprintf(os.Stdout, "set -x %s %s;\n", v.name, fishQuote(v.value))
			}
		}
	case opt.Env.ForJSON:
		jsonEnv := &struct {
			Addr  string `json:"VAULT_ADDR"`
			Token string `json:"VAULT_TOKEN,omitempty"`
			Skip  string `json:"VAULT_SKIP_VERIFY,omitempty"`
			NS    string `json:"VAULT_NAMESPACE,omitempty"`
		}{
			Addr:  addr,
			Token: token,
			Skip:  skipVerify,
			NS:    namespace,
		}
		b, err := json.Marshal(jsonEnv)
		if err != nil {
			return err
		}
		_, _ = fmt.Printf("%s\n", string(b))
		return nil

	default:
		for _, v := range vars {
			if v.value != "" {
				_, _ = fmt.Fprintf(os.Stderr, "  @B{%s}  @G{%s}\n", v.name, v.value)
			}
		}
	}
	return nil
}

func (c *CLI) cmdAuth(command string, args ...string) error {
	opt := c.opt

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}
	v := connect(false)
	v.Client().Client.SetAuthToken("")

	method := "token"
	if len(args) > 0 {
		method = args[0]
	}

	var token string
	url := os.Getenv("VAULT_ADDR")
	target := cfg.Current
	if opt.UseTarget != "" {
		target = opt.UseTarget
	}
	_, _ = fmt.Fprintf(os.Stderr, "Authenticating against @C{%s} at @C{%s}\n", target, url)

	authMount := method
	if opt.Auth.Path != "" {
		authMount = opt.Auth.Path
	}

	switch method {
	case "token":
		if opt.Auth.Path != "" {
			return fmt.Errorf("Setting a custom path is not supported for token auth")
		}
		token = prompt.Secure("Token: ")

	case "ldap":
		username := prompt.Normal("LDAP username: ")
		password := prompt.Secure("Password: ")

		result, err := v.Client().Client.AuthLDAPMount(authMount, username, password)
		if err != nil {
			return err
		}
		token = result.ClientToken

	case "okta":
		username := prompt.Normal("Okta username: ")
		password := prompt.Secure("Password: ")

		result, err := v.Client().Client.AuthOktaMount(authMount, username, password)
		if err != nil {
			return err
		}
		token = result.ClientToken

	case "oidc":
		result, err := v.Client().Client.AuthOIDCMount(authMount)
		if err != nil {
			return err
		}
		token = result.ClientToken
	case "github":
		accessToken := prompt.Secure("Github Personal Access Token: ")

		result, err := v.Client().Client.AuthGithubMount(authMount, accessToken)
		if err != nil {
			return err
		}
		token = result.ClientToken

	case "userpass":
		username := prompt.Normal("Username: ")
		password := prompt.Secure("Password: ")

		result, err := v.Client().Client.AuthUserpassMount(authMount, username, password)
		if err != nil {
			return err
		}
		token = result.ClientToken

	case "approle":
		roleID := prompt.Normal("Role ID: ")
		secretID := prompt.Secure("Secret ID: ")

		result, err := v.Client().Client.AuthApproleMount(authMount, roleID, secretID)
		if err != nil {
			return err
		}
		token = result.ClientToken

	case "status":
		v := connect(false)
		tokenInfo, err := v.Client().Client.TokenInfoSelf()
		var tokenObj TokenStatus
		if err != nil {
			if !vaultkv.IsForbidden(err) &&
				!vaultkv.IsNotFound(err) &&
				!vaultkv.IsBadRequest(err) {
				return err
			}
		} else {
			tokenObj.info = *tokenInfo
			tokenObj.valid = true
		}

		var output string
		if opt.Auth.JSON {
			outputBytes, err := json.MarshalIndent(tokenObj, "", "  ")
			if err != nil {
				return fmt.Errorf("could not marshal JSON from TokenStatus object: %w", err)
			}

			output = string(append(outputBytes, '\n'))
		} else {
			output = tokenObj.String()
		}

		_, _ = fmt.Printf("%s", output)
		return nil

	default:
		return fmt.Errorf("Unrecognized authentication method '%s'", method)
	}

	//The token belongs to the target that was authenticated against, which
	// -T may have named, and storing it must not move the current target.
	if err := cfg.SetTokenFor(target, token); err != nil {
		return err
	}
	return cfg.Write()
}

func (c *CLI) cmdLogout(command string, args ...string) error {
	opt := c.opt

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}

	target := cfg.Current
	if opt.UseTarget != "" {
		target = opt.UseTarget
	}
	//Dropping the token of the target that was named, rather than of the
	// current one, which is the only target SetToken can reach.
	if err := cfg.SetTokenFor(target, ""); err != nil {
		return err
	}
	if err := cfg.Write(); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, "Successfully logged out of @C{%s}\n", target)
	return nil
}

func (c *CLI) cmdRenew(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if len(args) > 0 {
		if len(args) != 1 || args[0] != "all" {
			return r.Usage("renew")
		}
		//Naming one target and asking for all of them says two things at
		// once. The rest of safe says which one it went with; this said
		// nothing and renewed them all.
		if opt.UseTarget != "" {
			_, _ = fmt.Fprintf(os.Stderr, "@Y{Specifying --target while renewing all targets makes no sense; ignoring...}\n")
		}
		//Reading the config rather than applying it: what the current target
		// is has no bearing on renewing every target, and applying it here
		// would leave its settings standing over the first target renewed.
		cfg, err := rc.Read()
		if err != nil {
			return err
		}
		//Renewing every one of no targets printed nothing and succeeded, so a
		// run against a config that had been lost said as much as one that
		// had renewed everything.
		if len(cfg.Vaults) == 0 {
			_, _ = fmt.Fprintf(os.Stderr, "@Y{no targets to renew.}\n")
			_, _ = fmt.Fprintf(os.Stderr, "Try @C{safe renew} to renew the token in your environment,\n")
			_, _ = fmt.Fprintf(os.Stderr, " or @C{safe target https://your-vault alias} to configure one.\n")
			return nil
		}
		//Each target is applied to the environment the command started with,
		// not to the one the target before it left behind. A target that says
		// nothing about certificate verification, a CA bundle, or a namespace
		// was otherwise talked to on the terms of whichever target happened to
		// be renewed before it.
		env := rc.SnapshotEnv()
		defer env.Restore()

		//In the order the targets are named everywhere else. Walking the
		// config gave them over in whatever order it held them, so two runs
		// over the same targets reported them differently.
		aliases := make([]string, 0, len(cfg.Vaults))
		for alias := range cfg.Vaults {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)

		failed := 0
		for _, vault := range aliases {
			env.Restore()
			if _, err := rc.Apply(vault); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "@R{failed to apply config for %s: %s}\n", vault, err)
				failed++
				continue
			}
			if os.Getenv("VAULT_TOKEN") == "" {
				_, _ = fmt.Printf("skipping @C{%s} - no token found.\n", vault)
				continue
			}
			_, _ = fmt.Printf("renewing token against @C{%s}...\n", vault)
			//A target that cannot be connected to is one more failure to
			// report at the end. connect would print advice about targeting a
			// Vault -- which names no target and makes no sense here -- and
			// end the run where it stood, leaving the targets after it
			// unrenewed and unmentioned.
			v, err := connectOrErr(true)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "@R{failed to connect to %s: %s}\n", vault, err)
				failed++
				continue
			}
			if err := v.RenewLease(); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "@R{failed to renew token against %s: %s}\n", vault, err)
				failed++
			}
		}
		if failed > 0 {
			return fmt.Errorf("failed to renew %d token(s)", failed)
		}
		return nil
	}

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	v := connect(true)
	if err := v.RenewLease(); err != nil {
		return err
	}
	return nil
}
