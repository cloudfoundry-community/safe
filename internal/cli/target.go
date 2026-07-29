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

		for name, details := range cfg.Vaults {
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
		if !opt.Quiet {
			printTarget()
		}
		return cfg.Write()
	}

	if len(args) == 2 {
		var err error
		alias, url := args[0], args[1]
		if !strings.HasPrefix(args[1], "http://") &&
			!strings.HasPrefix(args[1], "https://") {
			alias, url = url, alias
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
		if !opt.Quiet {
			printTarget()
		}
		return cfg.Write()
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
	if cfg.Current == alias {
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

func (c *CLI) cmdEnv(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if opt.Env.ForBash && opt.Env.ForFish && opt.Env.ForJSON {
		r.Help(os.Stderr, "env")
		_, _ = fmt.Fprintf(os.Stderr, "@R{Only specify one of --json, --bash OR --fish.}\n")
		rc.Cleanup()
		os.Exit(1)
	}
	vars := map[string]string{
		"VAULT_ADDR":        os.Getenv("VAULT_ADDR"),
		"VAULT_TOKEN":       os.Getenv("VAULT_TOKEN"),
		"VAULT_SKIP_VERIFY": os.Getenv("VAULT_SKIP_VERIFY"),
		"VAULT_NAMESPACE":   os.Getenv("VAULT_NAMESPACE"),
	}

	switch {
	case opt.Env.ForBash:
		for name, value := range vars {
			if value != "" {
				_, _ = fmt.Fprintf(os.Stdout, "\\export %s=%s;\n", name, value)
			} else {
				_, _ = fmt.Fprintf(os.Stdout, "\\unset %s;\n", name)
			}
		}
	case opt.Env.ForFish:
		for name, value := range vars {
			if value == "" {
				_, _ = fmt.Fprintf(os.Stdout, "set -u %s;\n", name)
			} else {
				_, _ = fmt.Fprintf(os.Stdout, "set -x %s %s;\n", name, value)
			}
		}
	case opt.Env.ForJSON:
		jsonEnv := &struct {
			Addr  string `json:"VAULT_ADDR"`
			Token string `json:"VAULT_TOKEN,omitempty"`
			Skip  string `json:"VAULT_SKIP_VERIFY,omitempty"`
			NS    string `json:"VAULT_NAMESPACE,omitempty"`
		}{
			Addr:  vars["VAULT_ADDR"],
			Token: vars["VAULT_TOKEN"],
			Skip:  vars["VAULT_SKIP_VERIFY"],
			NS:    vars["VAULT_NAMESPACE"],
		}
		b, err := json.Marshal(jsonEnv)
		if err != nil {
			return err
		}
		_, _ = fmt.Printf("%s\n", string(b))
		return nil

	default:
		for name, value := range vars {
			if value != "" {
				_, _ = fmt.Fprintf(os.Stderr, "  @B{%s}  @G{%s}\n", name, value)
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
		cfg, err := rc.Apply("")
		if err != nil {
			return err
		}
		failed := 0
		for vault := range cfg.Vaults {
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
			v := connect(true)
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
