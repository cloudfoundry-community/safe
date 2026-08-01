package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cloudfoundry-community/vaultkv"
	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func (c *CLI) cmdLocal(command string, args ...string) error {
	opt := c.opt

	if !opt.Local.Memory && opt.Local.File == "" {
		return fmt.Errorf("Please specify either --memory or --file <path>")
	}
	if opt.Local.Memory && opt.Local.File != "" {
		return fmt.Errorf("Please specify either --memory or --file <path>, but not both")
	}

	engine, err := selectEngine(opt.Local.Engine)
	if err != nil {
		return fmt.Errorf("@R{%s}", err)
	}

	var port int
	if opt.Local.Port != 0 {
		port = opt.Local.Port
	} else {
		for port = 8201; port < 9999; port++ {
			conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				break
			}
			_ = conn.Close()
		}
	}

	keys := make([]string, 0)
	if !opt.Local.Memory {
		opt.Local.File = filepath.ToSlash(opt.Local.File)
		if _, err := os.Stat(opt.Local.File); err == nil || !os.IsNotExist(err) {
			keys = append(keys, pr("Unseal Key", false, true))
		}
	}

	configBody, err := buildLocalConfig(localConfigParams{
		port:       port,
		memory:     opt.Local.Memory,
		filePath:   opt.Local.File,
		engineName: engine.Name(),
		global:     opt.Local.Config,
		listener:   opt.Local.Listener,
	})
	if err != nil {
		return err
	}

	f, err := os.CreateTemp("", "kazoo")
	if err != nil {
		return err
	}
	if _, err := f.WriteString(configBody); err != nil {
		return fmt.Errorf("Unable to write the %s config: %w", engine.Title(), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("Unable to write the %s config: %w", engine.Title(), err)
	}

	// Capture the server's output so a bad config (which safe deliberately
	// does not validate) is reported instead of surfacing as a startup
	// timeout. Config-parse errors go to stdout, so capture both streams.
	// Pointing Stdout and Stderr at the same writer is the documented way
	// to avoid an interleaving race (os/exec serializes the writes).
	var engineOutput lockedBuffer
	echan := make(chan error)
	// #nosec G204 - engine.Binary() is a PATH lookup of a known name, and
	// f.Name() is a temp file we created
	cmd := exec.Command(engine.Binary(), "server", "-config", f.Name())
	cmd.Stdout = &engineOutput
	cmd.Stderr = &engineOutput
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s server: %w", engine.Title(), err)
	}
	go func() {
		echan <- cmd.Wait()
	}()
	signal.Ignore(syscall.SIGINT)

	die := func(err error) {
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "@Y{shutting down %s...}\n", engine.Title())
		// On the startup path the wait goroutine has usually reaped the
		// process already; that is a clean shutdown, not a kill failure.
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			_, _ = fmt.Fprintf(os.Stderr, "@R{NOTE: Unable to terminate the %s process.}\n", engine.Title())
			_, _ = fmt.Fprintf(os.Stderr, "@R{      You may have some environmental cleanup to do.}\n")
			_, _ = fmt.Fprintf(os.Stderr, "@R{      Apologies.}\n")
		}
		rc.Cleanup()
		os.Exit(1)
	}

	cfg, err := rc.Apply("")
	if err != nil {
		return err
	}
	name := opt.Local.As
	if name == "" {
		name = RandomName()
		var n int
		for n = 15; n > 0; n-- {
			if existing, _ := cfg.Vault(name); existing == nil {
				break
			}
			name = RandomName()
		}
		if n == 0 {
			die(fmt.Errorf("I was unable to come up with a cool name for your local %s server.  Please try naming it with --as", engine.Title()))
		}
	} else {
		if existing, _ := cfg.Vault(name); existing != nil {
			die(fmt.Errorf("You already have '%s' as a Vault target", name))
		}
	}
	previous := cfg.Current

	_ = cfg.SetTarget(name, rc.Vault{
		URL:         fmt.Sprintf("http://127.0.0.1:%d", port),
		SkipVerify:  false,
		NoStrongbox: true,
	})
	_ = cfg.Write()

	if _, err := rc.Apply(""); err != nil {
		return err
	}
	v := connect(false)

	const maxStartupWait = 5 * time.Second
	const betweenChecksWait = 250 * time.Millisecond
	startupCheckBeginTime := time.Now()
	for {
		// If the server exited before becoming ready (most often a rejected
		// config), report its own error rather than waiting out the timeout.
		select {
		case waitErr := <-echan:
			die(fmt.Errorf("%s exited before it became ready: %s", engine.Title(), engineStartupError(engineOutput.String(), waitErr)))
		default:
		}

		_, err := v.Sealed()
		if err == nil {
			break
		}

		if time.Since(startupCheckBeginTime) > maxStartupWait {
			if msg := strings.TrimSpace(engineOutput.String()); msg != "" {
				die(fmt.Errorf("Timed out waiting for %s to begin listening: %s\n%s", engine.Title(), err, msg))
			}
			die(fmt.Errorf("Timed out waiting for %s to begin listening: %s", engine.Title(), err))
		}

		time.Sleep(betweenChecksWait)
	}

	token := ""
	if len(keys) == 0 {
		keys, token, err = v.Init(1, 1)
		if err != nil {
			die(fmt.Errorf("Unable to initialize the new (temporary) %s server: %w", engine.Title(), err))
		}
	}

	if err = v.Unseal(keys); err != nil {
		die(fmt.Errorf("Unable to unseal the new (temporary) %s server: %w", engine.Title(), err))
	}
	token, err = resolveRootToken(token, func() (string, error) {
		return v.NewRootToken(keys)
	})
	if err != nil {
		die(fmt.Errorf("Unable to generate a new root token: %w", err))
	}

	_ = cfg.SetToken(token)
	_ = os.Setenv("VAULT_TOKEN", token)
	_ = cfg.Write()
	v = connect(true)

	exists, err := v.MountExists("secret")
	if err != nil {
		return fmt.Errorf("Could not list mounts: %w", err)
	}

	if !exists {
		err := v.AddMount("secret", 2)
		if err != nil {
			return fmt.Errorf("Could not add `secret' mount: %w", err)
		}
		_, _ = fmt.Printf("safe has mounted the @C{secret} backend\n\n")
	}

	s := vault.NewSecret()
	_ = s.Set("knock", "knock", false)
	_ = v.Write("secret/handshake", s)

	if !opt.Quiet {
		_, _ = fmt.Fprintf(os.Stderr, "Now targeting (temporary) @Y{%s} at @C{%s}\n", cfg.Current, cfg.URL())
		if opt.Local.Memory {
			_, _ = fmt.Fprintf(os.Stderr, "@R{This %s server is MEMORY-BACKED!}\n", engine.Title())
			_, _ = fmt.Fprintf(os.Stderr, "If you want to @Y{retain your secrets} be sure to @C{safe export}.\n")
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Storing data (encrypted) in @G{%s}\n", opt.Local.File)
			_, _ = fmt.Fprintf(os.Stderr, "Your %s Seal Key is @M{%s}\n", engine.Title(), keys[0])
		}
		_, _ = fmt.Fprintf(os.Stderr, "Ctrl-C to shut down the %s server\n", engine.Title())
	}

	err = <-echan
	_, _ = fmt.Fprintf(os.Stderr, "%s terminated normally, cleaning up...\n", engine.Title())
	{
		var applyErr error
		cfg, applyErr = rc.Apply("")
		if applyErr != nil {
			return applyErr
		}
	}
	if cfg.Current == name {
		cfg.Current = ""
		if _, found, _ := cfg.Find(previous); found {
			cfg.Current = previous
		}
	}
	delete(cfg.Vaults, name)
	_ = cfg.Write()
	return err
}

func (c *CLI) cmdInit(command string, args ...string) error {
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

	if opt.Init.NKeys == 0 {
		opt.Init.NKeys = 5
	}
	if opt.Init.Threshold == 0 {
		if opt.Init.NKeys > 3 {
			opt.Init.Threshold = opt.Init.NKeys - 2
		} else {
			opt.Init.Threshold = opt.Init.NKeys
		}
	}

	if opt.Init.Single {
		opt.Init.NKeys = 1
		opt.Init.Threshold = 1
	}

	/* initialize the vault */
	keys, token, err := v.Init(opt.Init.NKeys, opt.Init.Threshold)
	if err != nil {
		return err
	}

	if token == "" {
		return fmt.Errorf("initialization error: token was nil")
	}

	/* auth with the new root token, transparently */
	//The token belongs to the Vault that was just initialized, which -T may
	// have named rather than the current target.
	target := cfg.Current
	if opt.UseTarget != "" {
		target = opt.UseTarget
	}
	if err := cfg.SetTokenFor(target, token); err != nil {
		return err
	}
	if err := cfg.Write(); err != nil {
		return err
	}
	_ = os.Setenv("VAULT_TOKEN", token)
	v = connect(true)

	/* be nice to the machines and machine-like intelligences */
	if opt.Init.JSON {
		out := struct {
			Keys  []string `json:"seal_keys"`
			Token string   `json:"root_token"`
		}{
			Keys:  keys,
			Token: token,
		}

		b, err := json.MarshalIndent(&out, "", "  ")
		if err != nil {
			return err
		}
		_, _ = fmt.Printf("%s\n", string(b))
	} else {
		for i, key := range keys {
			_, _ = fmt.Printf("Unseal Key #%d: @G{%s}\n", i+1, key)
		}
		_, _ = fmt.Printf("Initial Root Token: @M{%s}\n", token)
		_, _ = fmt.Printf("\n")
		if opt.Init.NKeys == 1 {
			_, _ = fmt.Printf("Vault initialized with a single key. Please securely distribute it.\n")
			_, _ = fmt.Printf("When the Vault is re-sealed, restarted, or stopped, you must provide\n")
			_, _ = fmt.Printf("this key to unseal it again.\n")
			_, _ = fmt.Printf("\n")
			_, _ = fmt.Printf("Vault does not store the master key. Without the above unseal key,\n")
			_, _ = fmt.Printf("your Vault will remain permanently sealed.\n")

		} else if opt.Init.NKeys == opt.Init.Threshold {
			_, _ = fmt.Printf("Vault initialized with %d keys. Please securely distribute the\n", opt.Init.NKeys)
			_, _ = fmt.Printf("above keys. When the Vault is re-sealed, restarted, or stopped,\n")
			_, _ = fmt.Printf("you must provide all of these keys to unseal it again.\n")
			_, _ = fmt.Printf("\n")
			_, _ = fmt.Printf("Vault does not store the master key. Without all %d of the keys,\n", opt.Init.Threshold)
			_, _ = fmt.Printf("your Vault will remain permanently sealed.\n")

		} else {
			_, _ = fmt.Printf("Vault initialized with %d keys and a key threshold of %d. Please\n", opt.Init.NKeys, opt.Init.Threshold)
			_, _ = fmt.Printf("securely distribute the above keys. When the Vault is re-sealed,\n")
			_, _ = fmt.Printf("restarted, or stopped, you must provide at least %d of these keys\n", opt.Init.Threshold)
			_, _ = fmt.Printf("to unseal it again.\n")
			_, _ = fmt.Printf("\n")
			_, _ = fmt.Printf("Vault does not store the master key. Without at least %d keys,\n", opt.Init.Threshold)
			_, _ = fmt.Printf("your Vault will remain permanently sealed.\n")
		}

		_, _ = fmt.Printf("\n")
	}

	if !opt.Init.Sealed {
		addrs := []string{}
		gotStrongbox := false
		if usesStrongbox(tgt) {
			if st, err := v.Strongbox(); err == nil {
				gotStrongbox = true
				for addr := range st {
					addrs = append(addrs, addr)
				}
			}
		}
		if !gotStrongbox {
			addrs = append(addrs, v.Client().Client.VaultURL.String())
		}

		for _, addr := range addrs {
			if err := v.SetURL(addr); err != nil {
				return fmt.Errorf("invalid vault address %s: %w", addr, err)
			}
			if err := v.Unseal(keys); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "!!! unable to unseal newly-initialized vault (at %s): %s\n", addr, err)
			}
		}

		//Make a best attempt to wait until Vault has figured out which node should be the master.
		// This doesn't error out if no master comes forward, as there may be a cluster but no
		// Strongbox. In that case, it may error later, but we've done what we can.
		const maxAttempts = 5
		const waitInterval = 500 * time.Millisecond
		var currentAttempt int
	waitMaster:
		for currentAttempt < maxAttempts {
			for _, addr := range addrs {
				if err := v.SetURL(addr); err != nil {
					return fmt.Errorf("invalid vault address %s: %w", addr, err)
				}
				if err := v.Client().Client.Health(false); err == nil {
					break waitMaster
				}
			}
			currentAttempt++
			time.Sleep(waitInterval)
		}

		if !opt.Init.NoMount {
			exists, err := v.MountExists("secret")
			if err != nil {
				return fmt.Errorf("Could not list mounts: %w", err)
			}

			if !exists {
				err := v.AddMount("secret", 2)
				if err != nil {
					return fmt.Errorf("Could not add `secret' mount: %w", err)
				}

				if !opt.Init.JSON {
					_, _ = fmt.Printf("safe has mounted the @C{secret} backend\n")
				}
			}
		}

		/* write secret/handshake, just for fun */
		s := vault.NewSecret()
		_ = s.Set("knock", "knock", false)
		_ = v.Write("secret/handshake", s)

		if !opt.Init.JSON {
			_, _ = fmt.Printf("safe has unsealed the Vault for you, and written a test value\n")
			_, _ = fmt.Printf("at @C{secret/handshake}.\n\n")
		}

		/* write seal keys to the vault */
		if opt.Init.Persist {
			if err := v.SaveSealKeys(keys); err != nil {
				return fmt.Errorf("failed to save seal keys: %w", err)
			}
			if !opt.Init.JSON {
				_, _ = fmt.Printf("safe has written the unseal keys at @C{secret/vault/seal/keys}\n")
			}
		}
	} else {
		if !opt.Init.JSON {
			_, _ = fmt.Printf("Your Vault has been left sealed.\n")
		}
	}

	if !opt.Init.JSON {
		_, _ = fmt.Printf("\n")
		_, _ = fmt.Printf("You have been automatically authenticated to the Vault with the\n")
		_, _ = fmt.Printf("initial root token.  Be safe out there!\n")
		_, _ = fmt.Printf("\n")
	}

	return nil
}

func (c *CLI) cmdUnseal(command string, args ...string) error {
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

	var addrs []string
	if usesStrongbox(tgt) {
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%w; are you targeting a `safe' installation?", err)
		}

		for addr, state := range st {
			if state == "sealed" {
				addrs = append(addrs, addr)
			}
		}
	} else {
		isSealed, err := v.Sealed()
		if err != nil {
			return err
		}

		if isSealed {
			addrs = append(addrs, targetAddress())
		}
	}

	if len(addrs) == 0 {
		_, _ = fmt.Printf("@C{all vaults are already unsealed!}\n")
		return nil
	}

	if err := v.SetURL(addrs[0]); err != nil {
		return err
	}
	nkeys, err := v.SealKeys()
	if err != nil {
		return err
	}

	_, _ = fmt.Printf("You need %d key(s) to unseal the vaults.\n\n", nkeys)
	keys := make([]string, nkeys)

	for i := range nkeys {
		keys[i] = pr(fmt.Sprintf("Key #%d", i+1), false, true)
	}

	for _, addr := range addrs {
		_, _ = fmt.Printf("unsealing @G{%s}...\n", addr)
		if err := v.SetURL(addr); err != nil {
			return err
		}
		err = v.Unseal(keys)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CLI) cmdSeal(command string, args ...string) error {
	opt := c.opt

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}
	tgt, err := cfg.Vault(opt.UseTarget)
	if err != nil {
		return err
	}
	v := connect(true)

	var toSeal []string
	if usesStrongbox(tgt) {
		st, err := v.Strongbox()
		if err != nil {
			return fmt.Errorf("%w; are you targeting a `safe' installation?", err)
		}

		for addr, state := range st {
			if state == "unsealed" {
				toSeal = append(toSeal, addr)
			}
		}
	} else {
		isSealed, err := v.Sealed()
		if err != nil {
			return err
		}
		if !isSealed {
			toSeal = append(toSeal, targetAddress())
		}
	}

	if len(toSeal) == 0 {
		_, _ = fmt.Printf("@C{all vaults are already sealed!}\n")
	}

	consecutiveFailures := 0
	const maxFailures = 10
	const attemptInterval = 500 * time.Millisecond

	for len(toSeal) > 0 {
		for i, addr := range toSeal {
			if err := v.SetURL(addr); err != nil {
				return err
			}
			err := v.Client().Client.Health(false)
			if err != nil {
				if vaultkv.IsErrStandby(err) {
					continue
				}

				return err
			}

			sealed, err := v.Seal()
			if err != nil {
				return err
			}

			if sealed {
				_, _ = fmt.Printf("sealed @G{%s}...\n", addr)
				//Remove sealed Vault from list
				toSeal[i], toSeal[len(toSeal)-1] = toSeal[len(toSeal)-1], toSeal[i]
				toSeal = toSeal[:len(toSeal)-1]
				consecutiveFailures = 0
				break
			}
		}
		if len(toSeal) > 0 {
			consecutiveFailures++
			if consecutiveFailures == maxFailures {
				return fmt.Errorf("timed out waiting for leader election")
			}
			time.Sleep(attemptInterval)
		}
	}

	return nil
}

func (c *CLI) cmdVault(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if opt.SkipIfExists {
		_, _ = fmt.Fprintf(os.Stderr, "@C{--no-clobber} @Y{specified, but is ignored for} @C{safe vault}\n")
	}

	proxy, err := vault.NewProxyRouter()
	if err != nil {
		return err
	}

	// OpenBao kept Vault's command surface when it forked, so the same
	// arguments pass through unchanged to whichever engine is resolved.
	// There is no --engine flag here (every argument belongs to the engine),
	// so the preference comes from SAFE_ENGINE or auto-detection.
	engine, err := selectEngine("")
	if err != nil {
		return fmt.Errorf("@R{%s}", err)
	}

	cmd := exec.Command(engine.Binary(), args...) // #nosec G204,G702 -- passthrough to the engine binary with user-supplied args is the intended behavior
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	//If the command is vault status, we don't want to expose the VAULT_NAMESPACE envvar
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			if arg == "status" {
				_ = os.Unsetenv("VAULT_NAMESPACE")
			}
			break
		}
	}
	cmd.Env = os.Environ()

	//Make sure we don't accidentally specify a http_proxy and a HTTP_PROXY
	for i := range cmd.Env {
		parts := strings.Split(cmd.Env[i], "=")
		if len(parts) < 2 {
			continue
		}
		if parts[0] == "http_proxy" || parts[0] == "https_proxy" || parts[0] == "no_proxy" {
			cmd.Env[i] = strings.ToUpper(parts[0]) + "=" + strings.Join(parts[1:], "=")
		}
	}

	if proxy.ProxyConf.HTTPProxy != "" {
		cmd.Env = append(cmd.Env, "HTTP_PROXY="+proxy.ProxyConf.HTTPProxy)
	}

	if proxy.ProxyConf.HTTPSProxy != "" {
		cmd.Env = append(cmd.Env, "HTTPS_PROXY="+proxy.ProxyConf.HTTPSProxy)
	}

	if proxy.ProxyConf.NoProxy != "" {
		cmd.Env = append(cmd.Env, "NO_PROXY="+proxy.ProxyConf.NoProxy)
	}

	err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func (c *CLI) cmdRekey(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	unsealKeys := 5 // default to 5
	var gpgKeys []string
	if len(opt.Rekey.GPG) > 0 {
		unsealKeys = len(opt.Rekey.GPG)
		for _, email := range opt.Rekey.GPG {
			output, err := exec.Command("gpg", "--export", email).Output() // #nosec G204 - GPG email arguments are user-provided but not shell-interpreted
			if err != nil {
				return fmt.Errorf("Failed to retrieve GPG key for %s from local keyring: %s", email, err.Error())
			}

			// gpg --export returns 0, with no stdout if the key wasn't found, so handle that
			if len(output) == 0 {
				return fmt.Errorf("No GPG key found for %s in the local keyring", email)
			}
			gpgKeys = append(gpgKeys, base64.StdEncoding.EncodeToString(output))
		}
	}

	// if specified, --unseal-keys takes priority, then the number of --gpg-keys, and a default of 5
	if opt.Rekey.NKeys != 0 {
		unsealKeys = opt.Rekey.NKeys
	}
	if len(opt.Rekey.GPG) > 0 && unsealKeys != len(opt.Rekey.GPG) {
		return fmt.Errorf("Both --gpg and --keys were specified, and their counts did not match.")
	}

	// if --threshold isn't specified, use a default (unless default is > the number of keys
	if opt.Rekey.Threshold == 0 {
		opt.Rekey.Threshold = 3
		if opt.Rekey.Threshold > unsealKeys {
			opt.Rekey.Threshold = unsealKeys
		}
	}
	if opt.Rekey.Threshold > unsealKeys {
		return fmt.Errorf("You specified only %d unseal keys, but are requiring %d keys to unseal vault. This is bad.", unsealKeys, opt.Rekey.Threshold)
	}
	if opt.Rekey.Threshold < 2 && unsealKeys > 1 {
		return fmt.Errorf("When specifying more than 1 unseal key, you must also have more than one key required to unseal.")
	}

	v := connect(true)
	keys, err := v.ReKey(unsealKeys, opt.Rekey.Threshold, gpgKeys)
	if err != nil {
		return err
	}

	if opt.Rekey.Persist {
		if err := v.SaveSealKeys(keys); err != nil {
			return fmt.Errorf("failed to save seal keys: %w", err)
		}
	}

	_, _ = fmt.Printf("@G{Your Vault has been re-keyed.} Please take note of your new unseal keys and @R{store them safely!}\n")
	for i, key := range keys {
		if len(opt.Rekey.GPG) == len(keys) {
			_, _ = fmt.Printf("Unseal key for @c{%s}:\n@y{%s}\n", opt.Rekey.GPG[i], key)
		} else {
			_, _ = fmt.Printf("Unseal key %d: @y{%s}\n", i+1, key)
		}
	}

	return nil
}
