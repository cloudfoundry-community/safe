package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
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

// localVaultURL is where the server cmdLocal starts can be reached: loopback,
// plain HTTP, on the port cmdLocal chose.
func localVaultURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// connectLocal builds a client aimed at the server cmdLocal launched --
// deliberately not connect(), which derives its target from the environment
// as applied from ~/.saferc. Everything cmdLocal does to its server -- the
// readiness poll, Init, Unseal, the mount -- must go to the process it
// started, and no state of ~/.saferc (stale, lost to a concurrent writer, or
// corrupted) may aim those calls anywhere else. Init against a foreign vault
// is the incident this guards against.
func connectLocal(port int, token string) (*vault.Vault, error) {
	return vault.NewVault(vault.VaultConfig{
		URL:   localVaultURL(port),
		Token: token,
	})
}

// localPortScanStart is where automatic port selection begins scanning.
const localPortScanStart = 8201

// findCandidatePort returns the first port at or after start that accepts a
// loopback bind, probing with the same listen(2) the server child performs.
// The old dial probe called a port free when connecting to it failed, which
// TIME_WAIT remnants pass while the bind still fails. The probe listener
// closes before the server launches, so the answer is only advisory: the
// child's own bind failure is authoritative, and cmdLocal retries on it.
func findCandidatePort(start int) (int, error) {
	for port := start; port < 9999; port++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = l.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no free local port found between %d and 9998", start)
}

// localServer is one launched attempt at running the engine.
type localServer struct {
	cmd     *exec.Cmd
	echan   chan error
	output  *lockedBuffer
	cfgFile string
}

// launchLocalServer renders the config, writes it to a temp file, and starts
// the engine on it. The returned echan is buffered so the exit of a server
// nobody is currently waiting on does not strand the reaper goroutine.
func launchLocalServer(engine Engine, params localConfigParams) (*localServer, error) {
	configBody, err := buildLocalConfig(params)
	if err != nil {
		return nil, err
	}

	f, err := os.CreateTemp("", "kazoo")
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(configBody); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("Unable to write the %s config: %w", engine.Title(), err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("Unable to write the %s config: %w", engine.Title(), err)
	}

	// Capture the server's output so a bad config (which safe deliberately
	// does not validate) is reported instead of surfacing as a startup
	// timeout. Config-parse errors go to stdout, so capture both streams.
	// Pointing Stdout and Stderr at the same writer is the documented way
	// to avoid an interleaving race (os/exec serializes the writes).
	var output lockedBuffer
	echan := make(chan error, 1)
	// #nosec G204 - engine.Binary() is a PATH lookup of a known name, and
	// f.Name() is a temp file we created
	cmd := exec.Command(engine.Binary(), "server", "-config", f.Name())
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("failed to start %s server: %w", engine.Title(), err)
	}
	go func() {
		echan <- cmd.Wait()
	}()
	return &localServer{cmd: cmd, echan: echan, output: &output, cfgFile: f.Name()}, nil
}

// waitLocalReady polls until the launched server answers on its port. It
// returns nil on readiness, and otherwise the reason: the server's own exit,
// in its own words, or a timeout.
//
// An answer on the port is not readiness by itself. If the child lost the
// bind race, whatever won it answers there instead -- and treating that
// stranger as ready is how a safe once fed Init to a vault it never started.
// The child's own account of a bind failure closes most of that hole but
// arrives asynchronously: a stranger who already holds the port answers the
// first probe before the child has even tried to bind. So readiness demands
// positive proof of ownership -- the child's startup banner, which both
// Vault and OpenBao print only after their listen(2) succeeded -- plus an
// answer on the port. The probe carries its own short timeout so a holder
// that accepts and never speaks HTTP cannot stall the poll.
func waitLocalReady(engine Engine, port int, srv *localServer) error {
	// The ceiling is generous because it is not the usual way out: a server
	// that fails exits, and the exit is caught on the spot. The timeout only
	// catches one that hangs without a word, and a loaded machine can make
	// an honest startup look like that for longer than you would think.
	const maxStartupWait = 30 * time.Second
	const betweenChecksWait = 250 * time.Millisecond
	probe := &http.Client{Timeout: time.Second}
	begin := time.Now()
	var lastErr error
	for {
		// If the server exited before becoming ready (most often a rejected
		// config), report its own error rather than waiting out the timeout.
		select {
		case waitErr := <-srv.echan:
			return fmt.Errorf("%s exited before it became ready: %s", engine.Title(), engineStartupError(srv.output.String(), waitErr))
		default:
		}

		// The child's word outranks anything the port says: once it reports
		// the bind failed, whoever answers there is a stranger. Reap the
		// child and report its own account.
		if isAddrInUse(srv.output.String()) {
			waitErr := <-srv.echan
			return fmt.Errorf("%s exited before it became ready: %s", engine.Title(), engineStartupError(srv.output.String(), waitErr))
		}

		if strings.Contains(srv.output.String(), "server started!") {
			resp, err := probe.Get(localVaultURL(port) + "/v1/sys/seal-status")
			if err == nil {
				_ = resp.Body.Close()
				return nil
			}
			lastErr = err
		}

		if time.Since(begin) > maxStartupWait {
			reason := "it never reported its listener up"
			if lastErr != nil {
				reason = lastErr.Error()
			}
			if msg := strings.TrimSpace(srv.output.String()); msg != "" {
				return fmt.Errorf("Timed out waiting for %s to begin listening: %s\n%s", engine.Title(), reason, msg)
			}
			return fmt.Errorf("Timed out waiting for %s to begin listening: %s", engine.Title(), reason)
		}

		time.Sleep(betweenChecksWait)
	}
}

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

	autoScan := opt.Local.Port == 0
	port := opt.Local.Port
	if autoScan {
		port, err = findCandidatePort(localPortScanStart)
		if err != nil {
			return err
		}
	}

	keys := make([]string, 0)
	if !opt.Local.Memory {
		opt.Local.File = filepath.ToSlash(opt.Local.File)
		if _, err := os.Stat(opt.Local.File); err == nil || !os.IsNotExist(err) {
			keys = append(keys, pr("Unseal Key", false, true))
		}
	}

	signal.Ignore(syscall.SIGINT)

	var srv *localServer
	die := func(err error) {
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "@R{!! %s}\n", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "@Y{shutting down %s...}\n", engine.Title())
		if srv != nil {
			// On the startup path the wait goroutine has usually reaped the
			// process already; that is a clean shutdown, not a kill failure.
			if err := srv.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				_, _ = fmt.Fprintf(os.Stderr, "@R{NOTE: Unable to terminate the %s process.}\n", engine.Title())
				_, _ = fmt.Fprintf(os.Stderr, "@R{      You may have some environmental cleanup to do.}\n")
				_, _ = fmt.Fprintf(os.Stderr, "@R{      Apologies.}\n")
			}
			_ = os.Remove(srv.cfgFile)
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

	// Launch, retrying on the one failure that is safe to retry: the child's
	// own report that the port was taken. The bind probe above narrows the
	// race but cannot close it -- only the server's listen(2) is
	// authoritative. A losing attempt exits immediately, so a retry costs
	// milliseconds.
	const maxPortAttempts = 10
	for attempt := 1; ; attempt++ {
		srv, err = launchLocalServer(engine, localConfigParams{
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

		startupErr := waitLocalReady(engine, port, srv)
		if startupErr == nil {
			break
		}

		if isAddrInUse(srv.output.String()) {
			_ = os.Remove(srv.cfgFile)
			if !autoScan {
				// An explicit --port is a decision, not a preference:
				// diagnose it accurately and let the operator make the
				// next one.
				die(fmt.Errorf("port %d is already in use; choose another with --port, or omit --port to let safe pick one", port))
			}
			if attempt < maxPortAttempts {
				port, err = findCandidatePort(port + 1)
				if err != nil {
					die(err)
				}
				continue
			}
			die(fmt.Errorf("no free port found for %s after %d attempts (last tried %d)", engine.Title(), maxPortAttempts, port))
		}
		die(startupErr)
	}

	v, err := connectLocal(port, "")
	if err != nil {
		die(fmt.Errorf("Unable to build a client for the local %s server: %w", engine.Title(), err))
	}

	// Registered only now that the server is up on a port that is final: a
	// failed or retried launch must not leave a target pointing at nothing.
	if err := rc.Update(func(c *rc.Config) error {
		return c.SetTarget(name, rc.Vault{
			URL:        localVaultURL(port),
			SkipVerify: false,
		})
	}); err != nil {
		// Nothing irreversible has happened yet: kill the server rather
		// than leave one running that no config file points at.
		die(fmt.Errorf("Unable to register '%s' in ~/.saferc: %w", name, err))
	}
	// Outputs of the decision just made, for anything spawned from here on.
	// Never read back as inputs: the client above was built from the port
	// directly.
	_ = os.Setenv("VAULT_ADDR", localVaultURL(port))

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

	_ = os.Setenv("VAULT_TOKEN", token)
	// SetTokenFor, not SetToken: SetToken stores against whatever target is
	// current in the state just read, which under concurrency can be some
	// other process's vault. The token belongs to the server started here.
	if err := rc.Update(func(c *rc.Config) error {
		return c.SetTokenFor(name, token)
	}); err != nil {
		// The server is initialized and unsealed; aborting now would destroy
		// it (unrecoverably, for --memory). Hand the operator what they need
		// to reach it instead. The token going to stderr is deliberate: this
		// flow already prints the seal key, and the server is loopback-only.
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! Unable to save the root token in ~/.saferc: %s}\n", err)
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! The %s server at} @C{%s} @R{is still running.}\n", engine.Title(), localVaultURL(port))
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! Its root token is} @M{%s}\n", token)
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! To reach it:} @C{safe target %s %s && safe auth token}\n", name, localVaultURL(port))
	}
	v, err = connectLocal(port, token)
	if err != nil {
		return fmt.Errorf("Unable to build a client for the local %s server: %w", engine.Title(), err)
	}

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
		_, _ = fmt.Fprintf(os.Stderr, "Now targeting (temporary) @Y{%s} at @C{%s}\n", name, localVaultURL(port))
		if opt.Local.Memory {
			_, _ = fmt.Fprintf(os.Stderr, "@R{This %s server is MEMORY-BACKED!}\n", engine.Title())
			_, _ = fmt.Fprintf(os.Stderr, "If you want to @Y{retain your secrets} be sure to @C{safe export}.\n")
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Storing data (encrypted) in @G{%s}\n", opt.Local.File)
			_, _ = fmt.Fprintf(os.Stderr, "Your %s Seal Key is @M{%s}\n", engine.Title(), keys[0])
		}
		_, _ = fmt.Fprintf(os.Stderr, "Ctrl-C to shut down the %s server\n", engine.Title())
	}

	err = <-srv.echan
	_ = os.Remove(srv.cfgFile)
	_, _ = fmt.Fprintf(os.Stderr, "%s terminated normally, cleaning up...\n", engine.Title())
	if updateErr := rc.Update(func(c *rc.Config) error {
		// Evaluated against the state as it is now, not as it was at
		// startup: if another process has moved `current` to its own
		// target in the meantime, it is left alone.
		if c.Current == name {
			c.Current = ""
			if _, found, _ := c.Find(previous); found {
				c.Current = previous
			}
		}
		delete(c.Vaults, name)
		return nil
	}); updateErr != nil {
		// The server is already gone; the config entry is now stale. Say
		// so, but let the server's own exit status be what is returned.
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! Unable to remove '%s' from ~/.saferc: %s}\n", name, updateErr)
		_, _ = fmt.Fprintf(os.Stderr, "@R{!! Remove it by hand with} @C{safe targets delete %s}\n", name)
	}
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
	if err := rc.Update(func(c *rc.Config) error {
		return c.SetTokenFor(target, token)
	}); err != nil {
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
