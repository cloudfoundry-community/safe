package cli

import (
	"io"
	"net/http/httputil"
	"os"
	"strings"

	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func (c *CLI) cmdVersion(command string, args ...string) error {

	if Version != "" {
		_, _ = fmt.Fprintf(os.Stderr, "safe v%s\n", Version)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "safe (development build)\n")
	}
	if GitCommit != "" {
		_, _ = fmt.Fprintf(os.Stderr, "  commit %s\n", GitCommit)
	}
	if BuildTime != "" {
		_, _ = fmt.Fprintf(os.Stderr, "  built  %s\n", BuildTime)
	}
	rc.Cleanup()
	os.Exit(0)
	return nil
}

func (c *CLI) cmdHelp(command string, args ...string) error {
	r := c.r

	if len(args) == 0 {
		args = append(args, "commands")
	}
	//Help is output that was asked for. Written to standard error, it could
	// not be piped anywhere: safe commands | grep came back with nothing.
	r.Help(os.Stdout, strings.Join(args, " "))
	rc.Cleanup()
	os.Exit(0)
	return nil
}

// cmdCommands prints the listing of what safe can do. It is the topic help
// gives when it is asked for nothing in particular, and safe's own help points
// at it by name, so it is a command in its own right rather than something
// that only answers because an unrecognized command falls through to help.
func (c *CLI) cmdCommands(command string, args ...string) error {
	return c.cmdHelp("help", "commands")
}

// envvarsHelp is what safe envvars prints and what safe help envvars gives
// back. One copy serves both: the command is the documentation.
const envvarsHelp = `@G{[SCRIPTING]}
  @B{SAFE_TARGET}    The vault alias which requests are sent to.

@G{[PROXYING]}
  @B{HTTP_PROXY}     The proxy to use for HTTP requests.
  @B{HTTPS_PROXY}    The proxy to use for HTTPS requests.
  @B{SAFE_ALL_PROXY} The proxy to use for both HTTP and HTTPS requests.
                 Overrides HTTP_PROXY and HTTPS_PROXY.
  @B{NO_PROXY}       A comma-separated list of domains to not use proxies for.
  @B{SAFE_KNOWN_HOSTS_FILE}
                 The location of your known hosts file, used for
                 'ssh+socks5://' proxying. Uses '${HOME}/.ssh/known_hosts'
                 by default.
  @B{SAFE_SKIP_HOST_KEY_VALIDATION}
                 If set, 'ssh+socks5://' proxying will skip host key validation
                 validation of the remote ssh server.


  The proxy environment variables support proxies with the schemes 'http://',
  'https://', 'socks5://', or 'ssh+socks5://'. http, https, and socks5 do what they
  say - they'll proxy through the server with the hostname:port given using the
  protocol specified in the scheme.

  'ssh+socks5://' will open an SSH tunnel to the given server, then will start a
  local SOCKS5 proxy temporarily which sends its traffic through the SSH tunnel.
  Because this requires an SSH connection, some extra information is required.
  This type of proxy should be specified in the form

      ssh+socks5://<user>@<hostname>:<port>/<path-to-private-key>
  or  ssh+socks5://<user>@<hostname>:<port>?private-key=<path-to-private-key

  If no port is provided, port 22 is assumed.
  Encrypted private keys are not supported. Password authentication is also not
  supported.

  Your known_hosts file is used to verify the remote ssh server's host key. If no
  key for the given server is present, you will be prompted to add the key. If no
  TTY when no host key is present, safe will return with a failure.

`

func (c *CLI) cmdEnvvars(command string, args ...string) error {
	_, _ = fmt.Printf(envvarsHelp)
	return nil
}

func (c *CLI) cmdPrompt(command string, args ...string) error {

	// --no-clobber is ignored here, because there's no context of what you're
	// about to be writing after a prompt, so not sure if we should or shouldn't prompt
	// if you need to write something and prompt, but only if it isnt already present
	// in vault, see the `ask` subcommand
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", strings.Join(args, " "))
	return nil
}

func (c *CLI) cmdFmt(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) != 4 {
		return r.Usage("fmt")
	}

	fmtType := args[0]
	path := args[1]
	oldKey := args[2]
	newKey := args[3]

	//fmt names the keys it reads and writes separately, so a key on the path
	// is a mistake. Left unchecked it reads as one, and the complaint that
	// comes back is that the key does not exist rather than that it does not
	// belong there.
	if err := assertWritablePaths(path); err != nil {
		return err
	}

	v := connect(true)
	s, err := v.Read(path)
	if err != nil {
		return err
	}
	if opt.SkipIfExists && s.Has(newKey) {
		if !opt.Quiet {
			_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to reformat} @C{%s:%s} @R{to} @C{%s} @R{as it is already present in Vault}\n", path, oldKey, newKey)
		}
		return nil
	}
	if err = s.Format(oldKey, newKey, fmtType, opt.SkipIfExists); err != nil {
		if vault.IsNotFound(err) {
			return fmt.Errorf("%s:%s does not exist, cannot create %s encoded copy at %s:%s", path, oldKey, fmtType, path, newKey)
		}
		return fmt.Errorf("Error encoding %s:%s as %s: %s", path, oldKey, fmtType, err)
	}

	return v.Write(path, s)
}

func (c *CLI) cmdCurl(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	var (
		url, method string
		data        []byte
	)

	method = "GET"
	if len(args) < 1 {
		return r.Usage("curl")
	} else if len(args) == 1 {
		url = args[0]
	} else {
		method = strings.ToUpper(args[0])
		url = args[1]
		data = []byte(strings.Join(args[2:], " "))
	}

	v := connect(true)
	res, err := v.Curl(method, url, data)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	if opt.Curl.DataOnly {
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s\n", string(b))

	} else {
		r, _ := httputil.DumpResponse(res, true)
		_, _ = fmt.Fprintf(os.Stdout, "%s\n", r)
	}
	return nil
}
