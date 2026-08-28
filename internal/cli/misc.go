package cli

import (
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"slices"
	"strings"

	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func (c *CLI) cmdVersion(command string, args ...string) error {

	//Which safe is running is an answer to a question that was asked, so it
	// goes where output goes. On standard error, safe -v | cut said nothing.
	if Version != "" {
		_, _ = fmt.Fprintf(os.Stdout, "safe v%s\n", Version)
	} else {
		_, _ = fmt.Fprintf(os.Stdout, "safe (development build)\n")
	}
	if GitCommit != "" {
		_, _ = fmt.Fprintf(os.Stdout, "  commit %s\n", GitCommit)
	}
	if BuildTime != "" {
		_, _ = fmt.Fprintf(os.Stdout, "  built  %s\n", BuildTime)
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
	topic := strings.Join(args, " ")
	//Help is output that was asked for. Written to standard error, it could
	// not be piped anywhere: safe commands | grep came back with nothing.
	// A topic safe does not have is the other way round -- that is a mistake,
	// and it is reported where mistakes are.
	if err := r.Help(os.Stdout, topic); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "@R{Unrecognized command or help topic '%s'}\n", topic)
		_, _ = fmt.Fprintf(os.Stderr, "Try 'safe help' to get started with safe,\n")
		_, _ = fmt.Fprintf(os.Stderr, " or 'safe commands' for a list of valid commands\n")
		rc.Cleanup()
		os.Exit(1)
	}
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
  @B{SAFE_ENGINE}    Which server binary 'safe local' and 'safe vault' run:
                 'vault' or 'bao' (OpenBao). Defaults to the first of the
                 two found on PATH, vault first. 'safe local --engine'
                 overrides this.

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

  A username or private key path containing special characters must be
  percent-encoded in the URL, e.g. '%40' for '@'.

  Your known_hosts file is used to verify the remote ssh server's host key. If no
  key for the given server is present, you will be prompted to add the key. If no
  TTY when no host key is present, safe will return with a failure.

`

func (c *CLI) cmdEnvvars(command string, args ...string) error {
	//envvarsHelp is handed to go-ansi's Printf as a format string, the same
	// way Runner.Help hands help.Description to ansi.Fprintf, and for the
	// same reason: it is how the @G{...} markup in it is read. A bare '%' in
	// the text would then be taken for the start of a verb, so it goes
	// through the same escapePercent Runner.Help applies before either one
	// reaches a formatter.
	_, _ = fmt.Printf(escapePercent(envvarsHelp))
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

	//Both bounds are checked before the read: a bad work factor should not
	// cost a round trip to the Vault. Main pre-seeds Fmt.Cost with
	// DefaultBcryptCost before go-cli parses the command line, so this
	// field already carries 12 unless --cost overwrote it -- including an
	// explicit --cost 0, which is a real request now, not the unset
	// default, and is judged the same as any other too-low value below.
	// The cost must never be weakened below the bcrypt library's own
	// default, and never raised past what the library itself will
	// accept -- left unchecked here, a too-high cost still pays for the
	// read before bcrypt gets the chance to refuse it.
	cost := opt.Fmt.Cost
	if cost < vault.MinBcryptCost {
		return fmt.Errorf("bcrypt cost %d is below the minimum of %d", cost, vault.MinBcryptCost)
	}
	if cost > vault.MaxBcryptCost {
		return fmt.Errorf("bcrypt cost %d is above the maximum of %d", cost, vault.MaxBcryptCost)
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
	if err = s.FormatWithCost(oldKey, newKey, fmtType, cost, opt.SkipIfExists); err != nil {
		if vault.IsNotFound(err) {
			return fmt.Errorf("%s:%s does not exist, cannot create %s encoded copy at %s:%s", path, oldKey, fmtType, path, newKey)
		}
		return fmt.Errorf("Error encoding %s:%s as %s: %s", path, oldKey, fmtType, err)
	}

	return v.Write(path, s)
}

// curlMethods are the methods safe curl will send. LIST is Vault's own; the
// rest are the ones a Vault endpoint answers to.
var curlMethods = []string{"GET", "LIST", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

// isCurlMethod reports whether s names an HTTP method, whatever its case.
func isCurlMethod(s string) bool {
	return slices.Contains(curlMethods, strings.ToUpper(s))
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

	//Whatever was given first was taken for the method and whatever was given
	// alone was taken for the URI, neither of them read. So safe curl GET
	// asked the Vault for /v1/GET, and safe curl /sys/health '{}' sent a
	// request whose method was /SYS/HEALTH.
	method = "GET"
	switch {
	case len(args) < 1:
		return r.Usage("curl")
	case len(args) == 1:
		if isCurlMethod(args[0]) {
			return fmt.Errorf("no REL-URI given to %s", strings.ToUpper(args[0]))
		}
		url = args[0]
	default:
		method = strings.ToUpper(args[0])
		if !isCurlMethod(method) {
			return fmt.Errorf("%s is not an HTTP method: give one of %s",
				args[0], strings.Join(curlMethods, ", "))
		}
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
		dump, err := httputil.DumpResponse(res, true)
		if err != nil {
			return fmt.Errorf("could not read the response to %s %s: %w", method, url, err)
		}
		_, _ = fmt.Fprintf(os.Stdout, "%s\n", dump)
	}

	//A request the Vault refused left safe exiting 0, so a script asking for
	// a path it may not read, or one that is not there, could not tell that
	// apart from a request that worked. Under --data-only, where the status
	// line is not printed either, nothing at all said so. What Vault answered
	// is printed either way: reading it is what the command is for.
	if res.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("%s %s: %s", method, url, res.Status)
	}
	return nil
}
