package vault

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	socks5 "github.com/armon/go-socks5"
	"github.com/cloudfoundry-community/safe/pkg/prompt"
	isatty "github.com/mattn/go-isatty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/net/http/httpproxy"
)

type ProxyRouter struct {
	ProxyConf httpproxy.Config
}

func (n ProxyRouter) Proxy(req *http.Request) (*url.URL, error) {
	return n.ProxyConf.ProxyFunc()(req.URL)
}

func NewProxyRouter() (*ProxyRouter, error) {
	httpProxy := getEnvironmentVariable("HTTP_PROXY", "http_proxy")
	httpsProxy := getEnvironmentVariable("HTTPS_PROXY", "https_proxy")

	allProxy := getEnvironmentVariable("SAFE_ALL_PROXY", "safe_all_proxy")
	if allProxy != "" {
		httpProxy = allProxy
		httpsProxy = allProxy
	}

	noProxy := getEnvironmentVariable("NO_PROXY", "no_proxy")

	knownHostsFile := getEnvironmentVariable("SAFE_KNOWN_HOSTS_FILE", "safe_known_hosts_file")
	skipHostKeyString := getEnvironmentVariable("SAFE_SKIP_HOST_KEY_VALIDATION", "safe_skip_host_key_validation")
	skipHostKeyValidation := false
	for _, trueString := range []string{"true", "yes", "1", "on"} {
		if strings.EqualFold(skipHostKeyString, trueString) {
			skipHostKeyValidation = true
			break
		}
	}
	if skipHostKeyValidation {
		fmt.Fprintf(os.Stderr, "WARNING: SSH host key validation disabled (SAFE_SKIP_HOST_KEY_VALIDATION=%s)\n", skipHostKeyString)
	}

	oldHTTPProxy := httpProxy
	var err error
	if strings.HasPrefix(httpProxy, "ssh+socks5://") {
		httpProxy, err = openSOCKS5Helper(httpProxy, knownHostsFile, skipHostKeyValidation)
		if err != nil {
			return nil, err
		}
	}

	if strings.HasPrefix(httpsProxy, "ssh+socks5://") {
		if httpsProxy == oldHTTPProxy {
			httpsProxy = httpProxy
		} else {
			httpsProxy, err = openSOCKS5Helper(httpsProxy, knownHostsFile, skipHostKeyValidation)
			if err != nil {
				return nil, err
			}
		}
	}

	return &ProxyRouter{
		ProxyConf: httpproxy.Config{
			HTTPProxy:  httpProxy,
			HTTPSProxy: httpsProxy,
			NoProxy:    noProxy,
		},
	}, nil
}

func openSOCKS5Helper(toOpen, knownHostsFile string, skipHostKeyValidation bool) (string, error) {
	u, err := url.Parse(toOpen)
	if err != nil {
		return "", fmt.Errorf("could not parse proxy URL (%s): %w", toOpen, err)
	}

	if u.User == nil {
		return "", fmt.Errorf("no user provided for SSH proxy")
	}

	if u.Port() == "" {
		u.Host = u.Host + ":22"
	}

	privateKeyPath := u.Query()["private-key"]

	if u.Path != "" && u.Path != "/" {
		privateKeyPath = append(privateKeyPath, u.Path)
	}

	if len(privateKeyPath) == 0 {
		return "", fmt.Errorf("no private key path provided")
	}

	if len(privateKeyPath) > 1 {
		return "", fmt.Errorf("more than one private key provided")
	}

	privateKeyContents, err := os.ReadFile(privateKeyPath[0])
	if err != nil {
		return "", fmt.Errorf("could not read private key file (%s): %w", privateKeyPath[0], err)
	}

	sshClient, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:                  u.Host,
		User:                  u.User.Username(),
		PrivateKey:            privateKeyContents,
		KnownHostsFile:        knownHostsFile,
		SkipHostKeyValidation: skipHostKeyValidation,
	})
	if err != nil {
		return "", fmt.Errorf("could not start SSH tunnel: %w", err)
	}

	socks5Addr, _, err := StartSOCKS5Server(sshClient.Dial)
	if err != nil {
		return "", fmt.Errorf("could not start SOCKS5 Server: %w", err)
	}

	// The closer is intentionally not stored here: the SOCKS5 listener must
	// remain open for the entire duration of the CLI process. The listener is
	// bound to a local ephemeral port and will be released when the process exits.
	return fmt.Sprintf("socks5://%s", socks5Addr), nil
}

func getEnvironmentVariable(variables ...string) string {
	for _, v := range variables {
		ret := os.Getenv(v)
		if ret != "" {
			return ret
		}
	}

	return ""
}

// SOCKS5SSHConfig contains configuration variables for setting up a SOCKS5
// proxy to be tunneled through an SSH connection.
type SOCKS5SSHConfig struct {
	Host                  string
	User                  string
	PrivateKey            []byte
	KnownHostsFile        string
	SkipHostKeyValidation bool
}

// StartSSHTunnel makes an SSH connection according to the given config. It
// returns an SSH client if it was successful and an error otherwise.
func StartSSHTunnel(conf SOCKS5SSHConfig) (*ssh.Client, error) {
	hostKeyCallback := ssh.InsecureIgnoreHostKey() // #nosec G106 - Default, will be overridden if SkipHostKeyValidation is false
	var err error

	if !conf.SkipHostKeyValidation {
		if conf.KnownHostsFile == "" {
			if os.Getenv("HOME") == "" {
				return nil, fmt.Errorf("no home directory set and no known hosts file explicitly given; cannot validate host key")
			}
			conf.KnownHostsFile = fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME"))
		}

		hostKeyCallback, err = knownHostsPromptCallback(conf.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("error opening known_hosts file at `%s': %w", conf.KnownHostsFile, err)
		}
	}

	privateKeySigner, err := ssh.ParsePrivateKey(conf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create signer for private key: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            conf.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(privateKeySigner)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	return ssh.Dial("tcp", conf.Host, sshConfig)
}

// StartSOCKS5Server makes an SSH connection according to the given config, starts
// a local SOCKS5 server on a random port, and then returns the proxy
// address, a closer function to shut down the listener, and an error if
// startup was unsuccessful. Callers must call the closer when the tunnel is no
// longer needed to release the bound port and goroutine.
func StartSOCKS5Server(dialFn func(string, string) (net.Conn, error)) (addr string, closer func() error, err error) {
	socks5Server, err := socks5.New(&socks5.Config{
		Dial: noopDialContext(dialFn),
	})
	if err != nil {
		return "", nil, fmt.Errorf("error starting local SOCKS5 server: %w", err)
	}

	socks5Listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("error starting local SOCKS5 server: %w", err)
	}

	go func() {
		if serr := socks5Server.Serve(socks5Listener); serr != nil {
			fmt.Fprintf(os.Stderr, "SOCKS5 proxy error: %s\n", serr)
		}
	}()

	return socks5Listener.Addr().String(), socks5Listener.Close, nil
}

func knownHostsPromptCallback(knownHostsFile string) (ssh.HostKeyCallback, error) {
	tmpCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("could not handle known hosts file: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		callbackErr := tmpCallback(hostname, remote, key)
		//If the base check is fine, then we just let the ssh request carry on
		if callbackErr == nil {
			return nil
		}

		//If we're here, we got some sort of error
		//Let's check if it was because the key wasn't trusted
		errAsKeyError, isKeyError := callbackErr.(*knownhosts.KeyError)
		if !isKeyError {
			return callbackErr
		}

		//If the error has hostnames listed under Want, it means that there was
		// a conflicting host key
		if len(errAsKeyError.Want) > 0 {
			//Point at the entry that conflicts with the key the host offered,
			// which is the one of the host's own type. Testing the candidate
			// already chosen rather than the one in hand named whichever entry
			// came last when the first happened to match and the first when it
			// did not, so the line reported was the wrong one either way, and
			// the reader who acted on it deleted a host key that was fine and
			// left the conflicting entry where it was.
			wantedKey := errAsKeyError.Want[0]
			for _, k := range errAsKeyError.Want {
				if k.Key.Type() == key.Type() {
					wantedKey = k
					break
				}
			}

			hostKeyConflictError := `
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the %[1]s key sent by the remote host is
%[2]s.
Please contact your system administrator.
Add correct host key in %[3]s to get rid of this message.
Offending %[6]s key in %[3]s:%[4]d
%[1]s host key for %[5]s has changed and safe uses strict checking.
Host key verification failed`
			//The offending line is named with the type of the key written on it,
			// which is the type of the key the host offered whenever there is an
			// entry of that type to conflict with.
			return fmt.Errorf(hostKeyConflictError,
				key.Type(), ssh.FingerprintSHA256(key), knownHostsFile, wantedKey.Line,
				hostname, wantedKey.Key.Type())
		}

		//If not, then the key doesn't exist in the host key file
		//Let's see if we can ask the user if they want to add it
		if !isatty.IsTerminal(os.Stderr.Fd()) || !promptAddNewKnownHost(hostname, remote, key) {
			//If its not a terminal or the user declined, we're rejecting it
			return fmt.Errorf("host key verification failed: %w", callbackErr)
		}

		if writeErr := writeKnownHosts(knownHostsFile, hostname, key); writeErr != nil {
			return writeErr
		}

		return nil
	}, nil
}

func promptAddNewKnownHost(hostname string, remote net.Addr, key ssh.PublicKey) bool {
	//Otherwise, let's ask the user
	fmt.Fprintf(os.Stderr, `The authenticity of host '%[1]s (%[2]s)' can't be established.
%[3]s key fingerprint is %[4]s
Are you sure you want to continue connecting (yes/no)? `, hostname, remote.String(), key.Type(), ssh.FingerprintSHA256(key))

	for {
		//A read that fails is the end of the matter. Answering nothing used to
		// leave the answer as it was and ask again, so stdin at its end -- a
		// pipe that is done, a job with no input attached -- spun here without
		// stopping, writing the prompt to stderr as fast as it could. No answer
		// is no.
		response, err := prompt.ReadLine()
		if err != nil {
			fmt.Fprintln(os.Stderr, "")
			return false
		}

		switch strings.TrimSpace(response) {
		case "yes":
			return true
		case "no":
			return false
		}

		fmt.Fprintf(os.Stderr, "Please type 'yes' or 'no': ")
	}
}

func writeKnownHosts(knownHostsFile, hostname string, key ssh.PublicKey) error {
	normalizedHostname := knownhosts.Normalize(hostname)
	f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_RDWR, 0600) // #nosec G304,G703 -- known_hosts path from user-controlled SAFE_KNOWN_HOSTS_FILE env var
	if err != nil {
		return fmt.Errorf("could not open `%s' for reading: %w", knownHostsFile, err)
	}

	fileInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("could not retrieve info for file `%s': %w", knownHostsFile, err)
	}

	if fileInfo.Size() != 0 {
		//Let's make sure we're writing to a new line...
		_, err := f.Seek(-1, 2)
		if err != nil {
			return fmt.Errorf("Error when seeking to end of `%s': %w", knownHostsFile, err)
		}

		lastByte := make([]byte, 1)
		_, err = f.Read(lastByte)
		if err != nil {
			return fmt.Errorf("Error when reading from `%s': %w", knownHostsFile, err)
		}

		if !bytes.Equal(lastByte, []byte("\n")) {
			//Need to append a newline
			_, err = f.Write([]byte("\n"))
			if err != nil {
				return fmt.Errorf("Error when writing to `%s': %w", knownHostsFile, err)
			}
		}
	}

	newKnownHostsLine := knownhosts.Line([]string{normalizedHostname}, key)
	_, err = f.WriteString(newKnownHostsLine + "\n")
	if err != nil {
		return fmt.Errorf("Error when writing to `%s': %w", knownHostsFile, err)
	}

	fmt.Fprintf(os.Stderr, "Warning: Permanently added '%s' (%s) to the list of known hosts.\n", hostname, key.Type())
	return nil
}

// noopDialContext adapts the ssh.Client.Dial signature (no context) to the
// context-aware DialContext signature required by the SOCKS5 server. The
// context is intentionally dropped because ssh.Client.Dial does not accept
// one; cancellation and deadline enforcement rely on the lower-level TCP
// timeout configured in the ssh.ClientConfig (30 s) and the SSH transport.
func noopDialContext(base func(string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		return base(network, addr)
	}
}
