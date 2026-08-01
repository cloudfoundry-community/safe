// The SSH proxy end to end: a real SSH handshake against a real server, the
// host key checked against a real known_hosts file, and traffic carried
// through the SOCKS5 proxy that the tunnel is there to provide.
package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

// makeSSHKeyPair returns a signer and the PEM the same key is written as, for
// use as either a host key or a login key.
func makeSSHKeyPair(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer, pem.EncodeToMemory(block)
}

// startEchoServer listens on a loopback port and sends back whatever it is
// sent. It stands in for the Vault that the tunnel exists to reach.
func startEchoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, aerr := listener.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	return listener.Addr().String()
}

// startFakeSSHServer listens on a loopback port, accepts any login, and
// forwards the direct-tcpip channels that a SOCKS5 proxy opens through it. It
// returns the address it is listening on and the public half of its host key.
func startFakeSSHServer(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	hostSigner, _ := makeSSHKeyPair(t)

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, aerr := listener.Accept()
			if aerr != nil {
				return
			}
			go serveFakeSSH(conn, config)
		}
	}()

	return listener.Addr().String(), hostSigner.PublicKey()
}

// serveFakeSSH completes one SSH handshake and forwards its channels.
func serveFakeSSH(conn net.Conn, config *ssh.ServerConfig) {
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = serverConn.Close() }()

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "direct-tcpip" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only direct-tcpip is forwarded")
			continue
		}
		go forwardDirectTCPIP(newChannel)
	}
}

// forwardDirectTCPIP dials where the channel asks and joins the two together,
// which is what an SSH server does for a tunnel.
func forwardDirectTCPIP(newChannel ssh.NewChannel) {
	var payload struct {
		DestAddr string
		DestPort uint32
		SrcAddr  string
		SrcPort  uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "unreadable direct-tcpip request")
		return
	}

	target, err := net.Dial("tcp", net.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort))))
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}

	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		_ = target.Close()
		return
	}
	go ssh.DiscardRequests(channelRequests)

	go func() {
		defer func() { _ = target.Close() }()
		_, _ = io.Copy(target, channel)
	}()
	go func() {
		defer func() { _ = channel.Close() }()
		_, _ = io.Copy(channel, target)
	}()
}

// TestTunnelCarriesTrafficForAKnownHost is the whole path: the host key is
// already trusted, so the tunnel opens, a SOCKS5 proxy comes up in front of
// it, and what is sent through the proxy reaches the far side.
func TestTunnelCarriesTrafficForAKnownHost(t *testing.T) {
	t.Parallel()
	sshAddr, hostKey := startFakeSSHServer(t)
	echoAddr := startEchoServer(t)

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	writeKnownHostsFixture(t, knownHosts, sshAddr, hostKey)

	_, loginKey := makeSSHKeyPair(t)
	client, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:           sshAddr,
		User:           "someone",
		PrivateKey:     loginKey,
		KnownHostsFile: knownHosts,
	})
	if err != nil {
		t.Fatalf("StartSSHTunnel: %v", err)
	}
	defer func() { _ = client.Close() }()

	socksAddr, closer, err := StartSOCKS5Server(client.Dial)
	if err != nil {
		t.Fatalf("StartSOCKS5Server: %v", err)
	}
	defer func() { _ = closer() }()

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("proxy.SOCKS5: %v", err)
	}
	conn, err := dialer.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	defer func() { _ = conn.Close() }()

	const sent = "through the tunnel\n"
	if _, err := io.WriteString(conn, sent); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	received := make([]byte, len(sent))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("read back through the tunnel: %v", err)
	}
	if string(received) != sent {
		t.Errorf("got %q back through the tunnel, sent %q", received, sent)
	}
}

// TestTunnelRefusesAnUnknownHostWithNoOneToAsk covers a script or a CI job:
// the host is not in known_hosts and there is nobody to accept it, so the
// tunnel must be refused rather than opened or waited on.
func TestTunnelRefusesAnUnknownHostWithNoOneToAsk(t *testing.T) {
	t.Parallel()
	sshAddr, _ := startFakeSSHServer(t)

	//An explicitly named known_hosts file is never auto-created; it must
	//already exist, so seed an empty one to isolate this test's assertion
	//to the unknown-host refusal it is checking.
	knownHosts := filepath.Join(t.TempDir(), ".ssh", "known_hosts")
	if err := ensureKnownHostsFile(knownHosts); err != nil {
		t.Fatalf("seed known_hosts file: %v", err)
	}
	_, loginKey := makeSSHKeyPair(t)

	_, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:           sshAddr,
		User:           "someone",
		PrivateKey:     loginKey,
		KnownHostsFile: knownHosts,
	})
	if err == nil {
		t.Fatal("tunnel opened to a host whose key was never accepted")
	}
	if !strings.Contains(err.Error(), "host key verification failed") {
		t.Errorf("unknown host refused for some other reason: %v", err)
	}
}

// TestTunnelRefusesAHostWhoseKeyChanged covers the key on file disagreeing
// with the key offered. This is the case the warning is written for, so the
// warning has to be what comes back.
func TestTunnelRefusesAHostWhoseKeyChanged(t *testing.T) {
	t.Parallel()
	sshAddr, _ := startFakeSSHServer(t)

	//A key for this host that the host does not have.
	strangerSigner, _ := makeSSHKeyPair(t)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	writeKnownHostsFixture(t, knownHosts, sshAddr, strangerSigner.PublicKey())

	_, loginKey := makeSSHKeyPair(t)
	_, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:           sshAddr,
		User:           "someone",
		PrivateKey:     loginKey,
		KnownHostsFile: knownHosts,
	})
	if err == nil {
		t.Fatal("tunnel opened to a host whose key had changed")
	}
	if !strings.Contains(err.Error(), "REMOTE HOST IDENTIFICATION HAS CHANGED") {
		t.Fatalf("changed host key did not raise the warning: %v", err)
	}
	if _, line := offendingKey(t, err); line != 1 {
		t.Errorf("warning names known_hosts line %d; the only entry is on line 1", line)
	}
}
