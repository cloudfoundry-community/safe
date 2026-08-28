package vault

import (
	"crypto/md5" // #nosec G501 - MD5 used for SSH fingerprint display only, not security
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// sshkeyGen is sshkey behind a package-level variable, mirroring
// dhparamGen: tests substitute a counting stub to prove a check-and-set
// conflict retry re-installs the first attempt's keypair rather than
// paying rsa.GenerateKey again -- see SetSSHKeyGenForTest in
// export_test.go.
var sshkeyGen = sshkey

func sshkey(bits int) (string, string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", "", err
	}

	private := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	pub := key.Public()
	pubkey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", "", err
	}
	public := ssh.MarshalAuthorizedKey(pubkey)

	var fp []string
	f := []byte(fmt.Sprintf("%x", md5.Sum(pubkey.Marshal()))) // #nosec G401 - MD5 used for SSH fingerprint display only
	for i := 0; i < len(f); i += 2 {
		fp = append(fp, string(f[i:i+2]))
	}
	fingerprint := strings.Join(fp, ":")

	return string(private), string(public), string(fingerprint), nil
}
