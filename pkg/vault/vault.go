package vault

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cloudfoundry-community/vaultkv"
	"github.com/jhunt/go-ansi"
)

type Vault struct {
	client *vaultkv.KV
	debug  bool
}

type VaultConfig struct {
	URL        string
	Token      string
	Namespace  string
	CACerts    *x509.CertPool
	SkipVerify bool
}

// NewVault creates a new Vault object.  If an empty token is specified,
// the current user's token is read from ~/.vault-token.
func NewVault(conf VaultConfig) (*Vault, error) {
	var err error
	if conf.CACerts == nil {
		// x509.SystemCertPool is not implemented for windows currently.
		// If nil is supplied for RootCAs, the system will verify the certs as per
		// https://golang.org/src/crypto/x509/verify.go (Line 741)
		conf.CACerts, err = x509.SystemCertPool()
		if err != nil && runtime.GOOS != "windows" {
			return nil, fmt.Errorf("unable to retrieve system root certificate authorities: %w", err)
		}
	}
	vaultURL, err := url.Parse(strings.TrimSuffix(conf.URL, "/"))
	if err != nil {
		return nil, fmt.Errorf("could not parse Vault URL: %w", err)
	}

	//The default port for Vault is typically 8200 (which is the VaultKV default),
	// but safe has historically ignored that and used the default http or https
	// port, depending on which was specified as the scheme
	if vaultURL.Port() == "" {
		port := ":80"
		if strings.ToLower(vaultURL.Scheme) == "https" {
			port = ":443"
		}
		vaultURL.Host = vaultURL.Host + port
	}

	proxyRouter, err := NewProxyRouter()
	if err != nil {
		return nil, fmt.Errorf("error setting up proxy: %w", err)
	}

	if conf.SkipVerify {
		_, _ = ansi.Fprintf(os.Stderr, "@Y{WARNING: TLS certificate verification disabled — connections to Vault are not authenticated}\n")
	}

	return &Vault{
		client: (&vaultkv.Client{
			VaultURL:  vaultURL,
			AuthToken: conf.Token,
			Namespace: conf.Namespace,
			Client: &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					Proxy: proxyRouter.Proxy,
					TLSClientConfig: &tls.Config{
						RootCAs:            conf.CACerts,
						InsecureSkipVerify: conf.SkipVerify, // #nosec G402 - User-controlled via config for development/testing
					},
					MaxIdleConnsPerHost: 100,
				},
			},
			Trace: func() (ret io.Writer) {
				if shouldDebug() {
					ret = os.Stderr
				}
				return ret
			}(),
		}).NewKV(),
		debug: shouldDebug(),
	}, nil
}

func (v *Vault) Client() *vaultkv.KV {
	return v.client
}

func (v *Vault) MountVersion(path string) (uint, error) {
	path = Canonicalize(path)
	return v.client.MountVersion(path)
}

func (v *Vault) Versions(path string) ([]vaultkv.KVVersion, error) {
	path = Canonicalize(path)
	ret, err := v.client.Versions(path)
	if vaultkv.IsNotFound(err) {
		return nil, NewSecretNotFoundError(path)
	}

	return ret, err
}

func shouldDebug() bool {
	d := strings.ToLower(os.Getenv("DEBUG"))
	return d != "" && d != "false" && d != "0" && d != "no" && d != "off"
}

func (v *Vault) Curl(method string, path string, body []byte) (*http.Response, error) {
	path = Canonicalize(path)
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("could not parse input path: %w", err)
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("could not parse query: %w", err)
	}

	return v.client.Client.Curl(method, u.Path, query, bytes.NewBuffer(body))
}

// Read checks the Vault for a Secret at the specified path, and returns it.
// The returned *Secret is never nil. A missing secret and a missing key are
// both reported through err, as SecretNotFound and KeyNotFound respectively,
// alongside an empty Secret; every Secret method dereferences its receiver,
// so a caller that tolerates a not-found error can still use the value.
func (v *Vault) Read(path string) (secret *Secret, err error) {
	path, key, version := ParsePath(path)

	secret = NewSecret()

	raw := map[string]any{}
	_, err = v.client.Get(path, &raw, &vaultkv.KVGetOpts{Version: uint(version)})
	if err != nil {
		if vaultkv.IsNotFound(err) {
			err = v.notFoundReading(path, version)
		}
		return
	}

	if key != "" {
		val, found := raw[key]
		if !found {
			return secret, NewKeyNotFoundError(path, key)
		}
		raw = map[string]any{key: val}
	}

	for k, v := range raw {
		if (key != "" && k == key) || key == "" {
			if s, ok := v.(string); ok {
				secret.data[k] = s
			} else {
				var b []byte
				b, err = json.Marshal(v)
				if err != nil {
					return
				}
				secret.data[k] = string(b)
			}
		}
	}

	return
}

// notFoundReading turns a 404 from a read into the most specific not-found
// error it can. A versioned read fails either because the secret is not there
// or because that one version is not, and the two send a reader looking in
// different places: one to create the secret, the other to `safe versions`.
//
// Telling them apart costs a metadata request, so it is only paid when a
// version was actually named. A plain read of a missing secret — what every
// `safe gen` does on a path it is about to create — still costs the single
// request it always did.
func (v *Vault) notFoundReading(path string, version uint64) error {
	if version == 0 {
		return NewSecretNotFoundError(path)
	}

	versions, err := v.client.Versions(path)
	if err != nil || len(versions) == 0 {
		//No history to consult, so the secret itself is the better answer.
		return NewSecretNotFoundError(path)
	}

	for _, v := range versions {
		if uint64(v.Version) != version {
			continue
		}
		switch {
		case v.Destroyed:
			return NewVersionNotFoundError(path, version, "destroyed")
		case v.Deleted:
			return NewVersionNotFoundError(path, version, "deleted")
		}
		//The version is there and alive, so the 404 was about something
		// other than the version; do not claim otherwise.
		return NewSecretNotFoundError(path)
	}

	return NewVersionNotFoundError(path, version, "")
}

// ExplainNotFound narrows a not-found error from Read the way notFoundReading
// narrows a versioned one: when the secret does exist and it is only its newest
// version that cannot be read, it says which version and what became of it.
// Anything else is returned untouched, including a missing key and a version
// the caller named, which is already as specific as it gets.
//
// Read does not do this for itself. A read with no version named is what gen,
// uuid, ssh, rsa and dhparam all do to a path they are about to create, and
// they expect the miss; the metadata request this costs would land on every one
// of those. Here it is paid only by a command that has already failed and is
// about to put the message in front of somebody.
//
// Vault does say which version it was in the body of the 404, but vaultkv
// discards the body of any non-2xx response, so the history has to be asked for
// separately.
func (v *Vault) ExplainNotFound(path string, err error) error {
	if !IsSecretNotFound(err) {
		return err
	}

	secret, _, version := ParsePath(path)
	if version != 0 {
		return err
	}

	versions, verr := v.client.Versions(secret)
	if verr != nil || len(versions) == 0 {
		//Nothing to consult, so the secret really is the best answer.
		return err
	}

	//A read with no version named asks for the newest one, so that is the
	// only version whose state can explain this particular miss.
	latest := versions[len(versions)-1]
	switch {
	case latest.Destroyed:
		return NewVersionNotFoundError(secret, uint64(latest.Version), "destroyed")
	case latest.Deleted:
		return NewVersionNotFoundError(secret, uint64(latest.Version), "deleted")
	}
	return err
}

// List returns the set of (relative) paths that are directly underneath
// the given path.  Intermediate path nodes are suffixed with a single "/",
// whereas leaf nodes (the secrets themselves) are not.
func (v *Vault) List(path string) (paths []string, err error) {
	path = Canonicalize(path)

	paths, err = v.client.List(path)
	if vaultkv.IsNotFound(err) {
		err = NewSecretNotFoundError(path)
	}

	return paths, err
}

// Write takes a Secret and writes it to the Vault at the specified path.
func (v *Vault) Write(path string, s *Secret) error {
	path, key, version := ParsePath(path)
	if key != "" {
		return fmt.Errorf("cannot write to paths in /path:key notation")
	}

	if version != 0 {
		return fmt.Errorf("cannot write to paths in /path^version notation")
	}

	if s.Empty() {
		return v.deleteIfPresent(path, DeleteOpts{})
	}

	_, err := v.client.Set(path, s.data, nil)
	if vaultkv.IsNotFound(err) {
		err = NewSecretNotFoundError(path)
	}

	return err
}

// errIfFolder returns an error with your provided message if the given path is a folder.
// Can also throw an error if contacting the backend failed, in which case that error
// is returned.
func (v *Vault) errIfFolder(path, message string, args ...any) error {
	path = Canonicalize(path)
	if _, err := v.List(path); err == nil {
		//We don't want the folder error to be ignored because of the -f flag to rm,
		// so we explicitly don't make this a secretNotFound error
		return fmt.Errorf(message, args...)
	} else if !IsNotFound(err) {
		return err
	}
	return nil
}

const (
	verifyStateAlive uint = iota
	verifyStateAliveOrDeleted
)

type verifyOpts struct {
	AnyVersion bool
	State      uint
}

func (v *Vault) verifySecretState(path string, opts verifyOpts) error {
	secret, _, version := ParsePath(path)
	mountV, err := v.MountVersion(secret)
	if err != nil {
		return err
	}

	switch mountV {
	case 1:
		return v.verifySecretExists(path)
	case 2:
		versions, err := v.Versions(secret)
		if err != nil {
			if IsNotFound(err) {
				err = v.errIfFolder(path, "`%s' points to a folder, not a secret", path)
				if err != nil {
					return err
				}

				return NewSecretNotFoundError(secret)
			}

			return err
		}

		if len(versions) == 0 {
			return NewSecretNotFoundError(secret)
		}

		if !opts.AnyVersion {
			var v vaultkv.KVVersion
			if version == 0 {
				v = versions[len(versions)-1]
			} else {
				//Older than anything Vault still lists, which only happens
				// once a version has been destroyed and pruned.
				if uint64(versions[0].Version) > version {
					return NewVersionNotFoundError(secret, version, "destroyed")
				}

				if version > uint64(versions[len(versions)-1].Version) {
					return NewVersionNotFoundError(secret, version, "")
				}

				idx := version - uint64(versions[0].Version)
				v = versions[idx]
			}

			//Named by number even when the caller asked for the latest, since
			// which version that was is the part they do not know.
			if v.Destroyed {
				return NewVersionNotFoundError(secret, uint64(v.Version), "destroyed")
			}
			if opts.State == verifyStateAlive && v.Deleted {
				return NewVersionNotFoundError(secret, uint64(v.Version), "deleted")
			}
		} else {
			for i := range versions {
				if (!versions[i].Deleted && !versions[i].Destroyed) || (opts.State == verifyStateAliveOrDeleted && !versions[i].Destroyed) {
					return nil
				}
			}

			//If we got this far, we couldn't find a version that satisfied our constraints
			if opts.State == verifyStateAlive {
				return secretNotFound{fmt.Sprintf("no living version of secret `%s` exists", secret)}
			}
			return secretNotFound{fmt.Sprintf("no living or deleted version of secret `%s` exists", secret)}
		}

	default:
		return fmt.Errorf("unsupported mount version: %d", mountV)
	}
	return nil
}

func (v *Vault) verifySecretExists(path string) error {
	path = Canonicalize(path)

	_, err := v.Read(path)
	if err != nil && IsNotFound(err) { //if this was not a leaf node (secret)...
		if folderErr := v.errIfFolder(path, "`%s` points to a folder, not a secret", path); folderErr != nil {
			return folderErr
		}
	}
	return err
}

// DeleteTree recursively deletes the leaf nodes beneath the given root until
// the root has no children, and then deletes that.
func (v *Vault) DeleteTree(root string, opts DeleteOpts) error {
	//A root naming a key or a version cannot be honoured by a recursion: the
	// walk drops both and deletes everything beneath the secret. Refuse rather
	// than delete more than was asked for.
	rawRoot, key, version := ParsePath(root)
	if key != "" || version != 0 {
		return fmt.Errorf("cannot recursively delete a specific key or version (%s)", root)
	}
	//ParsePath unescaped the root. The walk and the mount lookup want that
	// literal Vault path; deleteEntireSecret parses its argument again, so it
	// gets the escaped form back.
	root = EncodePath(rawRoot, "", 0)

	secrets, err := v.ConstructSecrets(rawRoot, TreeOpts{FetchKeys: false, SkipVersionInfo: true, AllowDeletedSecrets: true})
	if err != nil {
		return err
	}
	for _, path := range secrets.Paths() {
		err = v.deleteEntireSecret(path, opts.Destroy, opts.All)
		if err != nil {
			return err
		}
	}

	mount, err := v.Client().MountPath(rawRoot)
	if err != nil {
		return err
	}

	if strings.Trim(rawRoot, "/") != strings.Trim(mount, "/") {
		err = v.deleteEntireSecret(root, opts.Destroy, opts.All)
	}

	return err
}

type DeleteOpts struct {
	Destroy bool
	All     bool
}

func (v *Vault) canSemanticallyDelete(path string) error {
	justSecret, key, version := ParsePath(path)
	if key == "" || version == 0 {
		return nil
	}

	versions, err := v.Versions(justSecret)
	if err != nil {
		return err
	}

	if len(versions) == 0 {
		return NewSecretNotFoundError(justSecret)
	}

	if versions[len(versions)-1].Version == uint(version) {
		return nil
	}

	//Read the version, not the key: a read of a path that names a key hands
	// back that one key, so asking this way makes every version look as though
	// it held nothing else, and the check below can never find anything to
	// object to. ParsePath unescaped the secret path, and Read parses its
	// argument again, so the escaped form goes back in.
	s, err := v.Read(EncodePath(justSecret, "", version))
	if err != nil {
		return err
	}

	if !s.Has(key) {
		return NewKeyNotFoundError(justSecret, key)
	}

	if len(s.data) != 1 {
		return fmt.Errorf("cannot delete %s from version %d: that version holds other keys, and a version already written cannot be rewritten", key, version)
	}

	return nil
}

// Delete removes the secret or key stored at the specified path.
// If destroy is true and the mount is v2, the latest version is destroyed instead
func (v *Vault) Delete(path string, opts DeleteOpts) error {
	path = Canonicalize(path)

	reqState := verifyStateAlive
	if opts.Destroy {
		reqState = verifyStateAliveOrDeleted
	}

	err := v.verifySecretState(path, verifyOpts{
		AnyVersion: opts.All,
		State:      reqState,
	})
	if err != nil {
		return err
	}

	err = v.canSemanticallyDelete(path)
	if err != nil {
		return err
	}

	if !PathHasKey(path) {
		return v.deleteEntireSecret(path, opts.Destroy, opts.All)
	}

	return v.deleteSpecificKey(path)
}

func (v *Vault) deleteEntireSecret(path string, destroy bool, all bool) error {
	secret, _, version := ParsePath(path)

	if destroy && all {
		return v.client.DestroyAll(secret)
	}

	var versions []uint
	if version != 0 {
		versions = []uint{uint(version)}
	}

	if destroy {
		allVersions, err := v.Versions(secret)
		if err != nil {
			return err
		}
		if len(allVersions) == 0 {
			return NewSecretNotFoundError(secret)
		}
		//Need to populate latest version to a Destroy call if the
		// version is not explicitly given
		if len(versions) == 0 {
			versions = []uint{allVersions[len(allVersions)-1].Version}
		}
		//Check if we should clean up the metadata entirely because there are
		// no more remaining non-destroyed versions
		shouldNuke := true
		verIdx := 0
		for i := range allVersions {
			for verIdx < len(versions) && versions[verIdx] < allVersions[i].Version {
				verIdx++
			}
			if !allVersions[i].Destroyed && (verIdx >= len(versions) || versions[verIdx] != allVersions[i].Version) {
				shouldNuke = false
				break
			}
		}

		if shouldNuke {
			return v.client.DestroyAll(secret)
		}
		return v.client.Destroy(secret, versions)
	}

	if all {
		allVersions, err := v.Versions(secret)
		if err != nil {
			return err
		}

		versions = make([]uint, 0, len(allVersions))
		for i := range allVersions {
			versions = append(versions, allVersions[i].Version)
		}

	}

	return v.client.Delete(secret, &vaultkv.KVDeleteOpts{Versions: versions, V1Destroy: true})
}

func (v *Vault) deleteSpecificKey(path string) error {
	secretPath, key, _ := ParsePath(path)
	//ParsePath unescaped the secret path. Read, Write, and deleteEntireSecret
	// all parse their argument again, so they need the escaped form back or
	// they split a second time at a colon that belongs to the path.
	encodedPath := EncodePath(secretPath, "", 0)
	secret, err := v.Read(encodedPath)
	if err != nil {
		return err
	}
	deleted := secret.Delete(key)
	if !deleted {
		return NewKeyNotFoundError(secretPath, key)
	}
	if secret.Empty() {
		//Gotta avoid call to Write because Write ignores version information (with good reason)
		// We can only be here and not be on the latest version if this was the only key remaining
		// and we're just trying to nuke the secret
		//
		//At some point, we should probably get Destroy routed into here so that we can destroy
		// secrets through specifying keys
		return v.deleteEntireSecret(encodedPath, false, false)
	}
	return v.Write(encodedPath, secret)
}

// DeleteVersions marks the given versions of the given secret as deleted for
// a v2 backend or actually deletes it for a v1 backend.
func (v *Vault) DeleteVersions(path string, versions []uint) error {
	return v.client.Delete(path, &vaultkv.KVDeleteOpts{Versions: versions, V1Destroy: true})
}

// DestroyVersions irrevocably destroys the given versions of the given secret
func (v *Vault) DestroyVersions(path string, versions []uint) error {
	return v.client.Destroy(path, versions)
}

func (v *Vault) Undelete(path string) error {
	secret, key, version := ParsePath(path)
	if key != "" {
		return fmt.Errorf("cannot undelete specific key (%s)", path)
	}

	respVersions, err := v.Versions(secret)
	if err != nil {
		return err
	}

	if len(respVersions) == 0 {
		return NewSecretNotFoundError(secret)
	}

	if version == 0 {
		version = uint64(respVersions[len(respVersions)-1].Version)
	}

	//Said the way a read says it, but left a plain error: this one reaches the
	// tree walk, and MoveCopyTree drops walk errors that answer to IsNotFound.
	destroyedErr := errors.New(VersionNotFoundMessage(secret, version, "destroyed"))
	firstVersion := respVersions[0].Version
	if version < uint64(firstVersion) {
		return destroyedErr
	}

	diff := version - uint64(firstVersion)
	const maxInt = int(^uint(0) >> 1)
	if diff > uint64(maxInt) {
		return fmt.Errorf("version difference too large for int conversion")
	}
	idx := int(diff)
	if idx >= len(respVersions) {
		return errors.New(VersionNotFoundMessage(secret, version, ""))
	}

	if respVersions[idx].Destroyed {
		return destroyedErr
	}

	return v.Client().Undelete(secret, []uint{uint(version)})
}

// deleteIfPresent first checks to see if there is a Secret at the given path,
// and if so, it deletes it. Otherwise, no error is thrown
func (v *Vault) deleteIfPresent(path string, opts DeleteOpts) error {
	secretpath, _, _ := ParsePath(path)
	if _, err := v.Read(secretpath); err != nil {
		if IsSecretNotFound(err) {
			return nil
		}
		return err
	}

	err := v.Delete(path, opts)
	if IsKeyNotFound(err) {
		return nil
	}
	return err
}

func (v *Vault) verifyMetadataExists(path string) error {
	versions, err := v.Versions(path)
	if err != nil {
		if vaultkv.IsNotFound(err) {
			return NewSecretNotFoundError(path)
		}
		return err
	}

	if len(versions) == 0 {
		return NewSecretNotFoundError(path)
	}

	return nil
}

type MoveCopyOpts struct {
	SkipIfExists bool
	Quiet        bool
	//Deep copies all versions and overwrites all versions at the target location
	Deep bool
	//DeletedVersions undeletes, reads, and redeletes the deleted keys
	// It also puts in dummy destroyed keys to dest to match destroyed keys from src
	//Makes no sense without Deep
	DeletedVersions bool
}

// Copy copies secrets from one path to another.
// With a secret:key specified: key -> key is good.
// key -> no-key is okay - we assume to keep old key name
// no-key -> key is bad. That makes no sense and the user should feel bad.
// Returns KeyNotFoundError if there is no such specified key in the secret at oldpath
func (v *Vault) Copy(oldpath, newpath string, opts MoveCopyOpts) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	if opts.DeletedVersions && !opts.Deep {
		return fmt.Errorf("DeletedVersions requires Deep to be set")
	}
	var err error
	reqState := verifyStateAlive
	if opts.DeletedVersions {
		reqState = verifyStateAliveOrDeleted
	}

	err = v.verifySecretState(oldpath, verifyOpts{
		State:      reqState,
		AnyVersion: opts.Deep,
	})
	if err != nil {
		return err
	}

	if opts.SkipIfExists {
		if _, err := v.Read(newpath); err == nil {
			if !opts.Quiet {
				_, _ = ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as that would clobber existing data}\n", newpath)
			}
			return nil
		} else if !IsNotFound(err) {
			return err
		}
	}

	srcPath, srcKey, srcVersion := ParsePath(oldpath)
	dstPath, dstKey, dstVersion := ParsePath(newpath)
	//ParsePath unescaped both paths. The tree walk and SecretEntry.Copy want
	// those literal Vault paths, but Read and Write parse their argument again,
	// so they get the destination back in the escaped syntax.
	encodedDstPath := EncodePath(dstPath, "", 0)

	if dstVersion != 0 {
		return fmt.Errorf("copying a secret to a specific destination version is not supported")
	}

	if opts.Deep && srcVersion != 0 {
		return fmt.Errorf("performing a deep copy of a specified version is not supported")
	}

	var toWrite []*Secret
	if srcKey != "" { //Just a single key.
		if opts.Deep {
			return fmt.Errorf("cannot take deep copy of a specific key")
		}
		srcSecret, err := v.Read(oldpath)
		if err != nil {
			return err
		}

		if !srcSecret.Has(srcKey) {
			return NewKeyNotFoundError(oldpath, srcKey)
		}

		if dstKey == "" {
			dstKey = srcKey
		}

		dstOrig, err := v.Read(encodedDstPath)
		if err != nil && !IsSecretNotFound(err) {
			return err
		}

		if IsSecretNotFound(err) {
			dstOrig = NewSecret()
		}

		toWrite = append(toWrite, dstOrig)
		_ = toWrite[0].Set(dstKey, srcSecret.Get(srcKey), false)
	} else {
		if dstKey != "" {
			return fmt.Errorf("cannot move full secret `%s` into specific key `%s`", oldpath, newpath)
		}
		t, err := v.ConstructSecrets(srcPath, TreeOpts{
			FetchKeys:           true,
			GetOnly:             true,
			FetchAllVersions:    opts.Deep || srcVersion != 0,
			GetDeletedVersions:  opts.Deep && opts.DeletedVersions,
			AllowDeletedSecrets: opts.Deep || srcVersion != 0,
		})

		if err != nil {
			return err
		}

		if len(t) == 0 {
			// Prevent a panic
			return NewSecretNotFoundError(srcPath)
		}

		if srcVersion != 0 {
			//Filter results to the specific requested secret
			for i := range t[0].Versions {
				if t[0].Versions[i].Number == uint(srcVersion) {
					t[0].Versions = []SecretVersion{t[0].Versions[i]}
					break
				}
			}
		}

		err = t[0].Copy(v, dstPath, TreeCopyOpts{Clear: opts.Deep, Pad: opts.Deep})
		if err != nil {
			return err
		}
	}

	for i := range toWrite {
		err := v.Write(encodedDstPath, toWrite[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// MoveCopyTree will recursively copy all nodes from the root to the new location.
// This function will get confused about 'secret:key' syntax, so don't let those
// get routed here - they don't make sense for a recursion anyway.
func (v *Vault) MoveCopyTree(oldRoot, newRoot string, f func(string, string, MoveCopyOpts) error, opts MoveCopyOpts) error {
	//Neither root can name a key or a version: the recursion drops both and
	// relocates the whole subtree instead of the one thing that was named.
	rawOldRoot, oldKey, oldVersion := ParsePath(oldRoot)
	rawNewRoot, newKey, newVersion := ParsePath(newRoot)
	if oldKey != "" || newKey != "" || oldVersion != 0 || newVersion != 0 {
		return fmt.Errorf("cannot recursively copy or move a specific key or version (%s -> %s)", oldRoot, newRoot)
	}
	//The walk wants the literal Vault paths ParsePath returned. The prefix
	// replace below and f() both work in the escaped syntax that
	// Secrets.Paths() emits, and EscapePathSegment substitutes byte by byte,
	// so escaping a path and escaping its root prefix agree: the replace stays
	// exact. Re-encoding also normalizes the roots the way the walk does.
	oldRoot = EncodePath(rawOldRoot, "", 0)
	newRoot = EncodePath(rawNewRoot, "", 0)

	tree, err := v.ConstructSecrets(rawOldRoot, TreeOpts{FetchKeys: false, AllowDeletedSecrets: opts.Deep, SkipVersionInfo: true})
	if err != nil {
		return err
	}
	if opts.SkipIfExists {
		//Writing one secret over a deleted secret isn't clobbering. Completely overwriting a set of deleted secrets would be
		newTree, err := v.ConstructSecrets(rawNewRoot, TreeOpts{FetchKeys: false, AllowDeletedSecrets: !opts.Deep, SkipVersionInfo: true})
		if err != nil && !IsNotFound(err) {
			return err
		}
		existing := map[string]bool{}
		for _, path := range newTree.Paths() {
			existing[path] = true
		}
		existingPaths := []string{}
		for _, path := range tree.Paths() {
			newPath := strings.Replace(path, oldRoot, newRoot, 1)
			if existing[newPath] {
				existingPaths = append(existingPaths, newPath)
			}
		}
		if len(existingPaths) > 0 {
			if !opts.Quiet {
				_, _ = ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as the following paths would be clobbered:}\n", newRoot)
				for _, path := range existingPaths {
					_, _ = ansi.Fprintf(os.Stderr, "@R{- }@C{%s}\n", path)
				}
			}
			return nil
		}
	}
	for _, path := range tree.Paths() {
		newPath := strings.Replace(path, oldRoot, newRoot, 1)
		err = f(path, newPath, opts)
		if err != nil {
			return err
		}
	}

	if _, err := v.Read(oldRoot); !IsNotFound(err) { // run through a copy unless we successfully got a 404 from this node
		return f(oldRoot, newRoot, opts)
	}
	return nil
}

// Move moves secrets from one path to another.
// A move is semantically a copy and then a deletion of the original item. For
// more information on the behavior of Move pertaining to keys, look at Copy.
func (v *Vault) Move(oldpath, newpath string, opts MoveCopyOpts) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	err := v.canSemanticallyDelete(oldpath)
	if err != nil {
		return fmt.Errorf("can't move `%s': %w. Did you mean cp?", oldpath, err)
	}

	err = v.Copy(oldpath, newpath, opts)
	if err != nil {
		return err
	}

	if opts.Deep && opts.DeletedVersions {
		//DestroyAll goes straight to Vault, so it takes the literal path rather
		// than the escaped syntax the caller wrote. Copy has already refused a
		// deep move that names a key or a version, so nothing is dropped here.
		rawOldPath, _, _ := ParsePath(oldpath)
		err = v.client.DestroyAll(rawOldPath)
		if err != nil {
			return err
		}
	} else {
		err = v.Delete(oldpath, DeleteOpts{})
		if err != nil {
			return err
		}
	}
	return nil
}

type mountpoint struct {
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Config      map[string]any `json:"config"`
}

func (v *Vault) Mounts(typ string) ([]string, error) {
	mounts, err := v.client.Client.ListMounts()
	if err != nil {
		return nil, err
	}

	ret := []string{}

	for name, mountInfo := range mounts {
		if mountInfo.Type == typ {
			ret = append(ret, strings.TrimSuffix(name, "/")+"/")
		}
	}

	return ret, nil
}

func (v *Vault) IsMounted(typ, path string) (bool, error) {
	mounts, err := v.Mounts(typ)
	if err != nil {
		return false, err
	}

	for _, at := range mounts {
		if at == path || at == path+"/" {
			return true, nil
		}
	}
	return false, nil
}

func (v *Vault) Mount(typ, path string, params map[string]any) error {
	mounted, err := v.IsMounted(typ, path)
	if err != nil {
		return err
	}

	if !mounted {
		p := mountpoint{
			Type:        typ,
			Description: "(managed by safe)",
			Config:      params,
		}
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}

		res, err := v.Curl("POST", fmt.Sprintf("sys/mounts/%s", path), data)
		if err != nil {
			return err
		}
		defer func() { _ = res.Body.Close() }()

		if res.StatusCode != 204 {
			body, err := io.ReadAll(res.Body)
			if err != nil {
				return err
			}
			return DecodeErrorResponse(body)
		}

	} else {
		data, err := json.Marshal(params)
		if err != nil {
			return err
		}

		res, err := v.Curl("POST", fmt.Sprintf("sys/mounts/%s/tune", path), data)
		if err != nil {
			return err
		}
		defer func() { _ = res.Body.Close() }()

		if res.StatusCode != 204 {
			body, err := io.ReadAll(res.Body)
			if err != nil {
				return err
			}
			return DecodeErrorResponse(body)
		}
	}

	return nil
}

func (v *Vault) RetrievePem(backend, path string) ([]byte, error) {
	if err := v.CheckPKIBackend(backend); err != nil {
		return nil, err
	}

	res, err := v.Curl("GET", fmt.Sprintf("/%s/%s/pem", backend, path), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		return nil, DecodeErrorResponse(body)
	}

	return body, nil
}

func DecodeErrorResponse(body []byte) error {
	var raw map[string]any

	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("received non-200 with non-JSON payload:\n%s", body)
	}

	if rawErrors, ok := raw["errors"]; ok {
		var errors []string
		if elems, ok := rawErrors.([]any); ok {
			for _, elem := range elems {
				if err, ok := elem.(string); ok {
					errors = append(errors, err)
				}
			}
			return fmt.Errorf("%s", strings.Join(errors, "\n"))
		} else {
			return fmt.Errorf("received unexpected format of Vault error messages:\n%v", errors)
		}
	} else {
		return fmt.Errorf("received non-200 with no error messagess:\n%v", raw)
	}
}

type CertOptions struct {
	CN                string `json:"common_name"`
	TTL               string `json:"ttl,omitempty"`
	AltNames          string `json:"alt_names,omitempty"`
	IPSans            string `json:"ip_sans,omitempty"`
	ExcludeCNFromSans bool   `json:"exclude_cn_from_sans,omitempty"`
}

func (v *Vault) CreateSignedCertificate(backend, role, path string, params CertOptions, skipIfExists bool) error {
	if err := v.CheckPKIBackend(backend); err != nil {
		return err
	}

	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	res, err := v.Curl("POST", fmt.Sprintf("%s/issue/%s", backend, role), data)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	if res.StatusCode >= 400 {
		return fmt.Errorf("unable to create certificate %s: %s", params.CN, DecodeErrorResponse(body))
	}

	var raw map[string]any
	if err = json.Unmarshal(body, &raw); err == nil {
		if d, ok := raw["data"]; ok {
			if data, ok := d.(map[string]any); ok {
				var cert, key, serial string
				var c, k, s any
				var ok bool
				if c, ok = data["certificate"]; !ok {
					return fmt.Errorf("no certificate found when issuing certificate %s:\n%v", params.CN, data)
				}
				if cert, ok = c.(string); !ok {
					return fmt.Errorf("invalid data type for certificate %s:\n%v", params.CN, data)
				}
				if k, ok = data["private_key"]; !ok {
					return fmt.Errorf("no private_key found when issuing certificate %s:\n%v", params.CN, data)
				}
				if key, ok = k.(string); !ok {
					return fmt.Errorf("invalid data type for private_key %s:\n%v", params.CN, data)
				}
				if s, ok = data["serial_number"]; !ok {
					return fmt.Errorf("no serial_number found when issuing certificate %s:\n%v", params.CN, data)
				}
				if serial, ok = s.(string); !ok {
					return fmt.Errorf("invalid data type for serial_number %s:\n%v", params.CN, data)
				}

				secret, err := v.Read(path)
				if err != nil && !IsNotFound(err) {
					return err
				}
				err = secret.Set("cert", cert, skipIfExists)
				if err != nil {
					return err
				}
				err = secret.Set("key", key, skipIfExists)
				if err != nil {
					return err
				}
				err = secret.Set("combined", cert+key, skipIfExists)
				if err != nil {
					return err
				}
				err = secret.Set("serial", serial, skipIfExists)
				if err != nil {
					return err
				}
				return v.Write(path, secret)
			} else {
				return fmt.Errorf("invalid response datatype requesting certificate %s:\n%v", params.CN, d)
			}
		} else {
			return fmt.Errorf("no data found when requesting certificate %s:\n%v", params.CN, d)
		}
	} else {
		return fmt.Errorf("unparseable json creating certificate %s:\n%s", params.CN, body)
	}
}

func (v *Vault) RevokeCertificate(backend, serial string) error {
	if err := v.CheckPKIBackend(backend); err != nil {
		return err
	}

	if strings.ContainsRune(serial, '/') {
		secret, err := v.Read(serial)
		if err != nil {
			return err
		}
		if !secret.Has("serial") {
			return fmt.Errorf("certificate specified using path %s, but no serial secret was found there", serial)
		}
		serial = secret.Get("serial")
	}

	d := struct {
		Serial string `json:"serial_number"`
	}{Serial: serial}

	data, err := json.Marshal(d)
	if err != nil {
		return err
	}

	res, err := v.Curl("POST", fmt.Sprintf("%s/revoke", backend), data)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode >= 400 {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("unable to revoke certificate %s: %s", serial, DecodeErrorResponse(body))
	}
	return nil
}

func (v *Vault) CheckPKIBackend(backend string) error {
	mounted, err := v.IsMounted("pki", backend)
	if err != nil {
		return fmt.Errorf("could not check PKI backend: %w", err)
	}
	if !mounted {
		return fmt.Errorf("the PKI backend `%s` has not been configured. Try running `safe pki init --backend %s`", backend, backend)
	}
	return nil
}

// FindSigningCA returns the authority that should sign cert, and the path it
// was read from. A certificate signs itself when it is named as its own
// authority or when it already carries its own signature; otherwise the
// authority is read from the Vault, and has to be one — signing with a plain
// certificate produces something no relying party will accept, and nothing
// further along reports it.
func (v *Vault) FindSigningCA(cert *X509, certPath string, signPath string) (*X509, string, error) {
	/* find the CA */
	if signPath != "" {
		if certPath == signPath {
			return cert, certPath, nil
		} else {
			s, err := v.Read(signPath)
			if err != nil {
				return nil, "", err
			}
			ca, err := s.X509(true)
			if err != nil {
				return nil, "", err
			}
			if !ca.IsCA() {
				return nil, "", fmt.Errorf("%s is not a certificate authority", signPath)
			}
			return ca, signPath, nil
		}
	} else {
		// Check if this cert is self-signed If so, don't change the value
		// of s, because its already the cert we loaded in. #Hax
		err := cert.Certificate.CheckSignature(
			cert.Certificate.SignatureAlgorithm,
			cert.Certificate.RawTBSCertificate,
			cert.Certificate.Signature,
		)
		if err == nil {
			return cert, certPath, nil
		} else {
			// Lets see if we can guess the CA if none was provided
			caPath := certPath[0:strings.LastIndex(certPath, "/")] + "/ca"
			s, err := v.Read(caPath)
			if err != nil {
				return nil, "", fmt.Errorf("no signing authority provided and no 'ca' sibling found")
			}
			ca, err := s.X509(true)
			if err != nil {
				return nil, "", err
			}
			if !ca.IsCA() {
				return nil, "", fmt.Errorf("%s is not a certificate authority", caPath)
			}
			//The sibling is a guess. Signing under it when it is not the
			// authority that issued the certificate hands back something
			// with a different issuer than the one it went in with, which
			// is not what renewing or reissuing was asked to do. Naming an
			// authority explicitly still moves a certificate to a new one.
			if err := ca.Certificate.CheckSignature(
				cert.Certificate.SignatureAlgorithm,
				cert.Certificate.RawTBSCertificate,
				cert.Certificate.Signature,
			); err != nil {
				return nil, "", fmt.Errorf("%s did not sign %s; name its authority with --signed-by", caPath, certPath)
			}
			return ca, caPath, nil
		}
	}
}

func (v *Vault) SaveSealKeys(keys []string) error {
	path := "secret/vault/seal/keys"
	s := NewSecret()
	for i, key := range keys {
		if err := s.Set(fmt.Sprintf("key%d", i+1), key, false); err != nil {
			return err
		}
	}
	return v.Write(path, s)
}

func (v *Vault) SetURL(u string) error {
	vaultURL, err := url.Parse(strings.TrimSuffix(u, "/"))
	if err != nil {
		return fmt.Errorf("could not parse Vault URL: %w", err)
	}

	//The default port for Vault is typically 8200 (which is the VaultKV default),
	// but safe has historically ignored that and used the default http or https
	// port, depending on which was specified as the scheme
	if vaultURL.Port() == "" {
		port := ":80"
		if strings.ToLower(vaultURL.Scheme) == "https" {
			port = ":443"
		}
		vaultURL.Host = vaultURL.Host + port
	}
	v.client.Client.VaultURL = vaultURL
	return nil
}
