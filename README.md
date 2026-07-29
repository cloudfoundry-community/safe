safe - A Vault CLI
==================

Questions? Pop in our [slack channel](https://cloudfoundry.slack.com/messages/vault/)!

![SAFE](docs/safe.png)

[Vault][vault] is an awesome project and it comes with superb
documentation, a rock-solid server component and a flexible and
capable command-line interface.

![get-set-passwords](docs/safely-generate-passwords.gif)

So, why `safe`?  To solve the following problems:

  1. Securely generate new SSH public / private keys
  2. Securely generate random RSA key pairs
  3. Auto-generate secure, random passwords
  4. Securely provide credentials, without files
  5. Dumping multiple paths

Primarily, these are things encountered in trying to build secure
BOSH deployments using Vault and [Spruce][spruce].

ATTENTION HOMEBREW USERS
------------------------

If you run Homebrew on MacOS, be aware that the the Formula for
safe in homebrew core is outdated, incorrect, and unmaintained.
We maintain our own tap, which you are encouraged to use instead:

```
brew tap cloudfoundry-community/cf
brew install cloudfoundry-community/cf/safe
```


Authentication
--------------

To make it easier to target multiple Vaults from one client (i.e.
your work laptop), `safe` lets you track and authenticate against
_targets_, each representing a different vault.

To get started, you'll need to add a new target:

```
safe target https://vault.example.com myvault
```

The first argument is the URL to the Vault; the second is a
shorthand alias for the target.  Later, you can retarget this
Vault with just:

```
safe target myvault
```

You can see what Vaults you have targeted by running

```
safe targets
```

All commands will be run against the currently targeted Vault.

To authenticate:

```
safe auth [token]
safe auth ldap
safe auth github
safe auth okta
```

(Other authentication backends are not yet supported)

For each type (token, ldap, okta or github), you will be prompted for
the necessary credentials to authenticated against the Vault.

Usage
-----

`safe` operates by way of sub-commands.  To generate a new
2048-bit SSH keypair, and store it in `secret/ssh`:

```
safe ssh 2048 secret/ssh
```

To set non-sensitive keys, you can just specify them inline:

```
safe set secret/ssh username=system
```

If you use a password manager (good for you!) and don't want to
have to paste passwords twice, use the `paste` subcommand:

```
safe paste secret/1pass/managed
```

Commands can be chained by separating them with the argument
terminator, `--`, so to both create a new SSH keypair and set the
username:

```
safe ssh 2048 secret/ssh -- set secret/ssh username=system
```

Auto-generated passwords are easy too:

```
safe gen secret/account passphrase
```

Sometimes, you just want to import passwords from another source
(like your own password manager), without the hassle of writing
files to disk or the risk of leaking credentials via the process
table or your shell history file.  For that, `safe` provides a
double-confirmation interactive mode:

```
safe set secret/ssl/ca passphrase
passphrase [hidden]:
passphrase [confirm]:
```

What you type will not be echoed back to the screen, and the
confirmation prompt is there to make sure your fingers didn't
betray you.

All operations (except for `delete`) are additive, so the
following:

```
safe set secret/x a=b c=d
```

is equivalent to this:

```
safe set secret/x a=b -- set secret/x c=d
```

Need to take an existing password, and generate a crypt-sha512 hash,
or base64 encode it? `safe fmt` will do this, and store the results
in a new key for you, making it easy to generate a password, and then
format that password as needed.

```
safe gen secret/account password
safe fmt base64 secret/account password base64_pass
safe fmt crypt-sha512 secret/account password crypt_pass
safe get secret/account
```

Secret Paths
------------

Most commands take a _path_ naming a secret, like `secret/dc1/admin`.
Some also accept a single key inside that secret, written after a
`:`, and a specific version of it, written after a `^`:

```
safe get secret/dc1/admin            # every key, latest version
safe get secret/dc1/admin:password   # one key
safe get secret/dc1/admin^3          # every key, version 3
safe get secret/dc1/admin:password^3 # one key, version 3
```

The version must come last.  Version numbers start at 1, and are only
meaningful on a version 2 KV mount; `^0` means the latest version,
which is the same as leaving the version off entirely.

Not every command understands all three parts, and the ones that
cannot honour a key or a version say so rather than ignoring it:

  - Commands that write a whole secret — `set`, `ask`, `paste`, `ssh`,
    `rsa`, and `dhparam` — take a path only.

  - Commands that list what is under a path — `ls`, `tree`, `paths`,
    `values`, and `export` — take a path only, since a key or a
    version cannot scope a listing.

  - `gen` and `uuid` take `path:key`, which is how you name the key
    they are about to create.

  - `get`, `exists`, and `delete` take all three.

  - `move` and `copy` take a key or a version on the secret they read
    from, and a key on the one they write to.

### Escaping

Because `:` and `^` separate the parts, a path or key that contains
one has to escape it with a backslash:

```
safe set secret/dc1/admin 'user:name=root'
safe get 'secret/dc1/admin:user\:name'
```

Only the arguments `safe` parses need escaping.  The key named on a
`set` is taken as written, which is why the same key goes in plain
and comes back escaped.

The backslash escapes itself as well, so a path or key holding a
literal backslash takes two:

```
safe set 'secret/dc1/we\\ird' password=s3cr3t
safe get 'secret/dc1/we\\ird:password'
```

`safe` prints paths in this same escaped form, so anything from `safe
paths`, `safe paths --keys`, `safe tree --keys`, or `safe ls` can be
pasted straight back into another command:

```
safe paths --keys secret/dc1/admin
secret/dc1/admin:password
secret/dc1/admin:user\:name
```

`safe ls` prints one name per entry rather than a whole path, and
escapes each name the same way, so joining a name to the path you
listed gives a path `safe` accepts:

```
safe ls secret/dc1
admin  we\:ird/
safe ls 'secret/dc1/we\:ird'
haproxy
```

Quote these arguments, or your shell will eat the backslashes before
`safe` ever sees them.

Command Reference
------------------

### set path key\[=value\] \[key ...\]

Updates a single path with new keys.  Any existing keys that are
not specified on the command line are left intact.

You will be prompted to enter values for any keys that do not have
values.  This can be used for more sensitive credentials like
passwords, PINs, etc.

Example:

```
safe set secret/root username=root password
<prompts for 'password' here...>
```

Similarly, `safe paste` works the same way, but does not have a confirmation
prompt for your value. It assumes you have pasted in the value from a known-good
source.

Setting the value of a key to be the contents of a file

Example:

```
safe set secret/root ssl_key@/path/to/ssl_key_file
```

### get path \[path ...\]

Retrieve and print the values of one or more paths, to standard
output.  This is most useful for piping credentials through
`keybase` or `pgp` for encrypting and sending to others.

```
safe get secret/root secret/whatever secret/key
--- # secret/root
username: root
password: it's a secret

--- # secret/whatever
whatever: is clever

--- # secret/key
private: |
   -----BEGIN RSA PRIVATE KEY-----
   ...
   -----END RSA PRIVATE KEY-----
public: |
  -----BEGIN RSA PUBLIC KEY-----
  ...
  -----END RSA PRIVATE KEY-----
```

### ls \[-1|-q\] \[path ...\]

List what sits directly under a path, one level deep: secrets plain,
folders with a trailing slash.  With no path, the mounts are listed
instead.  `-1` prints one entry per line.

A secret is listed only if its newest version can still be read, so
one whose newest version has been deleted or destroyed is left out —
even when an older version of it is still live.  Finding that out
costs a read per secret, and `-q` skips the check and lists those
secrets too.  Only a version 2 mount keeps versions, so neither the
check nor `-q` does anything on a version 1 mount.

```
safe ls secret/dc1
admin  concourse/

safe ls -1 secret/dc1/concourse/pipeline-the-first
aws
dockerhub
github
```

### tree \[-d|-q|--keys\] path \[path ...\]

Provide a tree hierarchy listing of all reachable keys in the
Vault.

`-d` draws only the folders, which is a quicker way to get your
bearings in an unfamiliar Vault.  `--keys` names the keys inside each
secret beside it.  `-q` skips the liveness check, exactly as it does
for `ls` above.

```
safe tree secret/dc1
.
└── secret/dc1/
    └── concourse/
        ├── pipeline-the-first/
        │   ├── aws
        │   ├── dockerhub
        │   └── github
        └── pipeline-the-second/
            ├── aws
            ├── dockerhub
            └── github
```

### paths \[-q|--keys\] path \[path ... \]

Provide a flat listing of all reachable keys in the Vault.

`--keys` prints a line per key, as `path:key`, rather than a line per
secret.  `-q` skips the liveness check, exactly as it does for `ls`
above.

```
safe paths secret/dc1
secret/dc1/concourse/pipeline-the-first/aws
secret/dc1/concourse/pipeline-the-first/dockerhub
secret/dc1/concourse/pipeline-the-first/github
secret/dc1/concourse/pipeline-the-second/aws
secret/dc1/concourse/pipeline-the-second/dockerhub
secret/dc1/concourse/pipeline-the-second/github
```

### values \[--keys\] \[-p path ...\] value \[value ...\]

Find the secrets whose latest live version contains one of the given
values, matched exactly and case-sensitively. Handy for auditing
credential reuse or locating every place a leaked value must be
rotated. Repeat `-p` to search several subtrees (default: `secret`);
with `--keys`, each match is printed as `path:key`. Values may also be
read from a file (`@file`), standard input (`@-`), or a hidden prompt
(no arguments). Subtrees the token cannot read are skipped with a
warning on standard error.

```
safe values -p secret/prod hunter2
secret/prod/db
secret/prod/legacy/db

safe values --keys hunter2
secret/prod/db:password
secret/prod/legacy/db:old-password
```

### delete path \[path ...\]

Removes multiple paths from the Vault.

```
safe delete secret/unused
```

### move oldpath newpath

Move a secret from `oldpath` to `newpath`, a rename of sorts.

```
safe move secret/staging/user secret/prod/user
```

(or, more succinctly, using brace expansion):

```
safe move secret/{staging,prod}/user
```

Any credentials at `newpath` will be completely overwritten.  The
secret at `oldpath` will no longer exist.

### copy oldpath newpath

Copy a secret from `oldpath` to `newpath`.

```
safe copy secret/staging/user secret/prod/user
```

(or, as with `move`, using brace expansion):

```
save copy secret/{staging,prod}/user
```

Any credentials at `newpath` will be completely overwritten.  The
secret at `oldpath` will still exist after the copy.

### gen \[length\] path key

Generate a new, random password.  By default, the generated
password will be 64 characters long.

```
safe gen secret/account secretkey
```

To get a shorter password, only 16 characters long:

```
safe gen 16 secret/account password
```

### fmt format_type path oldKey newKey

Take the key at `path:oldKey`, reformat it according to **format_type**,
and save it in `path:newKey`. Useful for hashing, or encoding passwords
in an alternate format (for htpass files, or /etc/shadow).

Currently supported formats:

- base64
- bcrypt
- crypt-md5
- crypt-sha256
- crypt-sha512

```
safe fmt base64 secret/account password base64_password
safe fmt crypt-sha512 secret/account password crypt_password
```

### ssh \[nbits\] path \[path ...\]

Generate a new SSH RSA keypair, adding the keys "private" and
"public" to each path.  The public key will be encoded as an
authorized keys.  The private key is a PEM-encoded DER private
key.

By default, a 2048-bit key will be generated.  The `nbits`
parameter allows you to change that.

Each path gets a unique SSH keypair.

### rsa \[nbits\] path \[path ...\]

Generate a new RSA keypair, adding the keys "private" and "public"
to each path.  Both keys will be PEM-encoded DER.

By default, a 2048-bit key will be generated.  The `nbits`
parameter allows you to change that.

Each path gets a unique RSA keypair.

### prompt ...

Echo the arguments, space-separated, as a single line to the
terminal.  This is a convenience helper for long pipelines of
chained commands.

### x509 issue \[OPTIONS\] --name cn.example.com path

Issues a new X.509 TLS/SSL certificate, and stores the new RSA
private key and the certificate in the Vault at _path_, in PEM
format.

### x509 revoke \[OPTIONS\] --signed-by path/to/ca path/to/cert

Revoke a certificate that was signed by a Certificate Authority.
The private key for the CA must be present in the Vault for this
to work.  Revoked certificates will be appended to the CA's
certificate revocation list (CRL), stored at `path/to/ca:crl`

### x509 validate \[OPTIONS\] path

Run a variety of validation checks against a certificate in the
Vault.  In its simplest form, without arguments, this verifies
that the private key stored at `path:key` matches the certificate
stored at `path:certificate`.  Options control more powerful
validations, like checking for revocation, SAN validity, and
expiry.

### x509 crl --renew path

Renews (re-signs) the certificate authority at `path`, without
affecting the list of revoked certificates.

### export \[-a|-d\] path \[path ...\]

Export the given subtree(s) in a format suitable for migration
(via a future `import` call), or long-term storage offline.
Secrets will not be encrypted in this representation, so care
should be taken in handling it.  Output will be printed to
standard output.

By default only the latest version of each secret is exported, which
keeps the output readable by versions of `safe` before v1.0.0.  `-a`
exports every version instead, in a newer format those versions cannot
read.

A secret is exported only if something in it can be read.  A plain
export takes the latest version, so it skips a secret whose latest
version has been deleted or destroyed; `-a` keeps any secret with at
least one readable version, and records the unreadable ones in place
as empty placeholders, so the versions around them keep their numbers.

`-d` undeletes, reads, and re-deletes each deleted version so that it
is exported with its value rather than as a placeholder, and it also
brings in the secrets a plain export would have skipped entirely.  A
destroyed version cannot be recovered and stays a placeholder either
way.

### import <export.file

Read an export (as produced by the `export` subcommand) from
standard input, and write all of the secrets contained
therein to the same paths inside the targeted Vault.  Trees
will be imported in an additive nature, so existing credentials
in the same subtree as imported credentials will be left intact.

If you've got an export saved in a file _on-disk_, you can feed
it to `safe import` using your shell's redirection facilities:

```
safe import < ./path/to/export.file
```

You can also use `cat`, in the standard UNIX idiom:

```
cat ./path/to/export.file | safe import
```

(_Note:_ storing exports on-disk is considered bad practice, as
 it leaks your secrets via a shared resource: the filesystem.)

Import and export can be combined in a pipeline to facilitate
movement of credentials from one Vault to another, like so:

```
safe -T old-vault export secret/sub/tree | \
  safe -T new-vault import
```

### env

Print the environment variables describing the current target:

```
safe env
  VAULT_ADDR  http://localhost:8200
  VAULT_TOKEN  $SOME_UUID
```

You can also use this command to export a target's configuration into the outer
shell in order to use the Vault CLI directly:

```
safe env --bash
\export VAULT_ADDR=http://localhost:8200;
\export VAULT_TOKEN=$SOME_UUID;
\unset VAULT_SKIP_VERIFY;

eval $(safe env --bash)
```

Testing
-------

Run the full test suite with the race detector enabled:

```
make test
```

Run tests without the race detector (faster, useful during tight edit cycles):

```
make test-short
```

Run the race detector explicitly against all packages:

```
go test -race ./...
```

Generate a coverage report:

```
make coverage
```

The `coverage` target writes `coverage.out` and prints per-function coverage
percentages. Use `make coverage-html` to open an interactive HTML report in
your browser.

[vault]:  https://vaultproject.io
[spruce]: https://github.com/geofffranks/spruce
