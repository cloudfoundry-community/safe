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

The two arguments may be given in either order: what makes one of
them the URL is the scheme it carries.  An address typed without
its `http://` or `https://` is not a URL, and `safe` says so
rather than filing the target under it.

A target can be named by its alias or by the URL it is at,
anywhere a name is taken -- retargeting, `-T`, and
`safe target delete`.  What gets recorded as the current target is
always the alias.

You can see what Vaults you have targeted by running

```
safe targets
```

All commands will be run against the currently targeted Vault.

To forget a target, along with the token saved with it:

```
safe target delete myvault
```

Deleting the target you are currently on leaves nothing targeted,
so the next command will ask you to target a Vault rather than
report a target that is no longer there.

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

A token does not last forever.  To put off its expiry, without
authenticating again:

```
safe renew
```

That renews the token of the target you are on, or of the one
`-T` names.  It extends the life of the token already saved; it
does not obtain a new one, and a token that has already expired
cannot be renewed.

To renew the token of every target at once:

```
safe renew all
```

Targets are renewed in the order `safe targets` lists them.  A
target with no saved token is skipped, and one that could not be
renewed is reported and the rest are renewed anyway; the command
exits non-zero with a count of what failed.  `-T` names a single
target and is ignored here.

### Concurrent safes and ~/.saferc.lock

Targets live in `~/.saferc`.  Every command that changes them —
`safe target`, `safe auth`, `safe local`, and friends — rewrites
that file, and concurrent safes coordinate those rewrites through
a lock on a sidecar file, `~/.saferc.lock`.  The sidecar is a
zero-byte file that is created on first use and never removed;
there is nothing in it to clean up, and deleting it while safes
are running reopens the window it closes.  Locks are released by
the kernel when a process exits, so a killed safe cannot leave
the file stuck.

One caveat: on filesystems whose advisory locks do not span
clients — NFS before v4 is the common case — safes on *different
hosts* sharing one home directory are not serialized against each
other.  Writes are still atomic there, so `~/.saferc` cannot be
corrupted; a simultaneous change from another host can be lost.

Proxies
-------

`safe` reads the usual proxy environment variables — `HTTP_PROXY`,
`HTTPS_PROXY`, and `NO_PROXY`, in either case — and honours them when
talking to a Vault.  `SAFE_ALL_PROXY` overrides the first two, for when
both should go the same way.

A Vault that is only reachable from inside a network can be reached
through an SSH tunnel, by giving a proxy variable an `ssh+socks5://`
URL naming a host to log into and a private key to log in with:

```
export SAFE_ALL_PROXY=ssh+socks5://you@bastion.example.com/home/you/.ssh/id_ed25519
export SAFE_ALL_PROXY=ssh+socks5://you@bastion.example.com?private-key=/home/you/.ssh/id_ed25519
```

Both forms mean the same thing; use the second one when the path to the
key is relative.  Naming the key both ways at once is an error, as is
naming none.  The port defaults to 22, and the key must not be one that
needs a passphrase to read.  `safe` opens the tunnel, runs a SOCKS5
proxy on a local port for as long as the command lasts, and sends its
Vault traffic through it.

The host key of the machine being logged into is checked against a
`known_hosts` file, the way `ssh` checks it:

  - `SAFE_KNOWN_HOSTS_FILE` names the file to check against.  It
    defaults to `$HOME/.ssh/known_hosts`, and is created empty if it
    does not exist yet.

  - A host that is not in the file is offered for you to accept, and is
    written to the file if you answer `yes`.  Where there is nothing to
    answer with — a script, a CI job — the host is refused.

  - A host whose key has changed is always refused, and the entry that
    the new key conflicts with is named by line.

  - `SAFE_SKIP_HOST_KEY_VALIDATION` set to `true`, `yes`, `1`, or `on`
    turns the check off and accepts whatever key is offered.  This
    leaves the tunnel open to being intercepted, so `safe` warns on
    stderr whenever it is set.

Usage
-----

`safe` operates by way of sub-commands.  To generate a new
2048-bit SSH keypair, and store it in `secret/ssh`:

```
safe ssh 2048 secret/ssh
```

To find out what the sub-commands are, and what any one of them does:

```
safe commands
safe help ssh
```

Both print on standard output, so they can be piped and searched.
`safe envvars` does the same for the environment variables `safe`
reads, and `safe version` for the version you are running.  A word
`safe` has no command for is an error: it names the word rather than
printing the whole list, and exits non-zero, so a mistyped command in
a script stops the script.

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
costs a version lookup per secret, and `-q` skips the check and lists
those secrets too.  The lookup reads version metadata rather than the
secret, so listing a folder needs no access to the values in it.  Only
a version 2 mount keeps versions, so neither the check nor `-q` does
anything on a version 1 mount.

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
for `ls` above; with `--keys` the lookup is made anyway, since that is
how the keys are reached.

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
above; with `--keys` the lookup is made anyway, since that is how the
keys are reached.

```
safe paths secret/dc1
secret/dc1/concourse/pipeline-the-first/aws
secret/dc1/concourse/pipeline-the-first/dockerhub
secret/dc1/concourse/pipeline-the-first/github
secret/dc1/concourse/pipeline-the-second/aws
secret/dc1/concourse/pipeline-the-second/dockerhub
secret/dc1/concourse/pipeline-the-second/github
```

### values \[--keys\] \[-a\] \[-p path ...\] value \[value ...\]

Find the secrets whose latest live version contains one of the given
values, matched exactly and case-sensitively. Handy for auditing
credential reuse or locating every place a leaked value must be
rotated. Repeat `-p` to search several subtrees (default: `secret`);
with `--keys`, each match is printed as `path:key`. Values may also be
read from a file (`@file`), standard input (`@-`), or a hidden prompt
(no arguments). Subtrees the token cannot read are skipped with a
warning on standard error.

`-a` (`--all-versions`) searches the whole readable history rather than
the value in use, which is what finds a credential that has already
been rotated away. Each match is then reported as `path^version`, so a
hit on a superseded version reads back exactly as printed.

`-d` (`--deleted`) reaches deleted versions as well, by undeleting each
one, reading it, and deleting it again — the same cycle `safe export
-d` uses. It writes to the Vault to answer the question, and an
interrupted search can leave a version undeleted. Destroyed versions
are gone and are searched by neither flag.

```
safe values -p secret/prod hunter2
secret/prod/db
secret/prod/legacy/db

safe values --keys hunter2
secret/prod/db:password
secret/prod/legacy/db:old-password

safe values --all-versions --keys hunter2
secret/prod/db:password^3
secret/prod/legacy/db:old-password^1
secret/prod/legacy/db:old-password^2
```

### delete path \[path ...\]

Removes multiple paths from the Vault.

```
safe delete secret/unused
```

A path may name a single key, and on a version 2 backend it may name a
version as well.

```
safe delete secret/db:password
safe delete secret/db^3
```

Removing a key writes what is left of the secret as a new version. A
version already written is never rewritten, so naming a key together with
an older version only works when that version holds nothing but the key —
in which case the version itself is what goes. Anything else is refused,
and `safe copy` is the command that reads a key out of an old version.

`-D` (`--destroy`) and `-a` (`--all`) work on whole versions. With a key,
they apply only when the key is the whole secret; otherwise the key would
stay behind in the versions already written, and safe says so rather than
writing a new version and calling it done.

`-a` works on every version there is, so a path that names one version
asks for two different things at once, and safe refuses the pair:

```
safe delete -a secret/db^3     # refused; drop the -a or drop the ^3
```

`-r` (`--recurse`) removes a whole tree of secrets, and refuses in the
same way a path that names a key or a version, neither of which is a
tree. `-f` (`--force`) skips the confirmation `-r` asks for, and carries
on past a path that holds no secret.

Every path given is read against the flags before any of them is
removed, so a refusal on the last one leaves the rest where they were.

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

The length has to be at least one.  `safe gen 0 secret/account
password` is refused, rather than storing an empty value under a
name that reads like a credential.

`--policy` limits the characters a password is made of.  It goes
inside a regular expression character class, so it has to be one,
and it has to keep at least one printable character:

```
safe gen 16 --policy a-z0-9 secret/account password
```

Several secrets can be named at once, as `path:key` or as `path
key`, and the two forms can be mixed.  The whole list is read
before the first password is generated, so an argument that
cannot be used stops the command with nothing written.

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

### dhparam \[nbits\] path \[path ...\]

Generate a set of Diffie-Hellman key exchange parameters, adding
the key "dhparam-pem" to each path.

By default, 2048-bit parameters will be generated.  The `nbits`
parameter allows you to change that, to 1024 or 4096.

Each path gets its own parameter set.  Generating one takes a
while, so every path is read before the first set is generated.

### prompt ...

Echo the arguments, space-separated, as a single line to the
terminal.  This is a convenience helper for long pipelines of
chained commands.

### x509 issue \[OPTIONS\] --name cn.example.com path

Issues a new X.509 TLS/SSL certificate, and stores the new RSA
private key and the certificate in the Vault at _path_, in PEM
format.

`--signed-by` has to name a certificate authority, and cannot name
_path_ itself.  Issuing writes the signing CA back, to record the
serial number it handed out, and then writes the new certificate
over whatever _path_ held.

Where `path:certificate` holds the issuers above the certificate as
well as the certificate itself, they stay with it: every command
that writes a certificate back keeps the whole chain.

### x509 reissue \[OPTIONS\] path

Reissues the certificate at _path_ with a freshly generated key,
keeping its subject, its names, and the rest of its details unless
options ask for something else.

The signing authority comes from `--signed-by`, which has to name a
certificate authority.  Naming one moves the certificate to it, so
it does not have to be the authority that signed the certificate
originally.  Without the option, `safe` looks for a sibling secret
named `ca` and uses it only if it is the authority that signed the
certificate, since it is a guess rather than an instruction.  A
certificate that signed itself signs itself again, with the new key.

### x509 renew \[OPTIONS\] path

Renews the certificate at _path_, keeping its existing key, and
resets its validity period.  The signing authority is found the same
way as for `x509 reissue`.

### x509 revoke \[OPTIONS\] --signed-by path/to/ca path/to/cert

Revoke a certificate that was signed by a Certificate Authority.
The private key for the CA must be present in the Vault for this
to work.  Revoked certificates will be appended to the CA's
certificate revocation list (CRL), stored at `path/to/ca:crl`

A CRL names serial numbers, and a serial number only identifies a
certificate within the authority that issued it, so `safe` refuses
to revoke a certificate the named CA did not sign.

### x509 validate \[OPTIONS\] path

Run a variety of validation checks against a certificate in the
Vault.  In its simplest form, without arguments, this verifies
that the private key stored at `path:key` matches the certificate
stored at `path:certificate`.  Options control more powerful
validations, like checking for revocation, SAN validity, and
expiry.

`--signed-by` reads only the CA's certificate, so an authority whose
private key is held offline or by another team can still be validated
against.

### x509 show path \[path ...\]

Print what is known about the certificate at each _path_: who issued
it, what names it is valid for, what its key is, how long it was
issued for, and how much of that is left.  Only the certificate is
read, so a path holding no private key can still be shown.

Each path is reported in turn.  A path that holds no certificate, or
that cannot be read, is reported as such and the rest are still shown;
the command exits non-zero if any path could not be shown.

### x509 crl --renew path

Renews (re-signs) the certificate authority at `path`, without
affecting the list of revoked certificates.  Each CRL is numbered
above the one before it, as RFC 5280 requires, so a relying party
can tell which of two to keep.

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
\export VAULT_ADDR='http://localhost:8200';
\export VAULT_TOKEN='$SOME_UUID';
\unset VAULT_SKIP_VERIFY;
\unset VAULT_NAMESPACE;

eval "$(safe env --bash)"
```

The values are quoted for the shell they are written for, so a namespace or
an address holding a space, a quote, or a semicolon arrives whole. Quote the
command substitution as shown, or the shell will split the output on
whitespace before `eval` ever sees it.

`--fish` writes the same thing for fish, and `--json` writes it as JSON. Give
one of them: naming two is an error.

### local (--memory|--file dir) \[--engine vault|bao\]

Spin up a throwaway server for testing or experimentation, target it, and tear
it down again on Ctrl-C. Use `--memory` for an in-memory backend whose data is
gone on exit, or `--file <dir>` to keep the (encrypted) data between runs.

```
safe local --memory
safe local --file /tmp/my-vault
```

safe can drive either HashiCorp Vault or [OpenBao][openbao], which forked from
it and kept the same server, secrets, auth, and operator commands. With no
`--engine`, safe runs whichever of `vault` or `bao` it finds first on `$PATH`,
in that order — so installing OpenBao alongside an existing Vault does not
change which server this command starts.

```
safe local --memory --engine bao
safe local --memory --engine vault
```

Set `SAFE_ENGINE` to change the default without passing the flag every time.
`--engine` still wins over it, and an engine you pin that is not installed is
an error rather than a quiet fallback to the other one:

```
export SAFE_ENGINE=bao
```

`safe vault ...`, which hands its arguments to the engine's own CLI, resolves
the engine the same way.

One caveat on OpenBao: it removed the legacy `sys/generate-root` API. A
`--file` backend that safe initialized itself works on either engine, but
re-opening an existing one whose root token you no longer have needs that API,
and so needs `--engine vault`.

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

### The round-trip suite

`ci/scripts/tests` is an end-to-end suite that starts a real server, points a
built `safe` at it, and exercises the whole command surface — set, get, tree,
policy, approle, rekey, x509, and the rest — against both KV v1 and KV v2.

It runs against either engine. `VERSIONS` is a space-separated list, and the
engine binaries are downloaded into `./vaults/` on first use and cached, so
later runs against the same version need no network:

```
make test-integration ENGINE=vault VERSIONS=1.13.13
make test-integration ENGINE=bao   VERSIONS=2.6.1
make test-integration ENGINE=vault VERSIONS="1.11.10 1.12.6 1.13.13"
```

Only OpenBao 2.6.0 and later is supported: 2.6.0 renamed the release assets,
and the suite builds download URLs to the current scheme only.

Set `SAFE_DISABLE_GPG_TESTS=1` to skip the GPG rekey block on a machine with
no `gpg`:

```
SAFE_DISABLE_GPG_TESTS=1 make test-integration ENGINE=bao VERSIONS=2.6.1
```

The helpers that build those download URLs have their own unit tests, which
need neither a network nor an engine:

```
make test-engine-lib
```

In Concourse the same suite runs from `ci/scripts/test-release-against-engine`.
The `test-vault-1.9` … `test-vault-1.13` jobs each track the latest patch of a
Vault minor line, and `test-openbao-2.6` tracks the latest OpenBao 2.6.x patch.
A release only ships once every job in the matrix — Vault and OpenBao alike —
has passed.
Releases come from [releases.hashicorp.com/vault][vault-releases] and the
[OpenBao releases page][openbao-releases].

[vault]:            https://vaultproject.io
[openbao]:          https://openbao.org
[spruce]:           https://github.com/geofffranks/spruce
[vault-releases]:   https://releases.hashicorp.com/vault/
[openbao-releases]: https://github.com/openbao/openbao/releases
