package cli

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strconv"

	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"

	uuid "github.com/pborman/uuid"
)

// renderNotice formats a per-target stderr notice through go-ansi exactly as
// a direct fmt.Fprintf(os.Stderr, format, args...) would have rendered it --
// colorized or plain depending on whether os.Stderr is a terminal. gen, ssh,
// and rsa now generate several targets concurrently and queue this kind of
// notice to print after their group finishes, so the color decision -- which
// fmt.Fprintf would otherwise make itself, right at write time -- has to be
// made here instead and baked into the string. ui.go's table renderer needs
// the same thing for the same reason and takes the same approach.
func renderNotice(format string, args ...any) string {
	s := fmt.Sprintf(format, args...)
	if !fmt.ShouldColorize(os.Stderr) {
		s = ansiColorRegexp.ReplaceAllString(s, "")
	}
	return s
}

// A genTarget is one secret, and the key inside it that a password is to be
// written to.
type genTarget struct {
	path string
	key  string
}

// errGenIncomplete says the argument list named a secret with no key after it,
// which is a matter for the usage rather than for a sentence of its own.
var errGenIncomplete = errors.New("incomplete list of secrets and keys")

// readGenTargets reads the whole argument list of safe gen into the secrets and
// keys it names. It makes no request, so every argument goes past it before the
// first password is generated: a refusal on the third pair used to arrive with
// the first two already written.
func readGenTargets(args []string) ([]genTarget, error) {
	var targets []genTarget

	for len(args) > 0 {
		if err := assertWritableKeyPath(args[0]); err != nil {
			return nil, err
		}
		var path, key string
		if vault.PathHasKey(args[0]) {
			path, key, _ = vault.ParsePath(args[0])
			//Read and Write parse their argument as path:key syntax, so the
			// literal path ParsePath returned goes back to the escaped form.
			path = vault.EncodePath(path, "", 0)
			args = args[1:]
		} else {
			if len(args) < 2 {
				return nil, errGenIncomplete
			}
			path, key = args[0], args[1]
			//If the key looks like a full path with a :key at the end, then the user
			// probably botched the args
			if vault.PathHasKey(key) {
				return nil, fmt.Errorf("For secret `%s` and key `%s`: key cannot contain a key", path, key)
			}
			//A caret in the key argument names a version the same way it does
			// in the PATH:KEY form, and that form refuses it; this one wrote a
			// literal key named e.g. "pw^2" instead, which safe's own
			// path:key^version syntax then cannot read back.
			if err := assertWritableKeyPath(key); err != nil {
				return nil, err
			}
			args = args[2:]
		}
		targets = append(targets, genTarget{path: path, key: key})
	}

	return targets, nil
}

func (c *CLI) cmdGen(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) == 0 {
		return r.Usage("gen")
	}

	length := 64

	if opt.Gen.Length != 0 {
		length = opt.Gen.Length
	} else if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
		length = int(u)
		args = args[1:]
	}

	targets, err := readGenTargets(args)
	if err != nil {
		if errors.Is(err, errGenIncomplete) {
			return r.Usage("gen")
		}
		return err
	}
	//A length with nothing after it names no password to generate. It used to
	// connect and return, which reads as a success and leaves nothing written.
	if len(targets) == 0 {
		return r.Usage("gen")
	}

	v := connect(true)

	// Grouping runs on target.path rather than the raw argument, which
	// readGenTargets only canonicalizes on the path:key branch; distinct
	// paths generate concurrently, multiple keys on the same path stay
	// sequential within their group, same as before parallelism was added.
	order, groups := groupByCanonicalPath(targets, func(t genTarget) string { return t.path })
	// Each group runs as one unit -- a single read serves every key on its
	// path, so runPathGroups sees one target per group: the whole key list.
	// N keys then cost N+1 requests instead of 2N, one write per key so the
	// version history still gains one version per generated key.
	wholeGroups := make(map[string][][]genTarget, len(groups))
	for p, ts := range groups {
		wholeGroups[p] = [][]genTarget{ts}
	}
	// The group context goes unused: reads and writes are contextless
	// vaultkv requests, and password generation is microseconds.
	return runPathGroups(order, wholeGroups, max(runtime.NumCPU(), 4), func(_ context.Context, group []genTarget, notice func(format string, args ...any)) error {
		// One read seeds the state every key in the group builds on;
		// --no-clobber checks run against this accumulated state, so a
		// skipped key's existing value rides along in the writes that
		// follow. A failure at key k leaves keys 1..k-1 persisted, the
		// same partial state the per-key read-modify-write left.
		s, err := v.Read(group[0].path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		for _, target := range group {
			path, key := target.path, target.key
			if opt.SkipIfExists && s.Has(key) {
				if !opt.Quiet {
					notice("@R{Cowardly refusing to update} @C{%s:%s} @R{as it is already present in Vault}\n", path, key)
				}
				continue
			}
			if err := s.Password(key, length, opt.Gen.Policy, opt.SkipIfExists); err != nil {
				return err
			}
			if err := v.Write(path, s); err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *CLI) cmdUuid(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) != 1 {
		return r.Usage("uuid")
	}

	if err := assertWritableKeyPath(args[0]); err != nil {
		return err
	}

	u := uuid.NewRandom()

	stringuuid := u.String()

	v := connect(true)

	var path, key string
	if vault.PathHasKey(args[0]) {
		path, key, _ = vault.ParsePath(args[0])
		//Read and Write parse their argument as path:key syntax, so the literal
		// path ParsePath returned goes back to the escaped form.
		path = vault.EncodePath(path, "", 0)

	} else {
		path, key = args[0], "uuid"
		//If the key looks like a full path with a :key at the end, then the user
		//probably botched the args
		if vault.PathHasKey(key) {
			return fmt.Errorf("For secret `%s` and key `%s`: key cannot contain a key", path, key)
		}

	}
	s, err := v.Read(path)
	if err != nil && !vault.IsNotFound(err) {
		return err
	}
	exists := (err == nil)
	if opt.SkipIfExists && exists && s.Has(key) {
		if !opt.Quiet {
			_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to update} @C{%s:%s} @R{as it is already present in Vault}\n", path, key)
		}
		return nil
	}
	err = s.Set(key, stringuuid, opt.SkipIfExists)
	if err != nil {
		return err
	}

	if err = v.Write(path, s); err != nil {
		return err
	}

	return nil
}

func (c *CLI) cmdSsh(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	bits := 2048
	if len(args) > 0 {
		if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
			bits = int(u)
			args = args[1:]
		}
	}

	if len(args) < 1 {
		return r.Usage("ssh")
	}

	for _, path := range args {
		if err := assertWritablePath(path); err != nil {
			return err
		}
	}

	v := connect(true)

	// args has no target struct of its own, unlike gen's targets, so
	// grouping runs directly over the raw arguments; the canonical path
	// from ParsePath is still what decides the group, so secret//x and
	// secret/x land together.
	// The group context goes unused: SSHKey's rsa.GenerateKey cannot be
	// interrupted mid-search, so a sibling failure only stops paths that
	// have not started yet.
	order, groups := groupByCanonicalPath(args, func(path string) string { return path })
	return runPathGroups(order, groups, max(runtime.NumCPU(), 4), func(_ context.Context, path string, notice func(format string, args ...any)) error {
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		exists := (err == nil)
		if opt.SkipIfExists && exists && (s.Has("private") || s.Has("public") || s.Has("fingerprint")) {
			if !opt.Quiet {
				notice("@R{Cowardly refusing to generate an SSH key at} @C{%s} @R{as it is already present in Vault}\n", path)
			}
			return nil
		}
		if err = s.SSHKey(bits, opt.SkipIfExists); err != nil {
			return err
		}
		return v.Write(path, s)
	})
}

func (c *CLI) cmdRsa(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	bits := 2048
	if len(args) > 0 {
		if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
			bits = int(u)
			args = args[1:]
		}
	}

	if len(args) < 1 {
		return r.Usage("rsa")
	}

	for _, path := range args {
		if err := assertWritablePath(path); err != nil {
			return err
		}
	}

	v := connect(true)

	// Same shape as cmdSsh: no target struct, so grouping runs over the raw
	// arguments, keyed by ParsePath's canonical secret path. The group
	// context goes unused for the same reason -- rsa.GenerateKey cannot be
	// interrupted mid-search.
	order, groups := groupByCanonicalPath(args, func(path string) string { return path })
	return runPathGroups(order, groups, max(runtime.NumCPU(), 4), func(_ context.Context, path string, notice func(format string, args ...any)) error {
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		exists := (err == nil)
		if opt.SkipIfExists && exists && (s.Has("private") || s.Has("public")) {
			if !opt.Quiet {
				notice("@R{Cowardly refusing to generate an RSA key at} @C{%s} @R{as it is already present in Vault}\n", path)
			}
			return nil
		}
		if err = s.RSAKey(bits, opt.SkipIfExists); err != nil {
			return err
		}
		return v.Write(path, s)
	})
}

func (c *CLI) cmdDhparam(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	bits := 2048

	if len(args) > 0 {
		if u, err := strconv.ParseUint(args[0], 10, 16); err == nil {
			bits = int(u)
			args = args[1:]
		}
	}

	if len(args) < 1 {
		return r.Usage("dhparam")
	}

	//Every path is read before any set of parameters is generated. Generating
	// one takes long enough that a refusal on the second path used to arrive
	// well after the first had been written.
	for _, path := range args {
		if err := assertWritablePath(path); err != nil {
			return err
		}
	}

	v := connect(true)
	return dhparamPaths(v, args, bits, opt.SkipIfExists, opt.Quiet)
}

// dhparamPaths is cmdDhparam's target loop, extracted so tests can drive it
// directly against a fake Vault without going through argument parsing.
// openssl's dhparam is CPU-bound, so paths run under a lower concurrency
// limit than gen/ssh/rsa's -- half the CPUs, floored at 2 -- to leave the
// machine usable rather than saturating every core with openssl children.
//
// Paths are grouped by their canonical secret path exactly as cmdGen,
// cmdSsh, and cmdRsa group theirs: distinct paths generate concurrently,
// but a path named more than once stays sequential within its group, one
// read-modify-write at a time, so a repeated argument never races itself.
func dhparamPaths(v *vault.Vault, paths []string, bits int, skipIfExists bool, quiet bool) error {
	order, groups := groupByCanonicalPath(paths, func(path string) string { return path })
	return runPathGroups(order, groups, max(runtime.NumCPU()/2, 2), func(ctx context.Context, path string, notice func(format string, args ...any)) error {
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		exists := (err == nil)
		if skipIfExists && exists && s.Has("dhparam-pem") {
			if !quiet {
				notice("@R{Cowardly refusing to generate a Diffie-Hellman key exchange parameter set at} @C{%s} @R{as it is already present in Vault}\n", path)
			}
			return nil
		}
		if err = s.DHParamContext(ctx, bits, skipIfExists); err != nil {
			return err
		}
		return v.Write(path, s)
	})
}
