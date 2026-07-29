package cli

import (
	"os"
	"strconv"

	fmt "github.com/jhunt/go-ansi"

	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"

	uuid "github.com/pborman/uuid"
)

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

	v := connect(true)

	for len(args) > 0 {
		var path, key string
		if vault.PathHasKey(args[0]) {
			path, key, _ = vault.ParsePath(args[0])
			//Read and Write parse their argument as path:key syntax, so the
			// literal path ParsePath returned goes back to the escaped form.
			path = vault.EncodePath(path, "", 0)
			args = args[1:]
		} else {
			if len(args) < 2 {
				return r.Usage("gen")
			}
			path, key = args[0], args[1]
			//If the key looks like a full path with a :key at the end, then the user
			// probably botched the args
			if vault.PathHasKey(key) {
				return fmt.Errorf("For secret `%s` and key `%s`: key cannot contain a key", path, key)
			}
			args = args[2:]
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
			continue
		}
		err = s.Password(key, length, opt.Gen.Policy, opt.SkipIfExists)
		if err != nil {
			return err
		}

		if err = v.Write(path, s); err != nil {
			return err
		}
	}
	return nil
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
	for _, path := range args {
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		exists := (err == nil)
		if opt.SkipIfExists && exists && (s.Has("private") || s.Has("public") || s.Has("fingerprint")) {
			if !opt.Quiet {
				_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to generate an SSH key at} @C{%s} @R{as it is already present in Vault}\n", path)
			}
			continue
		}
		if err = s.SSHKey(bits, opt.SkipIfExists); err != nil {
			return err
		}
		if err = v.Write(path, s); err != nil {
			return err
		}
	}
	return nil
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
	for _, path := range args {
		s, err := v.Read(path)
		if err != nil && !vault.IsNotFound(err) {
			return err
		}
		exists := (err == nil)
		if opt.SkipIfExists && exists && (s.Has("private") || s.Has("public")) {
			if !opt.Quiet {
				_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to generate an RSA key at} @C{%s} @R{as it is already present in Vault}\n", path)
			}
			continue
		}
		if err = s.RSAKey(bits, opt.SkipIfExists); err != nil {
			return err
		}
		if err = v.Write(path, s); err != nil {
			return err
		}
	}
	return nil
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

	path := args[0]
	if err := assertWritablePath(path); err != nil {
		return err
	}
	v := connect(true)
	s, err := v.Read(path)
	if err != nil && !vault.IsNotFound(err) {
		return err
	}
	exists := (err == nil)
	if opt.SkipIfExists && exists && s.Has("dhparam-pem") {
		if !opt.Quiet {
			_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to generate a Diffie-Hellman key exchange parameter set at} @C{%s} @R{as it is already present in Vault}\n", path)
		}
		return nil
	}
	if err = s.DHParam(bits, opt.SkipIfExists); err != nil {
		return err
	}
	return v.Write(path, s)
}
