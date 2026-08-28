package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudfoundry-community/vaultkv"
	fmt "github.com/jhunt/go-ansi"
	"gopkg.in/yaml.v2"

	"github.com/cloudfoundry-community/safe/internal/parallel"
	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// walkRoot resolves a tree-walk root argument to the literal Vault path the
// walk needs. safe prints paths in its own escaped syntax, so a root pasted
// back from `safe paths` or `safe tree` arrives escaped, while the walk and
// Secrets.Draw both work in literal paths. A key or a version cannot scope a
// recursive walk, so naming one is refused rather than quietly dropped.
func walkRoot(command, arg string) (string, error) {
	raw, key, version := vault.ParsePath(arg)
	if key != "" {
		return "", fmt.Errorf("%s does not take a specific key (%s)", command, arg)
	}
	if version != 0 {
		return "", fmt.Errorf("%s does not take a specific version (%s)", command, arg)
	}
	return raw, nil
}

func (c *CLI) writeHelper(prompt bool, insecure bool, command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) < 2 {
		return r.Usage(command)
	}
	path, args := args[0], args[1:]
	if err := assertWritablePath(path); err != nil {
		return err
	}
	v := connect(true)
	s, err := v.Read(path)
	if err != nil && !vault.IsNotFound(err) {
		return err
	}
	exists := (err == nil)
	clobberKeys := []string{}
	for _, arg := range args {
		k, v, missing, err := parseKeyVal(arg, opt.Quiet)
		if err != nil {
			return err
		}
		if opt.SkipIfExists && exists && s.Has(k) {
			clobberKeys = append(clobberKeys, k)
			// Once a clobber key is found, only collect further clobbers; s.Set is not called.
			continue
		}
		if len(clobberKeys) > 0 {
			continue
		}
		if missing {
			v, err = pr(k, prompt, insecure)
			if err != nil {
				return err
			}
		}
		err = s.Set(k, v, opt.SkipIfExists)
		if err != nil {
			return err
		}
	}
	if len(clobberKeys) > 0 {
		if !opt.Quiet {
			_, _ = fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to update} @C{%s}@R{, as the following keys would be clobbered:} @C{%s}\n",
				path, strings.Join(clobberKeys, ", "))
		}
		return nil
	}
	return v.Write(path, s)
}

func (c *CLI) cmdAsk(command string, args ...string) error {

	return c.writeHelper(false, false, "ask", args...)
}

func (c *CLI) cmdSet(command string, args ...string) error {

	return c.writeHelper(true, true, "set", args...)
}

func (c *CLI) cmdPaste(command string, args ...string) error {

	//Dispatch call.
	return c.writeHelper(false, true, "paste", args...)
}

func (c *CLI) cmdExists(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) != 1 {
		return r.Usage("exists")
	}
	v := connect(true)
	_, err := v.Read(args[0])
	if err != nil {
		if vault.IsNotFound(err) {
			rc.Cleanup()
			os.Exit(1)
		}
		return err
	}
	rc.Cleanup()
	os.Exit(0)
	return nil
}

func (c *CLI) cmdGet(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) < 1 {
		return r.Usage("get")
	}

	v := connect(true)

	// Recessive case of one path
	if len(args) == 1 && !opt.Get.Yaml {
		s, err := v.Read(args[0])
		if err != nil {
			return v.ExplainNotFound(args[0], err)
		}

		if opt.Get.KeysOnly {
			keys := s.Keys()
			for _, key := range keys {
				_, _ = fmt.Printf("%s\n", key)
			}
		} else if _, key, _ := vault.ParsePath(args[0]); key != "" {
			value, err := s.SingleValue()
			if err != nil {
				return err
			}
			_, _ = fmt.Printf("%s\n", value)
		} else {
			_, _ = fmt.Printf("--- # %s\n%s\n", args[0], s.YAML())
		}
		return nil
	}

	// Read every path concurrently, then aggregate sequentially so the
	// order-sensitive output below -- the errs slice and the KeysOnly
	// listing -- stays driven by args, not by fetch completion order.
	type fetched struct {
		s   *vault.Secret
		err error
	}
	fetches := make([]fetched, len(args))
	// fn always returns nil: per-path errors are aggregated by the
	// sequential loop below exactly as before, so EachLimit's fail-fast
	// never triggers here and the always-nil return is deliberate.
	_ = parallel.EachLimit(context.Background(), args, parallel.IOLimit(), func(_ context.Context, i int, path string) error {
		s, err := v.Read(path)
		fetches[i] = fetched{s: s, err: err}
		return nil
	})

	// Track errors, paths, keys, values
	errs := make([]error, 0)
	results := make(map[string]map[string]string, 0)
	missingKeys := make(map[string][]string)
	for i, path := range args {
		p, k, _ := vault.ParsePath(path)
		s, err := fetches[i].s, fetches[i].err

		// Check if the desired path[:key] is found
		if err != nil {
			errs = append(errs, v.ExplainNotFound(path, err))
			if k != "" {
				if _, ok := missingKeys[p]; !ok {
					missingKeys[p] = make([]string, 0)
				}
				missingKeys[p] = append(missingKeys[p], k)
			}
			continue
		}

		if _, ok := results[p]; !ok {
			results[p] = make(map[string]string, 0)
		}
		for _, key := range s.Keys() {
			results[p][key] = s.Get(key)
		}
	}

	// Handle any errors encountered.  Warn for key request, return error otherwise
	var err error
	numErrs := len(errs)
	if numErrs == 1 {
		err = errs[0]
	} else if len(errs) > 1 {
		errStr := "Multiple errors found:"
		for _, err := range errs {
			errStr += fmt.Sprintf("\n   - %s", err)
		}
		err = errors.New(errStr)
	}
	if numErrs > 0 {
		if opt.Get.KeysOnly {
			_, _ = fmt.Fprintf(os.Stderr, "@y{WARNING:} %s\n", err)
		} else {
			return err
		}
	}

	// Now that we've collected/collated all the data, format and print it
	_, _ = fmt.Printf("---\n")
	if opt.Get.KeysOnly {
		printedPaths := make(map[string]bool, 0)
		for _, path := range args {
			p, _, _ := vault.ParsePath(path)
			if printedPaths[p] {
				continue
			}
			printedPaths[p] = true
			result, ok := results[p]
			if !ok {
				yml, err := yaml.Marshal(map[string][]string{p: []string{}})
				if err != nil {
					return fmt.Errorf("failed to marshal output: %w", err)
				}
				_, _ = fmt.Printf("%s", string(yml))
			} else {
				foundKeys := reflect.ValueOf(result).MapKeys()
				strKeys := make([]string, len(foundKeys))
				for i := range foundKeys {
					strKeys[i] = foundKeys[i].String()
				}
				sort.Strings(strKeys)
				yml, err := yaml.Marshal(map[string][]string{p: strKeys})
				if err != nil {
					return fmt.Errorf("failed to marshal output: %w", err)
				}
				_, _ = fmt.Printf("%s\n", string(yml))
			}
		}
	} else {
		yml, err := yaml.Marshal(results)
		if err != nil {
			return fmt.Errorf("failed to marshal output: %w", err)
		}
		_, _ = fmt.Printf("%s\n", string(yml))
	}
	return nil
}

func (c *CLI) cmdVersions(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	v := connect(true)

	if len(args) == 0 {
		return fmt.Errorf("No paths given")
	}

	for i := range args {
		secret, key, version := vault.ParsePath(args[i])
		if version > 0 {
			return fmt.Errorf("Specifying version to versions is not supported")
		}
		if key != "" {
			return fmt.Errorf("Specifying key to versions is not supported")
		}
		//The client takes literal Vault paths, so it gets what ParsePath
		// returned rather than the escaped syntax the argument arrived in.
		versions, err := v.Client().Versions(secret)
		if vaultkv.IsNotFound(err) {
			err = vault.NewSecretNotFoundError(args[i])
		}
		if err != nil {
			return err
		}

		if len(args) > 1 {
			_, _ = fmt.Printf("@B{%s}:\n", args[i])
		}

		table := table{}

		table.setHeader("version", "status", "created at")

		for j := range versions {
			//Destroyed needs to be first because things can come back as both deleted _and_ destroyed.
			// destroyed is objectively more interesting.
			statusString := "@G{alive}"
			if versions[j].Destroyed {
				statusString = "@R{destroyed}"
			} else if versions[j].Deleted {
				statusString = "@Y{deleted}"
			}

			createdAtString := "unknown"

			if !versions[j].CreatedAt.IsZero() {
				createdAtString = versions[j].CreatedAt.Local().Format(time.RFC822)
			}

			table.addRow(
				fmt.Sprintf("%d", versions[j].Version),
				statusString,
				createdAtString,
			)
		}

		table.print()

		if len(args) > 1 && i != len(args)-1 {
			_, _ = fmt.Printf("\n")
		}
	}

	return nil
}

func (c *CLI) cmdLs(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	v := connect(true)
	display := func(paths []string) {
		end := "  "
		if opt.List.Single {
			end = "\n"
		}
		for _, s := range paths {
			//Printed in safe's own syntax, so a name holding a colon or a
			// caret can be pasted back. The trailing slash marks a folder
			// and is not part of the name.
			name, folder := strings.CutSuffix(s, "/")
			name = vault.EscapePathSegment(name)
			if folder {
				_, _ = fmt.Printf("@B{%s/}%s", name, end)
			} else {
				_, _ = fmt.Printf("@G{%s}%s", name, end)
			}
		}
		if !opt.List.Single {
			_, _ = fmt.Printf("\n")
		}
	}

	if len(args) == 0 {
		args = []string{"/"}
	}

	for _, arg := range args {
		//Vault lists literal paths, so a root pasted back from safe's own
		// output has to be unescaped first.
		root, err := walkRoot("ls", arg)
		if err != nil {
			return err
		}

		var paths []string
		if root == "" {
			var err error
			paths, err = v.KVMounts()
			if err != nil {
				return err
			}
		} else {
			paths, err = v.List(root)
			if err != nil {
				return err
			}
		}

		filteredPaths := []string{}
		if !opt.List.Quick {
			for i := range paths {
				if !strings.HasSuffix(paths[i], "/") {
					child := root + "/" + paths[i]
					mountVersion, err := v.MountVersion(child)
					if err != nil {
						return err
					}

					if mountVersion == 2 {
						//Version metadata answers whether the newest version
						// can be read, which is all the listing needs to
						// decide. Reading the secret answered the same
						// question by fetching the value itself, so listing a
						// folder pulled back every secret in it and logged a
						// read of each one, for output that is names only.
						//
						//Versions takes a literal path rather than safe's own
						// syntax, so a colon in a name needs no escaping round
						// trip to survive the lookup.
						versions, err := v.Versions(child)
						if err != nil {
							if vault.IsNotFound(err) {
								continue
							}
							if !vaultkv.IsForbidden(err) {
								return err
							}
							//A policy can grant list and read-the-data
							// without also granting read-the-metadata, and
							// such a token could list this folder before the
							// liveness check moved to the metadata endpoint.
							// Fall back to the read the check used to make,
							// rather than aborting the whole listing on a
							// capability it does not strictly need.
							if _, err := v.Read(vault.EncodePath(child, "", 0)); err != nil {
								if vault.IsNotFound(err) {
									continue
								}
								return err
							}
						} else if len(versions) == 0 || !versions[len(versions)-1].Alive() {
							continue
						}
					}
				}
				filteredPaths = append(filteredPaths, paths[i])
			}
		} else {
			filteredPaths = paths
		}

		sort.Strings(filteredPaths)

		if len(args) != 1 {
			_, _ = fmt.Printf("@C{%s}:\n", arg)
		}
		display(filteredPaths)
		if len(args) != 1 {
			_, _ = fmt.Printf("\n")
		}
	}
	return nil
}

func (c *CLI) cmdTree(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if opt.Tree.HideLeaves && opt.Tree.ShowKeys {
		return fmt.Errorf("Cannot specify both -d and --keys at the same time")
	}
	if len(args) == 0 {
		args = append(args, "secret")
	}
	r1, _ := regexp.Compile("^ ")
	r2, _ := regexp.Compile("^└")
	v := connect(true)
	for i, path := range args {
		root, err := walkRoot("tree", path)
		if err != nil {
			return err
		}
		secrets, err := v.ConstructSecrets(root, vault.TreeOpts{
			FetchKeys: opt.Tree.ShowKeys,
			//Version metadata is what the liveness check reads, and the tree
			// renders none of it, so a quick walk has no reason to fetch it.
			// ConstructSecrets turns this back on whenever it still has to
			// decide what to drop, which is every walk without -q.
			SkipVersionInfo:     !opt.Tree.ShowKeys,
			AllowDeletedSecrets: opt.Tree.Quick,
		})

		if err != nil {
			return err
		}
		lines := strings.Split(secrets.Draw(root, fmt.CanColorize(os.Stdout), !opt.Tree.HideLeaves), "\n")
		if i > 0 {
			lines = lines[1:] // Drop root '.' from subsequent paths
		}
		if i < len(args)-1 {
			lines = lines[:len(lines)-1]
		}
		for _, line := range lines {
			if i < len(args)-1 {
				line = r1.ReplaceAllString(r2.ReplaceAllString(line, "├"), "│")
			}
			_, _ = fmt.Printf("%s\n", line)
		}
	}
	return nil
}

func (c *CLI) cmdPaths(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) < 1 {
		args = append(args, "secret")
	}
	v := connect(true)
	for _, path := range args {
		root, err := walkRoot("paths", path)
		if err != nil {
			return err
		}
		secrets, err := v.ConstructSecrets(root, vault.TreeOpts{
			FetchKeys:           opt.Paths.ShowKeys,
			AllowDeletedSecrets: opt.Paths.Quick,
			SkipVersionInfo:     !opt.Paths.ShowKeys,
		})
		if err != nil {
			return err
		}

		_, _ = fmt.Printf("%s\n", strings.Join(secrets.Paths(), "\n"))
	}
	return nil
}

func (c *CLI) cmdValues(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	//Expansion and prompting happen before connect() so input errors surface
	// without network traffic. @- consumes stdin during expansion; the prompt
	// only fires when no positionals were given, so the two never contend.
	values := make([]string, 0, len(args))
	for _, arg := range args {
		value, err := expandValueArg(arg)
		if err != nil {
			return err
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		value, err := pr("value", false, true)
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("no values specified to search for")
		}
		values = append(values, value)
	}

	paths := opt.Values.Paths
	if len(paths) == 0 {
		paths = []string{"secret"}
	}
	for i := range paths {
		root, err := walkRoot("values", paths[i])
		if err != nil {
			return err
		}
		paths[i] = root
	}
	paths = dedupeExportPaths(paths)

	v := connect(true)
	results, skipped, err := v.FindValueMatches(paths, values, vault.ValueSearchOpts{
		ShowKeys:    opt.Values.ShowKeys,
		AllVersions: opt.Values.AllVersions,
		Deleted:     opt.Values.Deleted,
	})
	//Partial results still print when some paths failed; err below makes
	// main report the failure and exit non-zero.
	for _, result := range results {
		_, _ = fmt.Printf("%s\n", result)
	}
	if skipped > 0 {
		_, _ = fmt.Fprintf(os.Stderr,
			"@Y{warning: skipped %d subtree(s) due to insufficient permissions; results may be incomplete}\n",
			skipped)
	}
	return err
}

// checkDeletePath reads one argument to safe delete against the options it
// arrived with, and says so when the two ask for different things. It makes no
// request, so the whole argument list can go past it first.
func checkDeletePath(path, verb string, opt *Options) error {
	secretPath, key, version := vault.ParsePath(path)

	//-r takes a tree of secrets; a key or a version names one thing inside one
	// secret. Asking for both was read as a mistake and answered by dropping
	// the -r, so `safe rm -r secret/app:password' deleted the one key and
	// `safe rm -r secret/app^2' the one version, each reporting the success of
	// something nobody asked for.
	if opt.Delete.Recurse {
		switch {
		case key != "":
			return fmt.Errorf("cannot %s `%s' recursively: -r takes a tree of secrets, and the path names the key %s", verb, secretPath, key)
		case version != 0:
			return fmt.Errorf("cannot %s `%s' recursively: -r takes a tree of secrets, and the path names version %d", verb, secretPath, version)
		}
	}

	return vault.CheckDeletePath(path, vault.DeleteOpts{
		Destroy: opt.Delete.Destroy,
		All:     opt.Delete.All,
	})
}

// allNotFound reports whether every failure err carries is a not-found, the
// only kind --force may swallow. DeleteTree and MoveCopyTree are fan-outs,
// so err may be a *parallel.Errors holding several siblings; whichever
// failure won the arrival race says nothing about the others, so each one
// must answer to IsNotFound before the whole error is suppressible. A bare
// error -- a single failure, or one raised before any fan-out -- is judged
// directly, as before.
func allNotFound(err error) bool {
	var errs *parallel.Errors
	if errors.As(err, &errs) {
		return errs.All(vault.IsNotFound)
	}
	return vault.IsNotFound(err)
}

func (c *CLI) cmdDelete(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) < 1 {
		return r.Usage("delete")
	}
	verb := "delete"
	if opt.Delete.Destroy {
		verb = "destroy"
	}

	//Every path is read before any of them is deleted, and before anything is
	// connected to. A refusal on the third argument used to arrive with the
	// first two already gone, and a destroy cannot be taken back to try the
	// command again.
	for _, path := range args {
		if err := checkDeletePath(path, verb, opt); err != nil {
			return err
		}
	}

	v := connect(true)

	for _, path := range args {
		if opt.Delete.Recurse {
			if !opt.Delete.Force && !recursively(verb, path) {
				continue /* skip this command, process the next */
			}
			if err := v.DeleteTree(path, vault.DeleteOpts{
				Destroy: opt.Delete.Destroy,
				All:     opt.Delete.All,
			}); err != nil && (!allNotFound(err) || !opt.Delete.Force) {
				return err
			}
		} else {
			if err := v.Delete(path, vault.DeleteOpts{
				Destroy: opt.Delete.Destroy,
				All:     opt.Delete.All,
			}); err != nil && (!allNotFound(err) || !opt.Delete.Force) {
				return err
			}
		}
	}
	return nil
}

func (c *CLI) cmdUndelete(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) < 1 {
		return r.Usage("undelete")
	}
	v := connect(true)

	for _, path := range args {
		if opt.Undelete.All {
			secret, key, version := vault.ParsePath(path)
			if key != "" {
				return fmt.Errorf("Cannot undelete specific key (%s)", path)
			}

			if version > 0 {
				return fmt.Errorf("--all given but path (%s) has version specified", path)
			}

			respVersions, err := v.Versions(secret)
			if err != nil {
				return err
			}

			versions := make([]uint, 0, len(respVersions))
			for _, v := range respVersions {
				versions = append(versions, v.Version)
			}

			//The version list was looked up under the parsed path; the
			// client takes literal paths, so the undelete uses it too.
			if err = v.UndeleteVersions(secret, versions); err != nil {
				return err
			}
		} else {
			if err := v.Undelete(path); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *CLI) cmdRevert(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) != 2 {
		return r.Usage("revert")
	}
	v := connect(true)

	secret, key, version := vault.ParsePath(args[0])
	if key != "" {
		return fmt.Errorf("Cannot call revert with path containing key")
	}

	if version > 0 {
		return fmt.Errorf("Cannot call revert with path containing version")
	}

	targetVersion, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("VERSION must be a positive integer")
	}

	if targetVersion == 0 {
		return nil
	}

	//Check what the most recent version is to avoid setting the latest version if unnecessary.
	// This should also catch if the secret is non-existent, or if we're targeting a destroyed,
	// deleted, or non-existent version.
	//Versions does not unescape its argument, so it takes the literal path
	// ParsePath already produced rather than what the user typed.
	allVersions, err := v.Versions(secret)
	if err != nil {
		return err
	}
	if len(allVersions) == 0 {
		return errors.New(vault.SecretNotFoundMessage(secret))
	}

	//Said the way a read says it, but left plain: revert reports these by
	// reading version metadata, not by failing a read, so nothing downstream
	// should mistake one for a missing path.
	destroyedErr := errors.New(vault.VersionNotFoundMessage(secret, targetVersion, "destroyed"))
	if targetVersion < uint64(allVersions[0].Version) {
		return destroyedErr
	}

	if targetVersion > uint64(allVersions[len(allVersions)-1].Version) {
		return errors.New(vault.VersionNotFoundMessage(secret, targetVersion, ""))
	}

	versionObject := allVersions[targetVersion-uint64(allVersions[0].Version)]
	if versionObject.Destroyed {
		return destroyedErr
	}

	if versionObject.Deleted {
		if !opt.Revert.Deleted {
			return fmt.Errorf("%s; pass --deleted to undelete it, revert to it, and delete it again",
				vault.VersionNotFoundMessage(secret, targetVersion, "deleted"))
		}

		err = v.Undelete(vault.EncodePath(secret, "", targetVersion))
		if err != nil {
			return err
		}
	}

	//If the version to revert to is the current version, do nothing...
	// unless its deleted, then either just undelete it or err, depending on
	// if the -d flag is set
	if targetVersion == uint64(allVersions[len(allVersions)-1].Version) {
		return nil
	}

	toWrite, err := v.Read(vault.EncodePath(secret, "", targetVersion))
	if err != nil {
		return err
	}

	//Write parses its argument as path:key syntax, so the literal path goes
	// back to the escaped form before the revert is written.
	err = v.Write(vault.EncodePath(secret, "", 0), toWrite)
	if err != nil {
		return err
	}

	//If we got this far and this is set, we must have undeleted a thing.
	// Clean up after ourselves
	if versionObject.Deleted {
		err = v.Delete(vault.EncodePath(secret, "", targetVersion), vault.DeleteOpts{})
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CLI) cmdExport(command string, args ...string) error {
	opt := c.opt

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) < 1 {
		args = append(args, "secret")
	}
	v := connect(true)

	var toExport any

	//Standardize and validate paths
	for i := range args {
		raw, key, version := vault.ParsePath(args[i])
		if key != "" {
			return fmt.Errorf("Cannot export path with key (%s)", args[i])
		}

		if version > 0 {
			return fmt.Errorf("Cannot export path with version (%s)", args[i])
		}
		//ParsePath already canonicalized, and the walk wants the literal
		// path rather than the escaped syntax the argument arrived in.
		args[i] = raw
	}

	//Deduplicate the input paths
	args = dedupeExportPaths(args)

	secrets := vault.Secrets{}
	for _, path := range args {
		theseSecrets, err := v.ConstructSecrets(path, vault.TreeOpts{
			FetchKeys:           true,
			FetchAllVersions:    opt.Export.All,
			GetDeletedVersions:  opt.Export.Deleted,
			AllowDeletedSecrets: opt.Export.Deleted,
		})
		if err != nil {
			return err
		}

		secrets = secrets.Merge(theseSecrets)
	}

	var mustV2Export bool
	//Determine if we can get away with a v1 export
	for _, s := range secrets {
		if len(s.Versions) > 1 {
			mustV2Export = true
			break
		}
	}

	v1Export := func() error {
		export := make(map[string]*vault.Secret)
		for _, s := range secrets {
			export[s.Path] = s.Versions[0].Data
		}

		toExport = export
		return nil
	}

	v2Export := func() error {
		export := exportFormat{ExportVersion: 2, Data: map[string]exportSecret{}, RequiresVersioning: map[string]bool{}}

		for _, secret := range secrets {
			if len(secret.Versions) > 1 {
				mount, _ := v.Client().MountPath(secret.Path)
				export.RequiresVersioning[mount] = true
			}

			thisSecret := exportSecret{FirstVersion: secret.Versions[0].Number}
			//We want to omit the `first` key in the json if it's 1
			if thisSecret.FirstVersion == 1 || opt.Export.Shallow {
				thisSecret.FirstVersion = 0
			}

			for _, version := range secret.Versions {
				thisVersion := exportVersion{
					Deleted:   version.State == vault.SecretStateDeleted && opt.Export.Deleted,
					Destroyed: version.State == vault.SecretStateDestroyed || (version.State == vault.SecretStateDeleted && !opt.Export.Deleted),
					Value:     map[string]string{},
				}

				for _, key := range version.Data.Keys() {
					thisVersion.Value[key] = version.Data.Get(key)
				}

				thisSecret.Versions = append(thisSecret.Versions, thisVersion)
			}

			export.Data[secret.Path] = thisSecret

			//Wrap export in array so that older versions of safe don't try to import this improperly.
			toExport = []exportFormat{export}
		}

		return nil
	}

	var err error
	if mustV2Export {
		err = v2Export()
	} else {
		err = v1Export()
	}

	if err != nil {
		return err
	}
	b, err := json.Marshal(&toExport)
	if err != nil {
		return err
	}
	_, _ = fmt.Printf("%s\n", string(b))

	return nil
}

// importPair is one secret from a version-2 export, paired with the path it
// is destined for.
type importPair struct {
	path   string
	secret exportSecret
}

// importPairs flattens a version-2 export's secrets into pairs sorted by
// path. data.Data is a map, whose iteration order Go deliberately
// randomizes; sorting here means cmdImport's processing order is a function
// of the input alone, never of map internals (Declared Behavior Change 4).
func importPairs(data map[string]exportSecret) []importPair {
	pairs := make([]importPair, 0, len(data))
	for path, secret := range data {
		pairs = append(pairs, importPair{path: path, secret: secret})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].path < pairs[j].path })
	return pairs
}

func (c *CLI) cmdImport(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}

	if opt.SkipIfExists {
		_, _ = fmt.Fprintf(os.Stderr, "@R{!!} @C{--no-clobber} @R{is incompatible with} @C{safe import}\n")
		return r.Usage("import")
	}

	v := connect(true)

	type importFunc func([]byte) error

	v1Import := func(input []byte) error {
		var data map[string]*vault.Secret
		err := json.Unmarshal(input, &data)
		if err != nil {
			return err
		}
		// Sorting first means processing order is a function of the input
		// alone, never of Go's randomized map iteration, exactly as the
		// version-2 loop's importPairs arranges. Distinct paths then write
		// concurrently; each `wrote` line is buffered by its path's slot
		// and replayed after the fan-out, so stderr comes out in sorted
		// order rather than completion order -- which also means nothing
		// prints until the whole import finishes, where a sequential loop
		// would have streamed a line per write as it happened. And a
		// failure only halts dispatch of paths not yet started: writes
		// already in flight when one fails still complete, so a failed
		// import can leave sorted paths past the failure point written,
		// the same fail-fast semantics the version-2 loop below already
		// has.
		paths := make([]string, 0, len(data))
		for path := range data {
			paths = append(paths, path)
		}
		sort.Strings(paths)
		wrote := make([]bool, len(paths))
		err = parallel.EachLimit(context.Background(), paths, parallel.IOLimit(), func(_ context.Context, i int, path string) error {
			//The keys of an export are literal Vault paths; Write reads its
			// argument as path:key syntax.
			if err := v.Write(vault.EncodePath(path, "", 0), data[path]); err != nil {
				return err
			}
			wrote[i] = true
			return nil
		})
		for i, path := range paths {
			if wrote[i] {
				_, _ = fmt.Fprintf(os.Stderr, "wrote %s\n", path)
			}
		}
		return err
	}

	v2Import := func(input []byte) error {
		var unmarshalTarget []exportFormat
		err := json.Unmarshal(input, &unmarshalTarget)
		if err != nil {
			return fmt.Errorf("Could not interpret export file: %w", err)
		}

		if len(unmarshalTarget) != 1 {
			return fmt.Errorf("Improperly formatted export file")
		}

		data := unmarshalTarget[0]

		if !opt.Import.Shallow {
			//Verify that the mounts that require versioning actually support it. We
			//can't really detect if v1 mounts exist at this stage unless we assume
			//the token given has mount listing privileges. Not a big deal, because
			//it will become very apparent once we start trying to put secrets in it
			for mount, needsVersioning := range data.RequiresVersioning {
				if needsVersioning {
					mountVersion, err := v.MountVersion(mount)
					if err != nil {
						return fmt.Errorf("Could not determine existing mount version: %w", err)
					}

					if mountVersion != 2 {
						return fmt.Errorf("Export for mount `%s' has secrets with multiple versions, but the mount either\n"+
							"does not exist or does not support versioning", mount)
					}
				}
			}
		}

		//Put the secrets in the places, writing the versions in the correct order and deleting/destroying secrets that
		// need to be deleted/destroyed. Distinct paths import concurrently at
		// the IO width: imports are round trips, not compute.
		pairs := importPairs(data.Data)

		return parallel.EachLimit(context.Background(), pairs, parallel.IOLimit(), func(_ context.Context, _ int, pair importPair) error {
			path, secret := pair.path, pair.secret
			s := vault.SecretEntry{
				Path: path,
			}

			firstVersion := secret.FirstVersion
			if firstVersion == 0 {
				firstVersion = 1
			}

			if opt.Import.Shallow {
				secret.Versions = secret.Versions[len(secret.Versions)-1:]
			}
			for i := range secret.Versions {
				state := vault.SecretStateAlive
				if secret.Versions[i].Destroyed {
					if opt.Import.IgnoreDestroyed {
						continue
					}
					state = vault.SecretStateDestroyed
				} else if secret.Versions[i].Deleted {
					if opt.Import.IgnoreDeleted {
						continue
					}
					state = vault.SecretStateDeleted
				}
				versionData := vault.NewSecret()
				for k, v := range secret.Versions[i].Value {
					_ = versionData.Set(k, v, false)
				}
				// Safe conversion: i is bounded by len(secret.Versions)
				// Check if adding i to firstVersion would overflow
				if i < 0 || uint(i) > ^uint(0)-firstVersion {
					return fmt.Errorf("version number overflow detected for secret %s", path)
				}
				s.Versions = append(s.Versions, vault.SecretVersion{
					Number: firstVersion + uint(i),
					State:  state,
					Data:   versionData,
				})
			}

			return s.Copy(v, s.Path, vault.TreeCopyOpts{
				Clear: true,
				Pad:   !opt.Import.IgnoreDestroyed && !opt.Import.Shallow,
			})
		})
	}

	var fn importFunc
	//determine which version of the export format this is
	var typeTest any
	jsonParseErr := json.Unmarshal(b, &typeTest)
	switch v := typeTest.(type) {
	case map[string]any:
		fn = v1Import
	case []any:
		if len(v) == 1 {
			if meta, isMap := (v[0]).(map[string]any); isMap {
				version, isFloat64 := meta["export_version"].(float64)
				if isFloat64 && version == 2 {
					fn = v2Import
				}
			}
		}
	}

	if fn == nil {
		if jsonParseErr != nil {
			return fmt.Errorf("Unknown export file format (JSON parse error: %w)", jsonParseErr)
		}
		return fmt.Errorf("Unknown export file format - aborting")
	}

	return fn(b)
}

// moveCopyParams captures the per-command differences between move and copy.
// op is the underlying vault operation (v.Move or v.Copy) used for the
// non-recursive, single-secret path; move tells the recursive path whether
// to move or copy; verb names the command for messages and the recurse
// prompt; guardRecurseVersion enables the check that forbids recursively
// moving or copying a versioned source.
type moveCopyParams struct {
	verb                string
	recurse             bool
	force               bool
	deep                bool
	guardRecurseVersion bool
	move                bool
	op                  func(string, string, vault.MoveCopyOpts) error
}

// moveCopy holds the shared move/copy logic: guard checks, optional recursion
// confirmation, and force-aware error suppression. Behavior matches the two
// original handlers exactly.
func (c *CLI) moveCopy(v *vault.Vault, args []string, p moveCopyParams) error {
	if vault.PathHasKey(args[0]) || vault.PathHasKey(args[1]) {
		if p.deep {
			return fmt.Errorf("Cannot deep copy a specific key")
		}

		if !vault.PathHasKey(args[0]) && vault.PathHasKey(args[1]) {
			return fmt.Errorf("Cannot move from entire secret into specific key")
		}
	}

	if vault.PathHasVersion(args[1]) {
		return fmt.Errorf("Cannot %s to a specific destination version", p.verb)
	}

	if p.guardRecurseVersion && p.recurse && vault.PathHasVersion(args[0]) {
		return fmt.Errorf("Cannot recursively %s a path with specific version", p.verb)
	}

	opts := vault.MoveCopyOpts{
		SkipIfExists:    c.opt.SkipIfExists,
		Quiet:           c.opt.Quiet,
		Deep:            p.deep,
		DeletedVersions: p.deep,
	}

	//Don't try to recurse if operating on a key
	// args[0] is the source path. args[1] is the destination path.
	if p.recurse && !vault.PathHasKey(args[0]) && !vault.PathHasKey(args[1]) {
		if !p.force && !recursively(p.verb, args...) {
			return nil /* skip this command, process the next */
		}
		err := v.MoveCopyTree(args[0], args[1], p.move, opts)
		if err != nil && (!allNotFound(err) || !p.force) {
			return err
		}
	} else {
		err := p.op(args[0], args[1], opts)
		if err != nil && (!allNotFound(err) || !p.force) {
			return err
		}
	}
	return nil
}

func (c *CLI) cmdMove(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) != 2 {
		return r.Usage("move")
	}

	v := connect(true)
	return c.moveCopy(v, args, moveCopyParams{
		verb:                "move",
		recurse:             opt.Move.Recurse,
		force:               opt.Move.Force,
		deep:                opt.Move.Deep,
		guardRecurseVersion: true,
		move:                true,
		op:                  v.Move,
	})
}

func (c *CLI) cmdCopy(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) != 2 {
		return r.Usage("copy")
	}
	v := connect(true)

	return c.moveCopy(v, args, moveCopyParams{
		verb:                "copy",
		recurse:             opt.Copy.Recurse,
		force:               opt.Copy.Force,
		deep:                opt.Copy.Deep,
		guardRecurseVersion: true,
		move:                false,
		op:                  v.Copy,
	})
}

func (c *CLI) cmdOption(command string, args ...string) error {
	opt := c.opt

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}

	// One table names the known options; it is built against whichever
	// Options struct is being read or written at the time -- cfg's for the
	// listing below, the freshly read config's for the persisted update.
	optionFields := func(o *rc.Options) []struct {
		opt string
		val *bool
	} {
		return []struct {
			opt string
			val *bool
		}{
			{"manage_vault_token", &o.ManageVaultToken},
		}
	}
	optLookup := optionFields(&cfg.Options)

	if len(args) == 0 {
		table := table{}
		for _, entry := range optLookup {
			value := "@R{false}"
			if *entry.val {
				value = "@G{true}"
			}
			table.addRow(entry.opt, value)
		}

		table.print()
		return nil
	}

	changes := map[string]bool{}
	updated := make([]string, 0, len(args))
	for _, arg := range args {
		argSplit := strings.Split(arg, "=")
		if len(argSplit) != 2 {
			return fmt.Errorf("Option arg syntax: option=value")
		}

		parseTrueFalse := func(s string) (bool, error) {
			switch s {
			case "true", "on", "yes":
				return true, nil
			case "false", "off", "no":
				return false, nil
			}

			return false, fmt.Errorf("value must be one of true|on|yes|false|off|no")
		}

		optionKey := strings.ReplaceAll(argSplit[0], "-", "_")
		optionVal, err := parseTrueFalse(argSplit[1])
		if err != nil {
			return err
		}

		found := false
		for _, opt := range optLookup {
			if opt.opt == optionKey {
				found = true
				changes[opt.opt] = optionVal
				updated = append(updated, opt.opt)
				break
			}
		}

		if !found {
			return fmt.Errorf("unknown option: %s", argSplit[0])
		}
	}

	if err := rc.Update(func(c *rc.Config) error {
		for _, field := range optionFields(&c.Options) {
			if val, ok := changes[field.opt]; ok {
				*field.val = val
			}
		}
		return nil
	}); err != nil {
		return err
	}

	for _, opt := range updated {
		_, _ = fmt.Printf("updated @G{%s}\n", opt)
	}
	return nil
}
