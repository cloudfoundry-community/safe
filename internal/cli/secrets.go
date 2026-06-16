package cli

import (
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

	"github.com/cloudfoundry-community/safe/pkg/rc"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func (c *CLI) writeHelper(prompt bool, insecure bool, command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) < 2 {
		r.ExitWithUsage(command)
	}
	v := connect(true)
	path, args := args[0], args[1:]
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
			continue
		}
		// realize that we're going to fail, and don't prompt the user for any info
		if len(clobberKeys) > 0 {
			continue
		}
		if missing {
			v = pr(k, prompt, insecure)
		}
		if err != nil {
			return err
		}
		err = s.Set(k, v, opt.SkipIfExists)
		if err != nil {
			return err
		}
	}
	if len(clobberKeys) > 0 {
		if !opt.Quiet {
			fmt.Fprintf(os.Stderr, "@R{Cowardly refusing to update} @C{%s}@R{, as the following keys would be clobbered:} @C{%s}\n",
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
		r.ExitWithUsage("exists")
	}
	v := connect(true)
	_, err := v.Read(args[0])
	if err != nil {
		if vault.IsNotFound(err) {
			os.Exit(1)
		}
		return err
	}
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
		r.ExitWithUsage("get")
	}

	v := connect(true)

	// Recessive case of one path
	if len(args) == 1 && !opt.Get.Yaml {
		s, err := v.Read(args[0])
		if err != nil {
			return err
		}

		if opt.Get.KeysOnly {
			keys := s.Keys()
			for _, key := range keys {
				fmt.Printf("%s\n", key)
			}
		} else if _, key, _ := vault.ParsePath(args[0]); key != "" {
			value, err := s.SingleValue()
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", value)
		} else {
			fmt.Printf("--- # %s\n%s\n", args[0], s.YAML())
		}
		return nil
	}

	// Track errors, paths, keys, values
	errs := make([]error, 0)
	results := make(map[string]map[string]string, 0)
	missingKeys := make(map[string][]string)
	for _, path := range args {
		p, k, _ := vault.ParsePath(path)
		s, err := v.Read(path)

		// Check if the desired path[:key] is found
		if err != nil {
			errs = append(errs, err)
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
			fmt.Fprintf(os.Stderr, "@y{WARNING:} %s\n", err)
		} else {
			return err
		}
	}

	// Now that we've collected/collated all the data, format and print it
	fmt.Printf("---\n")
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
				yml, _ := yaml.Marshal(map[string][]string{p: []string{}})
				fmt.Printf("%s", string(yml))
			} else {
				foundKeys := reflect.ValueOf(result).MapKeys()
				strKeys := make([]string, len(foundKeys))
				for i := 0; i < len(foundKeys); i++ {
					strKeys[i] = foundKeys[i].String()
				}
				sort.Strings(strKeys)
				yml, _ := yaml.Marshal(map[string][]string{p: strKeys})
				fmt.Printf("%s\n", string(yml))
			}
		}
	} else {
		yml, _ := yaml.Marshal(results)
		fmt.Printf("%s\n", string(yml))
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
		_, _, version := vault.ParsePath(args[i])
		if version > 0 {
			return fmt.Errorf("Specifying version to versions is not supported")
		}
		versions, err := v.Client().Versions(args[i])
		if vaultkv.IsNotFound(err) {
			err = vault.NewSecretNotFoundError(args[i])
		}
		if err != nil {
			return err
		}

		if len(args) > 1 {
			fmt.Printf("@B{%s}:\n", args[i])
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
				fmt.Sprintf(statusString),
				createdAtString,
			)
		}

		table.print()

		if len(args) > 1 && i != len(args)-1 {
			fmt.Printf("\n")
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
		if opt.List.Single {
			for _, s := range paths {
				if strings.HasSuffix(s, "/") {
					fmt.Printf("@B{%s}\n", s)
				} else {
					fmt.Printf("@G{%s}\n", s)
				}
			}
		} else {
			for _, s := range paths {
				if strings.HasSuffix(s, "/") {
					fmt.Printf("@B{%s}  ", s)
				} else {
					fmt.Printf("@G{%s}  ", s)
				}
			}
			fmt.Printf("\n")
		}
	}

	if len(args) == 0 {
		args = []string{"/"}
	}

	for _, path := range args {
		var paths []string
		if path == "" || path == "/" {
			generics, err := v.Mounts("generic")
			if err != nil {
				return err
			}
			kvs, err := v.Mounts("kv")
			if err != nil {
				return err
			}

			paths = append(generics, kvs...)
		} else {
			var err error
			paths, err = v.List(path)
			if err != nil {
				return err
			}
		}

		filteredPaths := []string{}
		if !opt.List.Quick {
			for i := range paths {
				if !strings.HasSuffix(paths[i], "/") {
					fullpath := path + "/" + vault.EscapePathSegment(paths[i])
					mountVersion, err := v.MountVersion(fullpath)
					if err != nil {
						return err
					}

					if mountVersion == 2 {
						_, err := v.Read(fullpath)
						if err != nil {
							if vault.IsNotFound(err) {
								continue
							}

							return err
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
			fmt.Printf("@C{%s}:\n", path)
		}
		display(filteredPaths)
		if len(args) != 1 {
			fmt.Printf("\n")
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
		secrets, err := v.ConstructSecrets(path, vault.TreeOpts{
			FetchKeys:           opt.Tree.ShowKeys,
			AllowDeletedSecrets: opt.Tree.Quick,
		})

		if err != nil {
			return err
		}
		lines := strings.Split(secrets.Draw(path, fmt.CanColorize(os.Stdout), !opt.Tree.HideLeaves), "\n")
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
			fmt.Printf("%s\n", line)
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
		secrets, err := v.ConstructSecrets(path, vault.TreeOpts{
			FetchKeys:           opt.Paths.ShowKeys,
			AllowDeletedSecrets: opt.Paths.Quick,
			SkipVersionInfo:     !opt.Paths.ShowKeys,
		})
		if err != nil {
			return err
		}

		fmt.Printf(strings.Join(secrets.Paths(), "\n"))
		fmt.Printf("\n")
	}
	return nil
}

func (c *CLI) cmdDelete(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) < 1 {
		r.ExitWithUsage("delete")
	}
	v := connect(true)

	verb := "delete"
	if opt.Delete.Destroy {
		verb = "destroy"
	}

	for _, path := range args {
		_, key, version := vault.ParsePath(path)

		//Ignore -r if path has a version or key because that seems like a mistake
		if opt.Delete.Recurse && (key == "" || version > 0) {
			if !opt.Delete.Force && !recursively(verb, path) {
				continue /* skip this command, process the next */
			}
			if err := v.DeleteTree(path, vault.DeleteOpts{
				Destroy: opt.Delete.Destroy,
				All:     opt.Delete.All,
			}); err != nil && !(vault.IsNotFound(err) && opt.Delete.Force) {
				return err
			}
		} else {
			if err := v.Delete(path, vault.DeleteOpts{
				Destroy: opt.Delete.Destroy,
				All:     opt.Delete.All,
			}); err != nil && !(vault.IsNotFound(err) && opt.Delete.Force) {
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
		r.ExitWithUsage("undelete")
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

			if err = v.Client().Undelete(path, versions); err != nil {
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
		r.ExitWithUsage("revert")
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
	allVersions, err := v.Versions(args[0])
	if err != nil {
		return err
	}

	destroyedErr := fmt.Errorf("Version %d of secret `%s' is destroyed", targetVersion, secret)
	if targetVersion < uint64(allVersions[0].Version) {
		return destroyedErr
	}

	if targetVersion > uint64(allVersions[len(allVersions)-1].Version) {
		return fmt.Errorf("Version %d of secret `%s' does not exist", targetVersion, secret)
	}

	versionObject := allVersions[targetVersion-uint64(allVersions[0].Version)]
	if versionObject.Destroyed {
		return destroyedErr
	}

	if versionObject.Deleted {
		if !opt.Revert.Deleted {
			return fmt.Errorf("Version %d of secret `%s' is deleted. To force a read, specify --deleted", targetVersion, secret)
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

	err = v.Write(secret, toWrite)
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

	var toExport interface{}

	//Standardize and validate paths
	for i := range args {
		args[i] = vault.Canonicalize(args[i])
		_, key, version := vault.ParsePath(args[i])
		if key != "" {
			return fmt.Errorf("Cannot export path with key (%s)", args[i])
		}

		if version > 0 {
			return fmt.Errorf("Cannot export path with version (%s)", args[i])
		}
	}

	//Deduplicate the input paths
	sort.Slice(args, func(i, j int) bool { return vault.PathLessThan(args[i], args[j]) })
	for i := 0; i < len(args)-1; i++ {
		//No need to get a deeper part of a tree if you're already walking the `((great)*grand)?parent`
		if strings.HasPrefix(strings.Trim(args[i+1], "/"), strings.Trim(args[i], "/")) {
			before := args[:i+1]
			var after []string
			if len(args)-1 != i+1 {
				after = args[i+2:]
			}
			args = append(before, after...)
			i--
		}
	}

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
	fmt.Printf("%s\n", string(b))

	return nil
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
	if err != nil {
		return err
	}

	if opt.SkipIfExists {
		fmt.Fprintf(os.Stderr, "@R{!!} @C{--no-clobber} @R{is incompatible with} @C{safe import}\n")
		r.ExitWithUsage("import")
	}

	v := connect(true)

	type importFunc func([]byte) error

	v1Import := func(input []byte) error {
		var data map[string]*vault.Secret
		err := json.Unmarshal(input, &data)
		if err != nil {
			return err
		}
		for path, s := range data {
			err = v.Write(path, s)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %s\n", path)
		}
		return nil
	}

	v2Import := func(input []byte) error {
		var unmarshalTarget []exportFormat
		err := json.Unmarshal(input, &unmarshalTarget)
		if err != nil {
			return fmt.Errorf("Could not interpret export file: %s", err)
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
						return fmt.Errorf("Could not determine existing mount version: %s", err)
					}

					if mountVersion != 2 {
						return fmt.Errorf("Export for mount `%s' has secrets with multiple versions, but the mount either\n"+
							"does not exist or does not support versioning", mount)
					}
				}
			}
		}

		//Put the secrets in the places, writing the versions in the correct order and deleting/destroying secrets that
		// need to be deleted/destroyed.
		for path, secret := range data.Data {
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
				data := vault.NewSecret()
				for k, v := range secret.Versions[i].Value {
					_ = data.Set(k, v, false)
				}
				// Safe conversion: i is bounded by len(secret.Versions)
				// Check if adding i to firstVersion would overflow
				if i < 0 || uint(i) > ^uint(0)-firstVersion {
					fmt.Fprintf(os.Stderr, "@R{Version number overflow detected for secret}\n")
					return fmt.Errorf("version number overflow detected")
				}
				s.Versions = append(s.Versions, vault.SecretVersion{
					Number: firstVersion + uint(i),
					State:  state,
					Data:   data,
				})
			}

			err := s.Copy(v, s.Path, vault.TreeCopyOpts{
				Clear: true,
				Pad:   !(opt.Import.IgnoreDestroyed || opt.Import.Shallow),
			})
			if err != nil {
				return err
			}
		}

		return nil
	}

	var fn importFunc
	//determine which version of the export format this is
	var typeTest interface{}
	_ = json.Unmarshal(b, &typeTest)
	switch v := typeTest.(type) {
	case map[string]interface{}:
		fn = v1Import
	case []interface{}:
		if len(v) == 1 {
			if meta, isMap := (v[0]).(map[string]interface{}); isMap {
				version, isFloat64 := meta["export_version"].(float64)
				if isFloat64 && version == 2 {
					fn = v2Import
				}
			}
		}
	}

	if fn == nil {
		return fmt.Errorf("Unknown export file format - aborting")
	}

	return fn(b)
}

func (c *CLI) cmdMove(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}
	if len(args) != 2 {
		r.ExitWithUsage("move")
	}

	v := connect(true)
	if vault.PathHasKey(args[0]) || vault.PathHasKey(args[1]) {
		if opt.Move.Deep {
			return fmt.Errorf("Cannot deep copy a specific key")
		}

		if !vault.PathHasKey(args[0]) && vault.PathHasKey(args[1]) {
			return fmt.Errorf("Cannot move from entire secret into specific key")
		}
	}

	if vault.PathHasVersion(args[1]) {
		return fmt.Errorf("Cannot move to a specific destination version")
	}

	//Don't try to recurse if operating on a key
	// args[0] is the source path. args[1] is the destination path.
	if opt.Move.Recurse && !(vault.PathHasKey(args[0]) || vault.PathHasKey(args[1])) {
		if !opt.Move.Force && !recursively("move", args...) {
			return nil /* skip this command, process the next */
		}
		err := v.MoveCopyTree(args[0], args[1], v.Move, vault.MoveCopyOpts{
			SkipIfExists: opt.SkipIfExists, Quiet: opt.Quiet, Deep: opt.Move.Deep, DeletedVersions: opt.Move.Deep,
		})
		if err != nil && !(vault.IsNotFound(err) && opt.Move.Force) {
			return err
		}
	} else {
		err := v.Move(args[0], args[1], vault.MoveCopyOpts{
			SkipIfExists: opt.SkipIfExists, Quiet: opt.Quiet, Deep: opt.Move.Deep, DeletedVersions: opt.Move.Deep,
		})
		if err != nil && !(vault.IsNotFound(err) && opt.Move.Force) {
			return err
		}
	}
	return nil
}

func (c *CLI) cmdCopy(command string, args ...string) error {
	opt := c.opt
	r := c.r

	if _, err := rc.Apply(opt.UseTarget); err != nil {
		return err
	}

	if len(args) != 2 {
		r.ExitWithUsage("copy")
	}
	v := connect(true)

	if vault.PathHasKey(args[0]) || vault.PathHasKey(args[1]) {
		if opt.Copy.Deep {
			return fmt.Errorf("Cannot deep copy a specific key")
		}

		if !vault.PathHasKey(args[0]) && vault.PathHasKey(args[1]) {
			return fmt.Errorf("Cannot move from entire secret into specific key")
		}
	}

	if vault.PathHasVersion(args[1]) {
		return fmt.Errorf("Cannot copy to a specific destination version")
	}

	if opt.Copy.Recurse && vault.PathHasVersion(args[0]) {
		return fmt.Errorf("Cannot recursively copy a path with specific version")
	}

	//Don't try to recurse if operating on a key
	// args[0] is the source path. args[1] is the destination path.
	if opt.Copy.Recurse && !(vault.PathHasKey(args[0]) || vault.PathHasKey(args[1])) {
		if !opt.Copy.Force && !recursively("copy", args...) {
			return nil /* skip this command, process the next */
		}
		err := v.MoveCopyTree(args[0], args[1], v.Copy, vault.MoveCopyOpts{
			SkipIfExists:    opt.SkipIfExists,
			Quiet:           opt.Quiet,
			Deep:            opt.Copy.Deep,
			DeletedVersions: opt.Copy.Deep,
		})
		if err != nil && !(vault.IsNotFound(err) && opt.Copy.Force) {
			return err
		}
	} else {
		err := v.Copy(args[0], args[1], vault.MoveCopyOpts{
			SkipIfExists:    opt.SkipIfExists,
			Quiet:           opt.Quiet,
			Deep:            opt.Copy.Deep,
			DeletedVersions: opt.Copy.Deep,
		})
		if err != nil && !(vault.IsNotFound(err) && opt.Copy.Force) {
			return err
		}
	}
	return nil
}

func (c *CLI) cmdOption(command string, args ...string) error {
	opt := c.opt

	cfg, err := rc.Apply(opt.UseTarget)
	if err != nil {
		return err
	}

	optLookup := []struct {
		opt string
		val *bool
	}{
		{"manage_vault_token", &cfg.Options.ManageVaultToken},
	}

	if len(args) == 0 {
		table := table{}
		for _, entry := range optLookup {
			value := "@R{false}"
			if *entry.val {
				value = "@G{true}"
			}
			table.addRow(entry.opt, fmt.Sprintf(value))
		}

		table.print()
		return nil
	}

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
				*opt.val = optionVal
				fmt.Printf("updated @G{%s}\n", opt.opt)
				break
			}
		}

		if !found {
			return fmt.Errorf("unknown option: %s", argSplit[0])
		}
	}

	return cfg.Write()
}
