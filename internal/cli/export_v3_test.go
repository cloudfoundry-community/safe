package cli

// safe export has two formats, and both carry every value as a string. A
// secret written by the vault CLI or by Terraform can hold objects, lists,
// numbers, booleans, and null, and an export of one used to turn them into
// strings, so importing it wrote back something else. Export now writes a
// version 3 file, which carries those values as the JSON they were, but only
// when some exported secret holds one. Everything else still gets exactly
// the version 1 or version 2 file it always did, which is what Genesis and
// older safe binaries read, and these pin that output byte for byte.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// exportOutput runs export with args and returns what it printed.
func exportOutput(t *testing.T, c *CLI, args ...string) string {
	t.Helper()
	return captureStdout(t, func() {
		if err := c.cmdExport("export", args...); err != nil {
			t.Fatalf("cmdExport(%v): %v", args, err)
		}
	})
}

// importInput feeds input to import and returns its error.
func importInput(t *testing.T, c *CLI, input string) error {
	t.Helper()
	withStdin(t, input)
	return c.cmdImport("import")
}

// assertRawJSON fails unless got holds exactly the JSON in want for each of
// its keys, and no other key, compared after compacting both sides.
func assertRawJSON(t *testing.T, what string, got map[string]json.RawMessage, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s has %d keys, want %d: %v", what, len(got), len(want), rawStrings(got))
	}
	for key, w := range want {
		raw, ok := got[key]
		if !ok {
			t.Errorf("%s has no %s", what, key)
			continue
		}
		var g, e bytes.Buffer
		if err := json.Compact(&g, raw); err != nil {
			t.Errorf("%s:%s is invalid JSON %q: %v", what, key, raw, err)
			continue
		}
		if err := json.Compact(&e, []byte(w)); err != nil {
			t.Fatalf("bad want %q for %s: %v", w, key, err)
		}
		if g.String() != e.String() {
			t.Errorf("%s:%s = %s, want %s", what, key, g.String(), e.String())
		}
	}
}

func rawStrings(m map[string]json.RawMessage) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}

// writesIn reports every request in log that would change the store.
func writesIn(log []string) []string {
	var out []string
	for _, line := range log {
		if strings.HasPrefix(line, "PUT ") || strings.HasPrefix(line, "POST ") || strings.HasPrefix(line, "DELETE ") {
			out = append(out, line)
		}
	}
	return out
}

// stringFixtureV1 seeds a KV v1 mount with string values only, one of them
// holding the characters encoding/json escapes.
func stringFixtureV1(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFake(t)
	fv.set("secret/x/a", map[string]string{"k": "v", "html": "<a&b>"})
	fv.set("secret/x/b/c", map[string]string{"x": "1", "true": "false"})
	return fv
}

// stringFixtureV2 seeds a KV v2 mount with string values only, across a
// history with a destroyed and a deleted version in it.
func stringFixtureV2(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x/a",
		map[string]string{"k": "1"},
		map[string]string{"k": "2"},
		map[string]string{"k": "3", "n": "<4>"})
	fv.destroyV2("secret/x/a", 1)
	fv.setV2("secret/x/b", map[string]string{"x": "y"})
	return fv
}

const (
	goldenV1 = `{"secret/x/a":{"html":"\u003ca\u0026b\u003e","k":"v"},"secret/x/b/c":{"true":"false","x":"1"}}` + "\n"

	goldenV2 = `[{"export_version":2,"data":{"secret/x/a":{"versions":[{"destroyed":true},{"value":{"k":"2"}},{"value":{"k":"3","n":"\u003c4\u003e"}}]},"secret/x/b":{"versions":[{"value":{"x":"y"}}]}},"requires_versioning":{"secret":true}}]` + "\n"

	goldenV2Deleted = `[{"export_version":2,"data":{"secret/x/a":{"versions":[{"destroyed":true},{"deleted":true,"value":{"k":"2"}},{"value":{"k":"3","n":"\u003c4\u003e"}}]},"secret/x/b":{"versions":[{"value":{"x":"y"}}]}},"requires_versioning":{"secret":true}}]` + "\n"
)

// Data of strings alone exports exactly as it always has.
func TestExportOfStringsIsTheV1FileItAlwaysWas(t *testing.T) {
	isolateHome(t)
	stringFixtureV1(t)
	c := newTestCLI(t)

	if got := exportOutput(t, c, "secret/x"); got != goldenV1 {
		t.Errorf("export =\n%s\nwant\n%s", got, goldenV1)
	}
}

func TestExportOfStringHistoryIsTheV2FileItAlwaysWas(t *testing.T) {
	for _, tc := range []struct {
		name    string
		deleted bool
		want    string
	}{
		{"all", false, goldenV2},
		{"all and deleted", true, goldenV2Deleted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			fv := stringFixtureV2(t)
			if tc.deleted {
				fv.deleteV2("secret/x/a", 2)
			}
			c := newTestCLI(t)
			c.opt.Export.All = true
			c.opt.Export.Deleted = tc.deleted

			if got := exportOutput(t, c, "secret/x"); got != tc.want {
				t.Errorf("export =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

// What comes back out of an import of a string-only file exports to the
// very same bytes, in both of the old formats.
func TestStringExportsRoundTripByteForByte(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		isolateHome(t)
		stringFixtureV1(t)
		c := newTestCLI(t)
		first := exportOutput(t, c, "secret/x")

		newCLIFake(t)
		if err := importInput(t, c, first); err != nil {
			t.Fatalf("cmdImport: %v", err)
		}
		if again := exportOutput(t, c, "secret/x"); again != first {
			t.Errorf("re-export =\n%s\nwant\n%s", again, first)
		}
	})
	t.Run("v2", func(t *testing.T) {
		isolateHome(t)
		fv := stringFixtureV2(t)
		fv.deleteV2("secret/x/a", 2)
		c := newTestCLI(t)
		c.opt.Export.All = true
		c.opt.Export.Deleted = true
		first := exportOutput(t, c, "secret/x")

		newCLIFakeV2(t)
		if err := importInput(t, c, first); err != nil {
			t.Fatalf("cmdImport: %v", err)
		}
		if again := exportOutput(t, c, "secret/x"); again != first {
			t.Errorf("re-export =\n%s\nwant\n%s", again, first)
		}
	})
}

// typedCLISecret holds one value of every JSON type, a number too large
// for a float64 to carry exactly among them.
const typedCLISecret = `{
	"config": {"b": [1, 2], "a": "x"},
	"count": 12345678901234567890,
	"ratio": 0.5,
	"enabled": false,
	"nothing": null,
	"list": ["p", {"q": 1}],
	"password": "old"
}`

var typedCLIWant = map[string]string{
	"config":   `{"b":[1,2],"a":"x"}`,
	"count":    `12345678901234567890`,
	"ratio":    `0.5`,
	"enabled":  `false`,
	"nothing":  `null`,
	"list":     `["p",{"q":1}]`,
	"password": `"old"`,
}

const goldenV3KV1 = `[{"export_version":3,"data":{"secret/x/plain":{"versions":[{"value":{"k":"v"}}]},"secret/x/typed":{"versions":[{"value":{"config":{"b":[1,2],"a":"x"},"count":12345678901234567890,"enabled":false,"list":["p",{"q":1}],"nothing":null,"password":"old","ratio":0.5}}]}},"requires_versioning":{}}]` + "\n"

// One typed value anywhere in the export makes it a version 3 file, which
// carries that value as its JSON and every string as a string.
func TestExportOfTypedValuesOnKVv1IsV3(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.setRaw(t, "secret/x/typed", typedCLISecret)
	fv.set("secret/x/plain", map[string]string{"k": "v"})
	c := newTestCLI(t)
	c.opt.Export.Typed = true

	got := exportOutput(t, c, "secret/x")
	if got != goldenV3KV1 {
		t.Fatalf("export =\n%s\nwant\n%s", got, goldenV3KV1)
	}

	restored := newCLIFake(t)
	if err := importInput(t, c, got); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}
	assertRawJSON(t, "secret/x/typed", restored.getRaw("secret/x/typed"), typedCLIWant)
	assertRawJSON(t, "secret/x/plain", restored.getRaw("secret/x/plain"), map[string]string{"k": `"v"`})

	//The restored Vault exports to the same file, so a second trip loses
	// nothing the first one kept.
	if again := exportOutput(t, c, "secret/x"); again != got {
		t.Errorf("re-export =\n%s\nwant\n%s", again, got)
	}
}

// typedHistory seeds a KV v2 secret whose versions hold typed values, with
// the middle one deleted.
func typedHistory(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2Raw(t, "secret/x/typed",
		`{"n": 1}`,
		`{"n": 2, "s": "x"}`,
		typedCLISecret)
	fv.deleteV2("secret/x/typed", 2)
	fv.setV2("secret/x/plain", map[string]string{"k": "v"})
	return fv
}

const goldenV3KV2 = `[{"export_version":3,"data":{"secret/x/plain":{"versions":[{"value":{"k":"v"}}]},"secret/x/typed":{"versions":[{"value":{"n":1}},{"deleted":true,"value":{"n":2,"s":"x"}},{"value":{"config":{"b":[1,2],"a":"x"},"count":12345678901234567890,"enabled":false,"list":["p",{"q":1}],"nothing":null,"password":"old","ratio":0.5}}]}},"requires_versioning":{"secret":true}}]` + "\n"

// A version 3 file keeps the history the way version 2 does, deleted
// versions included, and import writes each version back with its types.
func TestExportOfTypedHistoryOnKVv2IsV3AndImportsBack(t *testing.T) {
	isolateHome(t)
	typedHistory(t)
	c := newTestCLI(t)
	c.opt.Export.All = true
	c.opt.Export.Deleted = true
	c.opt.Export.Typed = true

	got := exportOutput(t, c, "secret/x")
	if got != goldenV3KV2 {
		t.Fatalf("export =\n%s\nwant\n%s", got, goldenV3KV2)
	}

	restored := newCLIFakeV2(t)
	if err := importInput(t, c, got); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}
	if states := strings.Join(restored.versionStates("secret/x/typed"), ","); states != "alive,deleted,alive" {
		t.Errorf("restored states = %s, want alive,deleted,alive", states)
	}
	assertRawJSON(t, "version 1", restored.versionRaw("secret/x/typed", 1), map[string]string{"n": `1`})
	assertRawJSON(t, "version 2", restored.versionRaw("secret/x/typed", 2), map[string]string{"n": `2`, "s": `"x"`})
	assertRawJSON(t, "version 3", restored.versionRaw("secret/x/typed", 3), typedCLIWant)

	if again := exportOutput(t, c, "secret/x"); again != got {
		t.Errorf("re-export =\n%s\nwant\n%s", again, got)
	}
}

// Without --typed an export is the file safe has always written, whatever
// the data holds. A typed value goes out as the JSON text safe get shows.
func TestExportOfTypedValuesWithoutTypedIsV1(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.setRaw(t, "secret/x/typed", `{"pid": 11485, "obj": {"a": 1}, "s": "str"}`)
	c := newTestCLI(t)

	want := `{"secret/x/typed":{"obj":"{\"a\":1}","pid":"11485","s":"str"}}` + "\n"
	if got := exportOutput(t, c, "secret/x"); got != want {
		t.Errorf("export =\n%s\nwant\n%s", got, want)
	}
}

func TestExportOfTypedHistoryWithoutTypedIsV2(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2Raw(t, "secret/x/typed", `{"n": 1}`, `{"pid": 11485, "s": "x"}`)
	c := newTestCLI(t)
	c.opt.Export.All = true

	want := `[{"export_version":2,"data":{"secret/x/typed":{"versions":[{"value":{"n":"1"}},{"value":{"pid":"11485","s":"x"}}]}},"requires_versioning":{"secret":true}}]` + "\n"
	if got := exportOutput(t, c, "secret/x"); got != want {
		t.Errorf("export =\n%s\nwant\n%s", got, want)
	}
}

// --typed writes version 3 even when every value is a string, so a caller
// always gets the one shape. The file holds one version per secret unless
// -a asks for the history.
func TestExportTypedOfStringsIsV3(t *testing.T) {
	isolateHome(t)
	stringFixtureV1(t)
	c := newTestCLI(t)
	c.opt.Export.Typed = true

	want := `[{"export_version":3,"data":{"secret/x/a":{"versions":[{"value":{"html":"\u003ca\u0026b\u003e","k":"v"}}]},"secret/x/b/c":{"versions":[{"value":{"true":"false","x":"1"}}]}},"requires_versioning":{}}]` + "\n"
	if got := exportOutput(t, c, "secret/x"); got != want {
		t.Errorf("export =\n%s\nwant\n%s", got, want)
	}
}

// With --typed, -a keeps the history and a latest-only export leaves the
// older typed versions out.
func TestExportTypedOverHistory(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2Raw(t, "secret/x/typed", `{"n": 1}`, `{"n": "2"}`)
	c := newTestCLI(t)
	c.opt.Export.Typed = true

	want := `[{"export_version":3,"data":{"secret/x/typed":{"first":2,"versions":[{"value":{"n":"2"}}]}},"requires_versioning":{}}]` + "\n"
	if got := exportOutput(t, c, "secret/x"); got != want {
		t.Errorf("export --typed =\n%s\nwant\n%s", got, want)
	}

	c.opt.Export.All = true
	want = `[{"export_version":3,"data":{"secret/x/typed":{"versions":[{"value":{"n":1}},{"value":{"n":"2"}}]}},"requires_versioning":{"secret":true}}]` + "\n"
	if got := exportOutput(t, c, "secret/x"); got != want {
		t.Errorf("export --typed -a =\n%s\nwant\n%s", got, want)
	}
}

// --shallow imports only the newest version of each secret, and keeps its
// types doing it.
func TestImportShallowOfV3KeepsTypes(t *testing.T) {
	isolateHome(t)
	typedHistory(t)
	c := newTestCLI(t)
	c.opt.Export.All = true
	c.opt.Export.Deleted = true
	c.opt.Export.Typed = true
	file := exportOutput(t, c, "secret/x")

	restored := newCLIFakeV2(t)
	c.opt.Import.Shallow = true
	if err := importInput(t, c, file); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}
	if states := strings.Join(restored.versionStates("secret/x/typed"), ","); states != "alive" {
		t.Fatalf("restored states = %s, want alive", states)
	}
	assertRawJSON(t, "version 1", restored.versionRaw("secret/x/typed", 1), typedCLIWant)
}

// A version 3 file onto a KV v1 mount: the single version of each secret
// lands with its types, and a history is refused the way version 2 refuses
// it.
func TestImportV3OntoKVv1(t *testing.T) {
	isolateHome(t)
	restored := newCLIFake(t)
	c := newTestCLI(t)

	single := `[{"export_version":3,"data":{"secret/t":{"versions":[{"value":{"n":7,"on":true}}]}},"requires_versioning":{}}]`
	if err := importInput(t, c, single); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}
	assertRawJSON(t, "secret/t", restored.getRaw("secret/t"), map[string]string{"n": `7`, "on": `true`})

	history := `[{"export_version":3,"data":{"secret/h":{"versions":[{"value":{"n":1}},{"value":{"n":2}}]}},"requires_versioning":{"secret":true}}]`
	err := importInput(t, c, history)
	if err == nil || !strings.Contains(err.Error(), "does not support versioning") {
		t.Errorf("cmdImport of a history onto KV v1 = %v, want the versioning refusal", err)
	}
}

// Files written by safe before version 3 existed still import.
func TestImportStillAcceptsV1AndV2Files(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		isolateHome(t)
		restored := newCLIFake(t)
		c := newTestCLI(t)
		if err := importInput(t, c, `{"secret/x/a":{"k":"v","n":"3"}}`); err != nil {
			t.Fatalf("cmdImport: %v", err)
		}
		assertRawJSON(t, "secret/x/a", restored.getRaw("secret/x/a"), map[string]string{"k": `"v"`, "n": `"3"`})
	})
	t.Run("v2", func(t *testing.T) {
		isolateHome(t)
		restored := newCLIFakeV2(t)
		c := newTestCLI(t)
		file := `[{"export_version":2,"data":{"secret/x/a":{"versions":[{"value":{"k":"1"}},{"deleted":true,"value":{"k":"2"}}]}},"requires_versioning":{"secret":true}}]`
		if err := importInput(t, c, file); err != nil {
			t.Fatalf("cmdImport: %v", err)
		}
		if states := strings.Join(restored.versionStates("secret/x/a"), ","); states != "alive,deleted" {
			t.Errorf("restored states = %s, want alive,deleted", states)
		}
		assertRawJSON(t, "version 1", restored.versionRaw("secret/x/a", 1), map[string]string{"k": `"1"`})
		assertRawJSON(t, "version 2", restored.versionRaw("secret/x/a", 2), map[string]string{"k": `"2"`})
	})
}

// A version 1 or version 2 file only ever holds strings, and a value of
// another type in one is refused rather than taken as a string, as before.
func TestImportOfOldFormatsStillRefusesTypedValues(t *testing.T) {
	for name, file := range map[string]string{
		"v1": `{"secret/x/a":{"n":3}}`,
		"v2": `[{"export_version":2,"data":{"secret/x/a":{"versions":[{"value":{"n":3}}]}},"requires_versioning":{}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			isolateHome(t)
			fv := newCLIFake(t)
			c := newTestCLI(t)
			if err := importInput(t, c, file); err == nil {
				t.Errorf("cmdImport = nil, want an error")
			}
			if w := writesIn(fv.requests()); len(w) != 0 {
				t.Errorf("a refused import wrote %v", w)
			}
		})
	}
}

// A file that claims a version this safe does not know, or a version 3
// file whose contents are not what version 3 holds, fails before anything
// is written.
func TestImportRefusesBadV3Files(t *testing.T) {
	good := `{"secret/ok":{"versions":[{"value":{"n":1}}]}}`
	for _, tc := range []struct {
		name, file, want string
	}{
		{"unknown version", `[{"export_version":4,"data":` + good + `,"requires_versioning":{}}]`, "Unknown export file format"},
		{"version as a string", `[{"export_version":"3","data":` + good + `}]`, "Unknown export file format"},
		{"fractional version", `[{"export_version":3.5,"data":` + good + `}]`, "Unknown export file format"},
		{"two documents", `[{"export_version":3,"data":` + good + `},{"export_version":3,"data":` + good + `}]`, "Unknown export file format"},
		{"truncated", `[{"export_version":3,"data":` + good, "Unknown export file format"},
		{"data not an object", `[{"export_version":3,"data":[1]}]`, "Could not interpret export file"},
		{"versions not a list", `[{"export_version":3,"data":{"secret/x":{"versions":{"value":{}}}}}]`, "Could not interpret export file"},
		{"value not an object", `[{"export_version":3,"data":` + good[:len(good)-1] + `,"secret/x":{"versions":[{"value":[1,2]}]}}}]`, "Could not interpret export file"},
		{"value a string", `[{"export_version":3,"data":{"secret/x":{"versions":[{"value":"k=v"}]}}}]`, "Could not interpret export file"},
		{"first not a number", `[{"export_version":3,"data":{"secret/x":{"first":"2","versions":[]}}}]`, "Could not interpret export file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			fv := newCLIFakeV2(t)
			c := newTestCLI(t)
			err := importInput(t, c, tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("cmdImport = %v, want an error containing %q", err, tc.want)
			}
			if w := writesIn(fv.requests()); len(w) != 0 {
				t.Errorf("a refused import wrote %v", w)
			}
		})
	}
}
