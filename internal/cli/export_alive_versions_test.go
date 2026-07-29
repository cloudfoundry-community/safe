package cli

// `safe export -a` promises every version of every secret. It dropped whole
// secrets whose newest version happened to be deleted or destroyed, alive
// versions and all, so a backup taken with it silently lacked data the reader
// could still have read back.
//
// The encoder already knew what to do with a version it cannot read: a deleted
// version in the middle of a history is written out as a destroyed placeholder
// and the surrounding versions come through fine. Only the newest one caused
// the whole secret to be discarded.

import (
	"encoding/json"
	"strings"
	"testing"
)

// exportJSON runs export over secret/e and returns the decoded document. The
// v2 form is an array of one object; the v1 form is a bare map.
func exportJSON(t *testing.T, c *CLI, args ...string) map[string]any {
	t.Helper()
	var out string
	captured := captureStdout(t, func() {
		if err := c.cmdExport("export", args...); err != nil {
			t.Fatalf("cmdExport(%v): %v", args, err)
		}
	})
	out = strings.TrimSpace(captured)

	var asArray []map[string]any
	if err := json.Unmarshal([]byte(out), &asArray); err == nil {
		if len(asArray) != 1 {
			t.Fatalf("export produced %d documents, want 1: %s", len(asArray), out)
		}
		data, ok := asArray[0]["data"].(map[string]any)
		if !ok {
			t.Fatalf("export document has no data object: %s", out)
		}
		return data
	}

	var asMap map[string]any
	if err := json.Unmarshal([]byte(out), &asMap); err != nil {
		t.Fatalf("export output is not JSON: %s", out)
	}
	return asMap
}

// exportedVersions returns the versions array recorded for a path, or nil if
// the path is absent from the export.
func exportedVersions(t *testing.T, doc map[string]any, path string) []any {
	t.Helper()
	entry, ok := doc[path]
	if !ok {
		return nil
	}
	secret, ok := entry.(map[string]any)
	if !ok {
		t.Fatalf("export entry for %s is not an object: %#v", path, entry)
	}
	versions, ok := secret["versions"].([]any)
	if !ok {
		t.Fatalf("export entry for %s has no versions array: %#v", path, entry)
	}
	return versions
}

// halfDeleted serves a v2 mount holding secret/e/half, whose version 1 is
// alive and whose newer version 2 is deleted, alongside a wholly alive secret
// with two versions so the export takes its v2 form.
func halfDeleted(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2("secret/e/half",
		map[string]string{"b": "one"},
		map[string]string{"b": "two"})
	fv.deleteV2("secret/e/half", 2)
	fv.setV2("secret/e/whole",
		map[string]string{"a": "one"},
		map[string]string{"a": "two"})
	return fv
}

// The headline case: the alive version survives the export, and the deleted
// one becomes the same placeholder a deleted middle version already got.
func TestExportAllKeepsAnAliveVersionUnderADeletedLatest(t *testing.T) {
	isolateHome(t)
	halfDeleted(t)
	c := newTestCLI(t)
	c.opt.Export.All = true

	doc := exportJSON(t, c, "secret/e")
	versions := exportedVersions(t, doc, "secret/e/half")
	if versions == nil {
		t.Fatalf("secret/e/half is missing from the export: %#v", doc)
	}
	if len(versions) != 2 {
		t.Fatalf("secret/e/half has %d versions, want 2: %#v", len(versions), versions)
	}

	first, _ := versions[0].(map[string]any)
	value, _ := first["value"].(map[string]any)
	if value["b"] != "one" {
		t.Errorf("version 1 = %#v, want its value b=one", first)
	}
	second, _ := versions[1].(map[string]any)
	if second["destroyed"] != true {
		t.Errorf("version 2 = %#v, want it marked destroyed", second)
	}
}

// A destroyed newest version is the same situation: the older alive one is
// still readable and still belongs in a backup.
func TestExportAllKeepsAnAliveVersionUnderADestroyedLatest(t *testing.T) {
	isolateHome(t)
	fv := halfDeleted(t)
	fv.destroyV2("secret/e/half", 2)
	c := newTestCLI(t)
	c.opt.Export.All = true

	doc := exportJSON(t, c, "secret/e")
	if exportedVersions(t, doc, "secret/e/half") == nil {
		t.Errorf("secret/e/half is missing from the export: %#v", doc)
	}
}

// A secret with nothing alive anywhere has nothing to contribute, and is still
// left out rather than exported as a row of placeholders.
func TestExportAllStillOmitsASecretWithNothingAlive(t *testing.T) {
	isolateHome(t)
	fv := halfDeleted(t)
	fv.deleteV2("secret/e/half", 1)
	c := newTestCLI(t)
	c.opt.Export.All = true

	doc := exportJSON(t, c, "secret/e")
	if _, present := doc["secret/e/half"]; present {
		t.Errorf("secret/e/half has no alive version and should not be exported: %#v", doc)
	}
	if exportedVersions(t, doc, "secret/e/whole") == nil {
		t.Errorf("secret/e/whole should still be exported: %#v", doc)
	}
}

// Without --all the export takes only the newest version, and a secret whose
// newest version cannot be read still has nothing to offer it.
func TestPlainExportStillOmitsADeletedLatest(t *testing.T) {
	isolateHome(t)
	halfDeleted(t)
	c := newTestCLI(t)

	doc := exportJSON(t, c, "secret/e")
	if _, present := doc["secret/e/half"]; present {
		t.Errorf("a latest-version export should not include secret/e/half: %#v", doc)
	}
	if _, present := doc["secret/e/whole"]; !present {
		t.Errorf("secret/e/whole should still be exported: %#v", doc)
	}
}

// With --deleted the deleted version is undeleted, read and recorded as
// deleted rather than as a placeholder. That path is unchanged.
func TestExportAllWithDeletedStillRecordsTheDeletedVersion(t *testing.T) {
	isolateHome(t)
	halfDeleted(t)
	c := newTestCLI(t)
	c.opt.Export.All = true
	c.opt.Export.Deleted = true

	doc := exportJSON(t, c, "secret/e")
	versions := exportedVersions(t, doc, "secret/e/half")
	if len(versions) != 2 {
		t.Fatalf("secret/e/half has %d versions, want 2: %#v", len(versions), versions)
	}
	second, _ := versions[1].(map[string]any)
	if second["deleted"] != true {
		t.Errorf("version 2 = %#v, want it marked deleted", second)
	}
	value, _ := second["value"].(map[string]any)
	if value["b"] != "two" {
		t.Errorf("version 2 = %#v, want its value b=two", second)
	}
}

// The point of the export is what comes back out of it. Round-tripping through
// import must restore the alive version rather than nothing at all.
func TestExportAllRoundTripsAnAliveVersionUnderADeletedLatest(t *testing.T) {
	isolateHome(t)
	halfDeleted(t)
	c := newTestCLI(t)
	c.opt.Export.All = true

	backup := strings.TrimSpace(captureStdout(t, func() {
		if err := c.cmdExport("export", "secret/e"); err != nil {
			t.Fatalf("cmdExport: %v", err)
		}
	}))

	//Restore into an empty Vault, which is what a backup is for. connect
	//	reads the address afresh every call, so pointing the environment at a
	//	second fake is enough to get a clean store.
	restored := newCLIFakeV2(t)
	withStdin(t, backup)
	if err := c.cmdImport("import"); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}

	states := restored.versionStates("secret/e/half")
	if len(states) == 0 {
		t.Fatal("secret/e/half was not restored at all")
	}
	if states[0] != "alive" {
		t.Errorf("restored states = %v, want the first version alive", states)
	}

	value := captureStdout(t, func() {
		if err := c.cmdGet("get", "secret/e/half:b^1"); err != nil {
			t.Fatalf("reading the restored version: %v", err)
		}
	})
	if strings.TrimSpace(value) != "one" {
		t.Errorf("restored value = %q, want %q", strings.TrimSpace(value), "one")
	}
}
