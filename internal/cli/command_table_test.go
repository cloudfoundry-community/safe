package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// newTestRunner builds the same fully-registered Runner that Main uses,
// against a fresh Options, so tests exercise the shipped command table.
// cmdHelp and cmdVersion call os.Exit, so tests must go through r.Help or
// inspect the Runner directly, never Execute those handlers.
func newTestRunner() *Runner {
	var opt Options
	return newRegisteredRunner(&opt)
}

// TestCommandTableComplete pins the shape of the registered command table:
// every dispatched command has a handler, a help topic, a non-empty Summary
// and Usage, and one of the Types the help renderer understands.
func TestCommandTableComplete(t *testing.T) {
	r := newTestRunner()

	if len(r.Handlers) == 0 {
		t.Fatal("no commands registered")
	}
	if len(r.Handlers) != len(r.Topics) {
		t.Errorf("handlers (%d) and topics (%d) out of step: every Dispatch passes a Help",
			len(r.Handlers), len(r.Topics))
	}

	// AdministrativeCommand and MiscellaneousCommand share a value, so the
	// set is built rather than written as one literal.
	validTypes := map[string]bool{}
	for _, ty := range []string{
		DestructiveCommand,
		NonDestructiveCommand,
		AdministrativeCommand,
		MiscellaneousCommand,
		HiddenCommand,
	} {
		validTypes[ty] = true
	}

	for cmd, fn := range r.Handlers {
		if fn == nil {
			t.Errorf("command %q registered with a nil handler", cmd)
		}
		h, ok := r.Topics[cmd]
		if !ok || h == nil {
			t.Errorf("command %q has no help topic", cmd)
			continue
		}
		if h.Summary == "" {
			t.Errorf("command %q has an empty Summary", cmd)
		}
		if h.Usage == "" {
			t.Errorf("command %q has an empty Usage", cmd)
		}
		if !validTypes[h.Type] {
			t.Errorf("command %q has unrecognized Type %q", cmd, h.Type)
		}
	}
}

// TestCommandTableKnownCommands checks that the commands safe has always
// shipped are all present, including the x509 sub-commands.
func TestCommandTableKnownCommands(t *testing.T) {
	r := newTestRunner()

	for _, cmd := range []string{
		"version", "help", "commands", "envvars",
		"targets", "target", "target delete", "status", "local", "init",
		"unseal", "seal", "env", "auth", "logout", "renew",
		"ask", "set", "paste", "exists", "get", "versions",
		"ls", "tree", "paths", "values",
		"delete", "undelete", "revert", "export", "import", "move", "copy",
		"gen", "uuid", "option", "ssh", "rsa", "dhparam", "prompt",
		"vault", "rekey", "fmt", "curl",
		"x509", "x509 validate", "x509 issue", "x509 reissue",
		"x509 renew", "x509 revoke", "x509 show", "x509 crl",
	} {
		if _, ok := r.Handlers[cmd]; !ok {
			t.Errorf("command %q is not registered", cmd)
		}
	}
}

// TestHelpRendersEveryTopic renders every registered topic through r.Help
// and checks nothing errors and nothing comes out empty.
func TestHelpRendersEveryTopic(t *testing.T) {
	r := newTestRunner()

	for topic := range r.Topics {
		var buf bytes.Buffer
		if err := r.Help(&buf, topic); err != nil {
			t.Errorf("Help(%q) returned error: %s", topic, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("Help(%q) rendered nothing", topic)
		}
	}

	var buf bytes.Buffer
	if err := r.Help(&buf, "commands"); err != nil {
		t.Fatalf("Help(commands) returned error: %s", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Valid commands are:") {
		t.Errorf("commands listing missing its header:\n%s", out)
	}
	for _, cmd := range []string{"target", "curl", "x509"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("commands listing missing %q:\n%s", cmd, out)
		}
	}

	if err := r.Help(&buf, "no such topic"); !errors.Is(err, ErrNoSuchTopic) {
		t.Errorf("Help on an unregistered topic returned %v, want ErrNoSuchTopic", err)
	}
}

// TestHelpSpotChecks pins fragments of shipped help text that users and
// scripts rely on.
func TestHelpSpotChecks(t *testing.T) {
	r := newTestRunner()

	render := func(topic string) string {
		t.Helper()
		var buf bytes.Buffer
		if err := r.Help(&buf, topic); err != nil {
			t.Fatalf("Help(%q) returned error: %s", topic, err)
		}
		return buf.String()
	}

	curl := render("curl")
	if !strings.Contains(curl, "/v1 that every Vault API path begins with: safe adds it for you.") {
		t.Errorf("curl help no longer explains the /v1 prefix:\n%s", curl)
	}
	if !strings.Contains(curl, "safe curl [OPTIONS] METHOD REL-URI [DATA]") {
		t.Errorf("curl help usage line changed:\n%s", curl)
	}

	envvars := render("envvars")
	if !strings.Contains(envvars, "SAFE_TARGET") {
		t.Errorf("envvars help does not mention SAFE_TARGET:\n%s", envvars)
	}

	version := render("version")
	if !strings.Contains(version, "safe version") {
		t.Errorf("version help missing its usage line:\n%s", version)
	}
}
