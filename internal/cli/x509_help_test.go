package cli

// `safe x509' is dispatched to a handler that prints the x509 help topic, and
// the topic is registered hidden so the umbrella command stays out of the
// listing of commands. A hidden command used to be left out of the help
// entirely, so both `safe x509' and `safe help x509' answered that there is no
// such command -- and the description of every x509 sub-command went with it.

import (
	"strings"
	"testing"
)

func TestX509PrintsTheHelpForItsSubcommands(t *testing.T) {
	r := NewRunner()
	c := &CLI{opt: &Options{}, r: r}
	r.Dispatch("x509", &Help{
		Summary:     "Issue / Revoke X.509 Certificates and Certificate Authorities",
		Usage:       "safe x509 <command> [OPTIONS]",
		Type:        HiddenCommand,
		Description: "x509 provides a handful of sub-commands for issuing certificates.",
	}, c.cmdX509)

	out := captureStdout(t, func() {
		if err := c.cmdX509("x509"); err != nil {
			t.Fatalf("cmdX509: %v", err)
		}
	})

	for _, want := range []string{
		"Issue / Revoke X.509 Certificates",
		"safe x509 <command> [OPTIONS]",
		"a handful of sub-commands",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("`safe x509' printed %q, want it to contain %q", out, want)
		}
	}
}
