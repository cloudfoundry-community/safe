package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestNewRunner verifies the constructor allocates both maps.
func TestNewRunner_Initialized(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	if r == nil {
		t.Fatal("NewRunner() returned nil")
	}
	if r.Handlers == nil {
		t.Error("Handlers map is nil")
	}
	if r.Topics == nil {
		t.Error("Topics map is nil")
	}
}

// TestRunner_Dispatch_RegistersHandlerAndTopic verifies that Dispatch stores
// the handler and, for non-hidden commands, the help topic.
func TestRunner_Dispatch_RegistersHandlerAndTopic(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	called := false
	r.Dispatch("ping", &Help{
		Summary: "ping summary",
		Usage:   "safe ping",
		Type:    NonDestructiveCommand,
	}, func(cmd string, args ...string) error {
		called = true
		return nil
	})

	if _, ok := r.Handlers["ping"]; !ok {
		t.Error("Handlers[ping] not registered")
	}
	if _, ok := r.Topics["ping"]; !ok {
		t.Error("Topics[ping] not registered for non-hidden command")
	}

	// Trigger handler to confirm it's the right function.
	if err := r.Execute("ping"); err != nil {
		t.Fatalf("Execute(ping): unexpected error: %v", err)
	}
	if !called {
		t.Error("registered handler was not called")
	}
}

// A hidden command is one the listing of commands leaves out. Its help is
// still meant to be reachable: `safe x509' is hidden and prints its own topic
// to say what its sub-commands are.
func TestRunner_Dispatch_HiddenCommand(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	r.Dispatch("secret-internal", &Help{
		Summary:     "hidden",
		Usage:       "safe secret-internal",
		Description: "what the hidden command is for",
		Type:        HiddenCommand,
	}, func(cmd string, args ...string) error { return nil })

	if _, inHandlers := r.Handlers["secret-internal"]; !inHandlers {
		t.Error("hidden command should still be in Handlers")
	}

	var help bytes.Buffer
	r.Help(&help, "secret-internal")
	if !strings.Contains(help.String(), "what the hidden command is for") {
		t.Errorf("help for a hidden command = %q, want its description", help.String())
	}

	var listing bytes.Buffer
	r.Help(&listing, "commands")
	if strings.Contains(listing.String(), "secret-internal") {
		t.Errorf("listing = %q, want a hidden command left out of it", listing.String())
	}
}

// The listing keeps the commands that are not hidden.
func TestRunner_Help_ListsVisibleCommands(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	r.Dispatch("ping", &Help{
		Summary: "ping summary",
		Type:    NonDestructiveCommand,
	}, func(cmd string, args ...string) error { return nil })

	var listing bytes.Buffer
	r.Help(&listing, "commands")
	if !strings.Contains(listing.String(), "ping") {
		t.Errorf("listing = %q, want it to name ping", listing.String())
	}
}

// TestRunner_Dispatch_NilHelp verifies that Dispatch with nil help still
// registers the handler and skips Topics.
func TestRunner_Dispatch_NilHelp(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	r.Dispatch("noop", nil, func(cmd string, args ...string) error { return nil })

	if _, ok := r.Handlers["noop"]; !ok {
		t.Error("Handlers[noop] not registered")
	}
	if _, ok := r.Topics["noop"]; ok {
		t.Error("Topics[noop] should not be set when help is nil")
	}
}

// TestRunner_Execute_HappyPath verifies that a registered handler is invoked
// with the correct command name and forwarded arguments.
func TestRunner_Execute_HappyPath(t *testing.T) {
	t.Parallel()
	r := NewRunner()

	var gotCmd string
	var gotArgs []string
	r.Dispatch("greet", nil, func(cmd string, args ...string) error {
		gotCmd = cmd
		gotArgs = args
		return nil
	})

	if err := r.Execute("greet", "hello", "world"); err != nil {
		t.Fatalf("Execute(greet): unexpected error: %v", err)
	}
	if gotCmd != "greet" {
		t.Errorf("cmd: got %q, want %q", gotCmd, "greet")
	}
	if len(gotArgs) != 2 || gotArgs[0] != "hello" || gotArgs[1] != "world" {
		t.Errorf("args: got %v, want [hello world]", gotArgs)
	}
}

// TestRunner_Execute_HandlerError verifies that errors returned by the handler
// are propagated unchanged.
func TestRunner_Execute_HandlerError(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	sentinel := errors.New("handler failure")
	r.Dispatch("fail", nil, func(cmd string, args ...string) error {
		return sentinel
	})

	err := r.Execute("fail")
	if !errors.Is(err, sentinel) {
		t.Errorf("Execute(fail): got %v, want sentinel error", err)
	}
}

// TestRunner_Execute_UnknownCommand verifies the "unknown command" error path.
func TestRunner_Execute_UnknownCommand(t *testing.T) {
	t.Parallel()
	r := NewRunner()

	err := r.Execute("no-such-command")
	if err == nil {
		t.Fatal("expected error for unknown command, got nil")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("error message: got %q, want to contain 'unknown command'", err.Error())
	}
	if !strings.Contains(err.Error(), "no-such-command") {
		t.Errorf("error message: got %q, want to contain command name", err.Error())
	}
}

// TestRunner_Execute_NoArgs verifies execution with zero extra arguments.
func TestRunner_Execute_NoArgs(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	var gotArgs []string
	r.Dispatch("noargs", nil, func(cmd string, args ...string) error {
		gotArgs = args
		return nil
	})
	if err := r.Execute("noargs"); err != nil {
		t.Fatalf("Execute(noargs): unexpected error: %v", err)
	}
	if len(gotArgs) != 0 {
		t.Errorf("args: got %v, want empty", gotArgs)
	}
}

// TestUsageError_Error verifies the Error() string format.
func TestUsageError_Error(t *testing.T) {
	t.Parallel()
	cases := []struct {
		topic string
		want  string
	}{
		{"delete", "usage error: delete"},
		{"x509 issue", "usage error: x509 issue"},
		{"", "usage error: "},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.topic, func(t *testing.T) {
			t.Parallel()
			e := &UsageError{Topic: tc.topic}
			if got := e.Error(); got != tc.want {
				t.Errorf("UsageError{%q}.Error(): got %q, want %q", tc.topic, got, tc.want)
			}
		})
	}
}

// TestRunner_Usage_ReturnsUsageError verifies that r.Usage wraps the topic in
// a *UsageError so callers can use errors.As.
func TestRunner_Usage_ReturnsUsageError(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	err := r.Usage("revert")
	if err == nil {
		t.Fatal("Usage() returned nil")
	}
	var usageErr *UsageError
	if !errors.As(err, &usageErr) {
		t.Fatalf("errors.As(*UsageError): got %T (%v)", err, err)
	}
	if usageErr.Topic != "revert" {
		t.Errorf("Topic: got %q, want %q", usageErr.Topic, "revert")
	}
}

// TestRunner_Dispatch_DescriptionTrimmed verifies that leading/trailing newlines
// in help.Description are stripped during Dispatch.
func TestRunner_Dispatch_DescriptionTrimmed(t *testing.T) {
	t.Parallel()
	r := NewRunner()
	r.Dispatch("trimcmd", &Help{
		Summary:     "trim test",
		Description: "\n\nbody text\n\n",
		Type:        AdministrativeCommand,
	}, func(cmd string, args ...string) error { return nil })

	h := r.Topics["trimcmd"]
	if h == nil {
		t.Fatal("Topics[trimcmd] not found")
	}
	if h.Description != "body text" {
		t.Errorf("Description: got %q, want %q", h.Description, "body text")
	}
}

// Help used to end the process itself for a topic it did not have, which left
// the caller no chance to say anything about it and skipped the cleanup safe
// does on its way out. It reports the topic back instead.
func TestRunner_Help_UnknownTopic(t *testing.T) {
	t.Parallel()
	r := NewRunner()

	var out bytes.Buffer
	err := r.Help(&out, "no-such-topic")
	if !errors.Is(err, ErrNoSuchTopic) {
		t.Errorf("Help(no-such-topic): got %v, want ErrNoSuchTopic", err)
	}
	if out.String() != "" {
		t.Errorf("Help wrote %q, want the complaint left to the caller", out.String())
	}
}
