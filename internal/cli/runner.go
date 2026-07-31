package cli

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jhunt/go-ansi"
)

const (
	DestructiveCommand    string = "@R"
	NonDestructiveCommand string = "@G"
	AdministrativeCommand string = "@W"
	MiscellaneousCommand  string = "@W"
	HiddenCommand         string = "HIDEME"
)

type Help struct {
	Summary     string
	Usage       string
	Description string
	Type        string
}

type Handler func(command string, args ...string) error

type Runner struct {
	Handlers map[string]Handler
	Topics   map[string]*Help
}

func NewRunner() *Runner {
	return &Runner{
		Handlers: make(map[string]Handler),
		Topics:   make(map[string]*Help),
	}
}

func (r *Runner) Dispatch(command string, help *Help, fn Handler) {
	if help != nil {
		help.Description = strings.Trim(help.Description, "\n")
	}

	r.Handlers[command] = fn
	//A hidden command is kept out of the listing of commands, which is where
	// Help leaves it out. Keeping it out of the topics as well took its help
	// with it: `safe help x509' and `safe x509' -- which prints that very
	// topic -- both answered that there is no such command, and the
	// description of every x509 sub-command was unreachable.
	if help != nil {
		r.Topics[command] = help
	}
}

func (r *Runner) HelpTopic(topic string, help string) {
	r.Topics[topic] = &Help{Description: strings.Trim(help, "\n")}
}

// ErrNoSuchTopic is what Help gives back when it is asked for a topic that
// was never registered.
var ErrNoSuchTopic = errors.New("no such help topic")

// Help writes the topic to out. A topic it does not have is reported back
// rather than complained about here: what to say about it, and where, belongs
// to the caller, and ending the process from inside the lookup skipped the
// cleanup safe does on its way out.
func (r *Runner) Help(out io.Writer, topic string) error {
	if topic == "commands" {
		_, _ = fmt.Fprintf(out, "Valid commands are:\n\n")

		ll := make([]string, 0)
		for cmd := range r.Handlers {
			ll = append(ll, cmd)
		}

		sort.Strings(ll)
		for _, cmd := range ll {
			if h := r.Topics[cmd]; h != nil && h.Type != HiddenCommand {
				f := h.Type
				if f == "" {
					f = "@W"
				}
				_, _ = ansi.Fprintf(out, "    "+f+"{%-10s}  %s\n", cmd, h.Summary)
			}
		}

		_, _ = fmt.Fprintf(out, "\nTry `safe envvars' for information on available environment variables\n")
		_, _ = fmt.Fprintf(out, "Try 'safe help <command>' for detailed information on specific commands\n")
		return nil
	}

	if help, ok := r.Topics[topic]; ok && help != nil {
		if help.Summary != "" {
			/* this is a command, print it like one */
			_, _ = ansi.Fprintf(out, "safe @G{%s} - @C{%s}\n", topic, help.Summary)
			if help.Usage != "" {
				_, _ = ansi.Fprintf(out, "USAGE: "+help.Usage+"\n")
			}
			if help.Description != "" {
				_, _ = ansi.Fprintf(out, "\n")
			}
		}
		if help.Description != "" {
			_, _ = ansi.Fprintf(out, help.Description+"\n")
		}
		return nil
	}

	return fmt.Errorf("%w: %s", ErrNoSuchTopic, topic)
}

// UsageError signals a command was invoked incorrectly. Handlers return it
// instead of exiting; the CLI renders the topic's usage block via PrintUsage
// and exits non-zero. Returning rather than calling os.Exit keeps the dispatch
// layer testable.
type UsageError struct {
	Topic string
}

func (e *UsageError) Error() string {
	return fmt.Sprintf("usage error: %s", e.Topic)
}

// Usage returns a UsageError for topic.
func (r *Runner) Usage(topic string) error {
	return &UsageError{Topic: topic}
}

// PrintUsage writes the usage block for topic to w. It does not exit.
func (r *Runner) PrintUsage(w io.Writer, topic string) {
	if help, ok := r.Topics[topic]; ok && help != nil {
		if help.Summary != "" {
			/* this is a command, print it like one */
			_, _ = ansi.Fprintf(w, "safe @G{%s} - @C{%s}\n", topic, help.Summary)
			if help.Usage != "" {
				_, _ = ansi.Fprintf(w, "USAGE: "+help.Usage+"\n")
			}
		}
	}
}

func (r *Runner) Execute(command string, args ...string) error {
	if fn, ok := r.Handlers[command]; ok {
		return fn(command, args...)
	}
	return fmt.Errorf("unknown command '%s'", command)
}
