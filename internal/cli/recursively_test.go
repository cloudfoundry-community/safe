package cli

// recursively is the confirmation gate in front of every recursive delete,
// move, and copy: it asks, names the command and the paths it is about to
// touch, and only a plain yes lets the command proceed.
//
// prompt.SetReader and captureStderr both mutate process-global state — do
// NOT add t.Parallel to any test in this file. An empty input is not tested
// because exhausting the prompt's input ends the process.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

func TestRecursivelyAcceptsOnlyYes(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"y\n", true},
		{"yes\n", true},
		{"  y  \n", true}, // surrounding whitespace is not a refusal
		{"n\n", false},
		{"no\n", false},
		{"Y\n", false}, // consent is spelled in lowercase
		{"YES\n", false},
		{"yeah\n", false},
		{"\n", false}, // just pressing enter is not consent
	}
	for _, tc := range tests {
		t.Run(strings.TrimSpace(tc.input), func(t *testing.T) {
			prompt.SetReader(strings.NewReader(tc.input))
			t.Cleanup(func() { prompt.SetReader(nil) })

			var got bool
			captureStderr(t, func() {
				got = recursively("delete", "secret/a")
			})
			if got != tc.want {
				t.Errorf("recursively with input %q = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// The question names the command and every path it was given, because a
// prompt that does not say what it is about to do is not one anyone can
// answer.
func TestRecursivelyNamesTheCommandAndPaths(t *testing.T) {
	prompt.SetReader(strings.NewReader("n\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	out := captureStderr(t, func() {
		recursively("move", "secret/from", "secret/to")
	})
	for _, want := range []string{"Recursively", "move", "secret/from secret/to", "(y/n)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the prompt is missing %q:\n%s", want, out)
		}
	}
}
