// The yes/no prompt that offers to add an unknown host key. It reads from
// stdin, and stdin is not always something that will answer.
package vault

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// askToAddHost runs the prompt against the given input and returns its answer.
// It fails the test if the prompt has not returned within a second, since the
// caller of a prompt that never returns is a process that has to be killed.
//
// Stderr goes to the null device while the prompt runs: a prompt that does
// loop writes to it as fast as it can, and the test should not be filling a
// disk while it waits. Where the prompt has not returned, stderr is left at
// the null device rather than put back, because the prompt is still writing
// to it and the rest of the run should not be buried.
func askToAddHost(t *testing.T, input string) bool {
	t.Helper()

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	realStderr := os.Stderr
	os.Stderr = devNull
	prompt.SetReader(strings.NewReader(input))

	answered := make(chan bool, 1)
	go func() {
		answered <- promptAddNewKnownHost("unknown.example.com:22",
			fakeNetAddr("127.0.0.1:22"), makeEd25519PublicKey(t))
	}()

	select {
	case answer := <-answered:
		os.Stderr = realStderr
		prompt.SetReader(nil)
		_ = devNull.Close()
		return answer
	case <-time.After(time.Second):
		t.Fatalf("prompt did not return for input %q", input)
		return false
	}
}

// TestPromptStopsWhenThereIsNoAnswer covers input that runs out. A read that
// gives nothing left the answer unset and asked again, so the prompt spun
// until the process was killed. An answer that never comes is a no.
func TestPromptStopsWhenThereIsNoAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "nothing at all", input: ""},
		{name: "an unusable answer and then nothing", input: "maybe\n"},
		{name: "a line with no newline to close it", input: "y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if askToAddHost(t, tc.input) {
				t.Error("prompt accepted the host key without being told yes")
			}
		})
	}
}

// TestPromptAnswers covers the answers a person can give.
func TestPromptAnswers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  bool
	}{
		{name: "yes", input: "yes\n", want: true},
		{name: "no", input: "no\n", want: false},
		{name: "asked again after an unusable answer", input: "maybe\nyes\n", want: true},
		{name: "trailing blanks", input: "yes  \n", want: true},
		{name: "declined after an unusable answer", input: "sure\nno\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := askToAddHost(t, tc.input); got != tc.want {
				t.Errorf("answer to %q was %t, want %t", tc.input, got, tc.want)
			}
		})
	}
}
