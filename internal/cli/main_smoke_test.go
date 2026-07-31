package cli

// safe's own output -- the command listing, a help topic, the version -- is
// written by handlers that end in os.Exit, so what they say, where they say
// it, and the status they leave behind can only be read from outside the
// process. These tests build the binary once and run it.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

var (
	safeBuildOnce sync.Once
	safeBinPath   string
	safeBinDir    string
	safeBuildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if safeBinDir != "" {
		_ = os.RemoveAll(safeBinDir)
	}
	os.Exit(code)
}

// safeBinary builds cmd/safe once per test run and returns the path to it.
func safeBinary(t *testing.T) string {
	t.Helper()
	safeBuildOnce.Do(func() {
		safeBinDir, safeBuildErr = os.MkdirTemp("", "safe-smoke")
		if safeBuildErr != nil {
			return
		}
		safeBinPath = filepath.Join(safeBinDir, "safe")
		build := exec.Command("go", "build", "-o", safeBinPath,
			"github.com/cloudfoundry-community/safe/cmd/safe")
		if out, err := build.CombinedOutput(); err != nil {
			safeBuildErr = err
			t.Logf("go build: %s", out)
		}
	})
	if safeBuildErr != nil {
		t.Fatalf("building cmd/safe: %v", safeBuildErr)
	}
	return safeBinPath
}

// run invokes safe with args and returns its standard output, standard error,
// and exit status. The command runs against an empty home directory and an
// environment naming no Vault, so nothing it reads comes from the machine the
// tests run on.
func run(t *testing.T, args ...string) (stdout, stderr string, status int) {
	t.Helper()
	cmd := exec.Command(safeBinary(t), args...)
	cmd.Env = append(os.Environ(),
		"HOME="+t.TempDir(),
		"SAFE_TARGET=",
		"VAULT_ADDR=",
		"VAULT_TOKEN=",
	)
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	var exitErr *exec.ExitError
	switch err := cmd.Run(); {
	case err == nil:
	case errors.As(err, &exitErr):
		status = exitErr.ExitCode()
	default:
		t.Fatalf("running safe %s: %v", strings.Join(args, " "), err)
	}
	return out.String(), errOut.String(), status
}

// listedCommands returns the command names safe commands prints.
func listedCommands(t *testing.T, listing string) []string {
	t.Helper()
	var names []string
	for _, line := range strings.Split(listing, "\n") {
		if !strings.HasPrefix(line, "    ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		names = append(names, fields[0])
	}
	if len(names) == 0 {
		t.Fatalf("no commands parsed out of the listing:\n%s", listing)
	}
	return names
}

// safe commands is what safe's own help points at for a list of what it can
// do. It was no command at all: the listing came back only because an
// unrecognized command falls through to help, which prints it.
func TestCommandsIsACommandOfItsOwn(t *testing.T) {
	stdout, stderr, status := run(t, "commands")
	if status != 0 {
		t.Errorf("safe commands exited %d, want 0", status)
	}

	listing := stdout + stderr
	if !strings.Contains(listing, "Valid commands are:") {
		t.Fatalf("safe commands printed no listing:\n%s", listing)
	}

	if !slices.Contains(listedCommands(t, listing), "commands") {
		t.Errorf("the listing leaves out commands itself:\n%s", listing)
	}
}

// safe's own listing points at safe envvars for what the environment
// variables are, and safe help had no topic for it, nor for help itself.
// Neither was in the listing either.
func TestHelpAnswersForEnvvarsAndForItself(t *testing.T) {
	stdout, stderr, _ := run(t, "commands")
	listed := listedCommands(t, stdout+stderr)

	for _, name := range []string{"envvars", "help"} {
		if !slices.Contains(listed, name) {
			t.Errorf("the listing leaves out %s:\n%s", name, stdout+stderr)
		}
		out, errOut, status := run(t, "help", name)
		if status != 0 {
			t.Errorf("safe help %s exited %d, want 0:\n%s", name, status, out+errOut)
		}
	}

	//The topic is the documentation itself, not a line saying it exists.
	out, errOut, _ := run(t, "help", "envvars")
	if !strings.Contains(out+errOut, "SAFE_TARGET") {
		t.Errorf("safe help envvars names no environment variable:\n%s", out+errOut)
	}
}

// A command safe does not have was not a failure: the whole listing came back
// and the run ended in success, so a mistyped command in a script read as one
// that had done its work.
func TestAnUnrecognizedCommandIsNamedAndFails(t *testing.T) {
	stdout, stderr, status := run(t, "gett", "secret/handshake")
	if status == 0 {
		t.Errorf("safe gett exited 0, want a failure")
	}
	if !strings.Contains(stderr, "gett") {
		t.Errorf("stderr = %q, want the word safe did not recognize named", stderr)
	}
	if strings.Contains(stdout+stderr, "Valid commands are:") {
		t.Errorf("one mistyped command brought back the whole listing:\n%s", stdout+stderr)
	}
}

// Nothing at all is not a mistake to report -- it is someone asking what safe
// can do.
func TestNoCommandAtAllGivesTheListing(t *testing.T) {
	stdout, stderr, status := run(t)
	if status != 0 {
		t.Errorf("safe with no arguments exited %d, want 0", status)
	}
	if !strings.Contains(stdout+stderr, "Valid commands are:") {
		t.Errorf("safe with no arguments printed no listing:\n%s", stdout+stderr)
	}
}

// Help is output that was asked for, so it goes where output goes. It was
// written to standard error, so safe commands | grep came back with nothing.
func TestHelpIsWrittenToStandardOutput(t *testing.T) {
	for _, args := range [][]string{{"commands"}, {"help"}, {"help", "get"}, {"-h"}} {
		stdout, stderr, _ := run(t, args...)
		if stdout == "" {
			t.Errorf("safe %s wrote nothing to standard output; standard error had:\n%s",
				strings.Join(args, " "), stderr)
		}
	}
}

// So is the version. safe -v | cut told you nothing about which safe you are
// running, because the version was on standard error.
func TestVersionIsWrittenToStandardOutput(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"-v"}} {
		stdout, stderr, status := run(t, args...)
		if status != 0 {
			t.Errorf("safe %s exited %d, want 0", strings.Join(args, " "), status)
		}
		if !strings.Contains(stdout, "safe") {
			t.Errorf("safe %s wrote %q to standard output; standard error had:\n%s",
				strings.Join(args, " "), stdout, stderr)
		}
	}
}

// A topic safe has nothing to say about is a mistake to report, so it is
// reported where mistakes are reported, and not among the help that piping
// safe help collects.
func TestHelpForATopicThatDoesNotExistFails(t *testing.T) {
	stdout, stderr, status := run(t, "help", "bogus")
	if status == 0 {
		t.Errorf("safe help bogus exited 0, want a failure")
	}
	if !strings.Contains(stderr, "bogus") {
		t.Errorf("stderr = %q, want the topic safe does not have named", stderr)
	}
	if stdout != "" {
		t.Errorf("standard output = %q, want the complaint kept off it", stdout)
	}
}

// A command in the listing is a command safe help can answer for.
func TestHelpAnswersForEveryCommandListed(t *testing.T) {
	stdout, stderr, _ := run(t, "commands")
	for _, name := range listedCommands(t, stdout+stderr) {
		out, errOut, status := run(t, "help", name)
		if status != 0 {
			t.Errorf("safe help %s exited %d, want 0:\n%s", name, status, out+errOut)
		}
	}
}
