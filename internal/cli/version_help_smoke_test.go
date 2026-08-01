package cli

// The version, help, and commands handlers end in os.Exit, so their exit
// status and what they leave on each stream can only be read from outside the
// process. main_smoke_test.go pins where their output goes; these tests pin
// what the version says about the build it came from and how help finds its
// topics.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A binary built without version metadata says so, rather than claiming a
// version it does not have.
func TestVersionOfADevelopmentBuild(t *testing.T) {
	stdout, _, status := run(t, "version")
	if status != 0 {
		t.Errorf("safe version exited %d, want 0", status)
	}
	if !strings.Contains(stdout, "development build") {
		t.Errorf("a build with no version should say development build, got:\n%s", stdout)
	}
	if strings.Contains(stdout, "commit") || strings.Contains(stdout, "built") {
		t.Errorf("a build with no metadata should not print commit or build lines:\n%s", stdout)
	}
}

// A released binary carries its version, commit, and build time, set through
// -ldflags at build time, and safe version reads them all back.
func TestVersionReportsBuildMetadata(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "safe")
	build := exec.Command("go", "build",
		"-ldflags", "-X main.Version=1.2.3 -X main.GitCommit=abc1234 -X main.BuildTime=2026-07-31T00:00:00Z",
		"-o", bin, "github.com/cloudfoundry-community/safe/cmd/safe")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	cmd := exec.Command(bin, "version")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "SAFE_TARGET=", "VAULT_ADDR=", "VAULT_TOKEN=")
	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	var exitErr *exec.ExitError
	switch err := cmd.Run(); {
	case err == nil:
	case errors.As(err, &exitErr):
		t.Errorf("safe version exited %d, want 0", exitErr.ExitCode())
	default:
		t.Fatalf("running safe version: %v", err)
	}

	stdout := out.String()
	for _, want := range []string{"safe v1.2.3", "commit abc1234", "built", "2026-07-31T00:00:00Z"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("safe version output is missing %q:\n%s", want, stdout)
		}
	}
	if errOut.Len() != 0 {
		t.Errorf("safe version wrote to standard error: %q", errOut.String())
	}
}

// help with nothing to look up answers with the command listing, the same
// answer safe commands gives.
func TestHelpWithNoTopicGivesTheListing(t *testing.T) {
	stdout, stderr, status := run(t, "help")
	if status != 0 {
		t.Errorf("safe help exited %d, want 0", status)
	}
	if !strings.Contains(stdout, "Valid commands are:") {
		t.Errorf("safe help printed no listing on standard output; standard error had:\n%s", stderr)
	}
}

// Sub-commands are registered under two-word names, and help joins its
// arguments back together to find them: safe help target delete is the topic
// `target delete', not the topic `target' with an argument.
func TestHelpJoinsAMultiWordTopic(t *testing.T) {
	stdout, stderr, status := run(t, "help", "target", "delete")
	if status != 0 {
		t.Errorf("safe help target delete exited %d, want 0:\n%s", status, stdout+stderr)
	}
	if !strings.Contains(stdout, "target delete") {
		t.Errorf("the topic printed does not name target delete:\n%s", stdout)
	}
}

// safe commands and safe help commands are the same topic reached two ways,
// so they answer alike.
func TestCommandsMatchesHelpCommands(t *testing.T) {
	direct, _, directStatus := run(t, "commands")
	viaHelp, _, helpStatus := run(t, "help", "commands")
	if directStatus != 0 || helpStatus != 0 {
		t.Fatalf("exited %d and %d, want 0 and 0", directStatus, helpStatus)
	}
	if direct != viaHelp {
		t.Errorf("safe commands and safe help commands disagree:\n--- commands ---\n%s\n--- help commands ---\n%s", direct, viaHelp)
	}
}
