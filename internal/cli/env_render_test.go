package cli

// Tests for cmdEnv rendering branches: bash, fish, and JSON.
//
// cmdEnv calls rc.Apply(opt.UseTarget) first (we isolate HOME → tmpdir),
// then writes to os.Stdout. We capture stdout via os.Pipe.
//
// The "default" branch (stderr token display) is NOT tested here because it
// writes to os.Stderr and depends on ANSI colorization state — it is low-value
// to capture and compare against.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn while capturing everything written to os.Stdout.
// It restores the original os.Stdout on return regardless of errors.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })

	fn()

	// Close write end so the read does not block.
	if err := w.Close(); err != nil {
		t.Fatalf("pipe close: %v", err)
	}
	os.Stdout = orig

	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for {
		n, readErr := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if readErr != nil {
			break
		}
	}
	_ = r.Close()
	return string(buf)
}

// newEnvCLI builds a *CLI with the env command registered.
func newEnvCLI(t *testing.T) *CLI {
	t.Helper()
	r := NewRunner()
	opt := &Options{}
	c := &CLI{opt: opt, r: r}
	r.Dispatch("env", &Help{
		Summary: "Print env vars",
		Usage:   "safe env",
		Type:    AdministrativeCommand,
	}, c.cmdEnv)
	return c
}

// ---------------------------------------------------------------------------
// bash branch
// ---------------------------------------------------------------------------

func TestCmdEnv_Bash_SetVars(t *testing.T) {
	isolateHome(t)
	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "s.testtoken")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_NAMESPACE", "")

	c := newEnvCLI(t)
	c.opt.Env.ForBash = true

	out := captureStdout(t, func() {
		if err := c.cmdEnv("env"); err != nil {
			t.Errorf("cmdEnv bash: unexpected error: %v", err)
		}
	})

	// Variables with values use \export KEY=VALUE;
	if !strings.Contains(out, `\export VAULT_ADDR=https://vault.example.com;`) {
		t.Errorf("bash: VAULT_ADDR export missing; got:\n%s", out)
	}
	if !strings.Contains(out, `\export VAULT_TOKEN=s.testtoken;`) {
		t.Errorf("bash: VAULT_TOKEN export missing; got:\n%s", out)
	}
	// Empty vars use \unset KEY;
	if !strings.Contains(out, `\unset VAULT_SKIP_VERIFY;`) {
		t.Errorf("bash: VAULT_SKIP_VERIFY unset missing; got:\n%s", out)
	}
	if !strings.Contains(out, `\unset VAULT_NAMESPACE;`) {
		t.Errorf("bash: VAULT_NAMESPACE unset missing; got:\n%s", out)
	}
}

func TestCmdEnv_Bash_AllUnset(t *testing.T) {
	isolateHome(t)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_NAMESPACE", "")

	c := newEnvCLI(t)
	c.opt.Env.ForBash = true

	out := captureStdout(t, func() {
		if err := c.cmdEnv("env"); err != nil {
			t.Errorf("cmdEnv bash all-unset: unexpected error: %v", err)
		}
	})

	for _, key := range []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_SKIP_VERIFY", "VAULT_NAMESPACE"} {
		want := `\unset ` + key + ";"
		if !strings.Contains(out, want) {
			t.Errorf("bash all-unset: missing %q in output:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------------------
// fish branch
// ---------------------------------------------------------------------------

func TestCmdEnv_Fish_SetVars(t *testing.T) {
	isolateHome(t)
	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "s.fishtoken")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_NAMESPACE", "")

	c := newEnvCLI(t)
	c.opt.Env.ForFish = true

	out := captureStdout(t, func() {
		if err := c.cmdEnv("env"); err != nil {
			t.Errorf("cmdEnv fish: unexpected error: %v", err)
		}
	})

	// Set variables use: set -x KEY VALUE;
	if !strings.Contains(out, "set -x VAULT_ADDR https://vault.example.com;") {
		t.Errorf("fish: VAULT_ADDR set missing; got:\n%s", out)
	}
	if !strings.Contains(out, "set -x VAULT_TOKEN s.fishtoken;") {
		t.Errorf("fish: VAULT_TOKEN set missing; got:\n%s", out)
	}
	// Unset variables use: set -u KEY;
	if !strings.Contains(out, "set -u VAULT_SKIP_VERIFY;") {
		t.Errorf("fish: VAULT_SKIP_VERIFY unset missing; got:\n%s", out)
	}
	if !strings.Contains(out, "set -u VAULT_NAMESPACE;") {
		t.Errorf("fish: VAULT_NAMESPACE unset missing; got:\n%s", out)
	}
}

func TestCmdEnv_Fish_AllUnset(t *testing.T) {
	isolateHome(t)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_NAMESPACE", "")

	c := newEnvCLI(t)
	c.opt.Env.ForFish = true

	out := captureStdout(t, func() {
		if err := c.cmdEnv("env"); err != nil {
			t.Errorf("cmdEnv fish all-unset: unexpected error: %v", err)
		}
	})

	for _, key := range []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_SKIP_VERIFY", "VAULT_NAMESPACE"} {
		want := "set -u " + key + ";"
		if !strings.Contains(out, want) {
			t.Errorf("fish all-unset: missing %q in output:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------------------
// JSON branch
// ---------------------------------------------------------------------------

func TestCmdEnv_JSON_AllSet(t *testing.T) {
	isolateHome(t)
	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "s.jsontoken")
	t.Setenv("VAULT_SKIP_VERIFY", "1")
	t.Setenv("VAULT_NAMESPACE", "ns/dev")

	c := newEnvCLI(t)
	c.opt.Env.ForJSON = true

	out := captureStdout(t, func() {
		if err := c.cmdEnv("env"); err != nil {
			t.Errorf("cmdEnv json: unexpected error: %v", err)
		}
	})

	// Output must be valid JSON.
	var parsed struct {
		Addr  string `json:"VAULT_ADDR"`
		Token string `json:"VAULT_TOKEN"`
		Skip  string `json:"VAULT_SKIP_VERIFY"`
		NS    string `json:"VAULT_NAMESPACE"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("json.Unmarshal: %v\noutput:\n%s", err, out)
	}

	if parsed.Addr != "https://vault.example.com" {
		t.Errorf("VAULT_ADDR: got %q, want %q", parsed.Addr, "https://vault.example.com")
	}
	if parsed.Token != "s.jsontoken" {
		t.Errorf("VAULT_TOKEN: got %q, want %q", parsed.Token, "s.jsontoken")
	}
	if parsed.Skip != "1" {
		t.Errorf("VAULT_SKIP_VERIFY: got %q, want %q", parsed.Skip, "1")
	}
	if parsed.NS != "ns/dev" {
		t.Errorf("VAULT_NAMESPACE: got %q, want %q", parsed.NS, "ns/dev")
	}
}

func TestCmdEnv_JSON_OnlyAddr(t *testing.T) {
	isolateHome(t)
	t.Setenv("VAULT_ADDR", "https://minimal.example.com")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_NAMESPACE", "")

	c := newEnvCLI(t)
	c.opt.Env.ForJSON = true

	out := captureStdout(t, func() {
		if err := c.cmdEnv("env"); err != nil {
			t.Errorf("cmdEnv json minimal: unexpected error: %v", err)
		}
	})

	// Must be valid JSON and contain VAULT_ADDR key.
	var parsed struct {
		Addr  string `json:"VAULT_ADDR"`
		Token string `json:"VAULT_TOKEN"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("json.Unmarshal: %v\noutput:\n%s", err, out)
	}
	if parsed.Addr != "https://minimal.example.com" {
		t.Errorf("VAULT_ADDR: got %q, want %q", parsed.Addr, "https://minimal.example.com")
	}
	// Token is omitempty in the struct, so empty is fine.
}

func TestCmdEnv_JSON_OutputNewline(t *testing.T) {
	isolateHome(t)
	t.Setenv("VAULT_ADDR", "https://vault.example.com")
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_SKIP_VERIFY", "")
	t.Setenv("VAULT_NAMESPACE", "")

	c := newEnvCLI(t)
	c.opt.Env.ForJSON = true

	out := captureStdout(t, func() {
		if err := c.cmdEnv("env"); err != nil {
			t.Errorf("cmdEnv json newline: unexpected error: %v", err)
		}
	})

	// cmdEnv JSON branch ends with a newline (fmt.Printf("%s\n", ...))
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("JSON output should end with newline, got: %q", out)
	}
}
