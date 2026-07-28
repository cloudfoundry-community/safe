package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExpandValueArg covers all branches of expandValueArg:
//   - plain value  (returned unchanged)
//   - @@value      (escaped literal leading @)
//   - @-           (read all of stdin via os.Pipe replacement)
//   - @FILE        (read file contents verbatim)
//   - @            (missing filename — error)
//   - @missing     (unreadable file — error)
func TestExpandValueArg_Plain(t *testing.T) {
	t.Parallel()
	for _, arg := range []string{"hunter2", "with@inside", "trailing@", ""} {
		got, err := expandValueArg(arg)
		if err != nil {
			t.Fatalf("expandValueArg(%q): unexpected error: %v", arg, err)
		}
		if got != arg {
			t.Errorf("expandValueArg(%q): got %q, want it unchanged", arg, got)
		}
	}
}

func TestExpandValueArg_DoubleAtEscape(t *testing.T) {
	t.Parallel()
	got, err := expandValueArg("@@literal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "@literal" {
		t.Errorf("got %q, want %q", got, "@literal")
	}

	// The escape strips exactly one '@'; "@@@x" yields "@@x".
	got, err = expandValueArg("@@@x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "@@x" {
		t.Errorf("got %q, want %q", got, "@@x")
	}
}

func TestExpandValueArg_Stdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })

	content := "value from stdin\nwith a second line\n"
	go func() {
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()

	got, err := expandValueArg("@-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != content {
		t.Errorf("got %q, want %q (content must be verbatim, no trimming)", got, content)
	}
}

func TestExpandValueArg_File(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "value.txt")
	content := "file value\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got, err := expandValueArg("@" + path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != content {
		t.Errorf("got %q, want %q (content must be verbatim, no trimming)", got, content)
	}
}

func TestExpandValueArg_BareAt(t *testing.T) {
	t.Parallel()
	_, err := expandValueArg("@")
	if err == nil {
		t.Fatal("expected error for bare @, got nil")
	}
	if !strings.Contains(err.Error(), "no file specified") {
		t.Errorf("error %q should mention 'no file specified'", err)
	}
}

func TestExpandValueArg_MissingFile(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := expandValueArg("@" + missing)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q should name the file %q", err, missing)
	}
}
