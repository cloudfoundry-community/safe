package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseKeyVal covers all branches of parseKeyVal:
//   - key=value  (non-empty value)
//   - key=        (empty value)
//   - key@file   (read from file)
//   - key@-      (read from stdin via os.Pipe replacement)
//   - key@       (missing filename — error)
//   - bare key   (no = or @; returns missing=true)
//
// The stdin branch is covered by temporarily replacing os.Stdin with a pipe.
func TestParseKeyVal_EqualsSplit_NonEmpty(t *testing.T) {
	t.Parallel()
	k, v, missing, err := parseKeyVal("username=alice", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "username" {
		t.Errorf("key: got %q, want %q", k, "username")
	}
	if v != "alice" {
		t.Errorf("value: got %q, want %q", v, "alice")
	}
	if missing {
		t.Errorf("missing: got true, want false")
	}
}

func TestParseKeyVal_EqualsSplit_EmptyValue(t *testing.T) {
	t.Parallel()
	k, v, missing, err := parseKeyVal("username=", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "username" {
		t.Errorf("key: got %q, want %q", k, "username")
	}
	if v != "" {
		t.Errorf("value: got %q, want empty string", v)
	}
	if missing {
		t.Errorf("missing: got true, want false")
	}
}

func TestParseKeyVal_EqualsSplit_ValueContainsEquals(t *testing.T) {
	t.Parallel()
	// Only the first '=' splits; remainder is the value.
	k, v, missing, err := parseKeyVal("cert=a=b==c", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "cert" {
		t.Errorf("key: got %q, want %q", k, "cert")
	}
	if v != "a=b==c" {
		t.Errorf("value: got %q, want %q", v, "a=b==c")
	}
	if missing {
		t.Errorf("missing: got true, want false")
	}
}

func TestParseKeyVal_AtFile_ReadsContents(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	content := "super-secret-value\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	k, v, missing, err := parseKeyVal("token@"+path, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "token" {
		t.Errorf("key: got %q, want %q", k, "token")
	}
	if v != content {
		t.Errorf("value: got %q, want %q", v, content)
	}
	if missing {
		t.Errorf("missing: got true, want false")
	}
}

func TestParseKeyVal_AtFile_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing_path := filepath.Join(dir, "does-not-exist.txt")

	_, _, _, err := parseKeyVal("token@"+missing_path, true)
	if err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read contents of") {
		t.Errorf("error message: got %q, want to contain 'failed to read contents of'", err.Error())
	}
}

func TestParseKeyVal_AtEmpty_MissingFilename(t *testing.T) {
	t.Parallel()
	// "key@" with no filename after '@'
	k, _, missing, err := parseKeyVal("token@", true)
	if err == nil {
		t.Fatalf("expected error for missing filename, got nil")
	}
	if k != "token" {
		t.Errorf("key: got %q, want %q", k, "token")
	}
	if !missing {
		t.Errorf("missing: got false, want true")
	}
	if !strings.Contains(err.Error(), "no file specified") {
		t.Errorf("error message: got %q, want to contain 'no file specified'", err.Error())
	}
}

func TestParseKeyVal_BareKey_ReturnsMissing(t *testing.T) {
	t.Parallel()
	// Bare key (no '=' or '@') returns missing=true, empty value, nil error.
	// The caller is expected to prompt the user; we only test the non-prompt return.
	k, v, missing, err := parseKeyVal("password", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "password" {
		t.Errorf("key: got %q, want %q", k, "password")
	}
	if v != "" {
		t.Errorf("value: got %q, want empty string", v)
	}
	if !missing {
		t.Errorf("missing: got false, want true for bare key")
	}
}

func TestParseKeyVal_AtStdin_ReadsFromPipe(t *testing.T) {
	// Replace os.Stdin with a pipe so we can feed data without a TTY.
	// Not parallel: mutates the process-level os.Stdin.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})

	want := "piped-secret-data"
	if _, err := w.WriteString(want); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close write end of pipe: %v", err)
	}

	k, v, missing, err := parseKeyVal("secret@-", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k != "secret" {
		t.Errorf("key: got %q, want %q", k, "secret")
	}
	if v != want {
		t.Errorf("value: got %q, want %q", v, want)
	}
	if missing {
		t.Errorf("missing: got true, want false")
	}
}

func TestParseKeyVal_TableDriven(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tmpFile := filepath.Join(dir, "val.txt")
	if err := os.WriteFile(tmpFile, []byte("filedata"), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cases := []struct {
		name        string
		input       string
		wantKey     string
		wantVal     string
		wantMissing bool
		wantErrSub  string // non-empty means expect error containing this
	}{
		{
			name:    "equals with value",
			input:   "k=v",
			wantKey: "k", wantVal: "v", wantMissing: false,
		},
		{
			name:    "equals empty value",
			input:   "k=",
			wantKey: "k", wantVal: "", wantMissing: false,
		},
		{
			name:    "at file",
			input:   "k@" + tmpFile,
			wantKey: "k", wantVal: "filedata", wantMissing: false,
		},
		{
			name:        "at empty filename",
			input:       "k@",
			wantKey:     "k",
			wantMissing: true,
			wantErrSub:  "no file specified",
		},
		{
			name:    "bare key",
			input:   "barekey",
			wantKey: "barekey", wantVal: "", wantMissing: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, v, missing, err := parseKeyVal(tc.input, true)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("parseKeyVal(%q): expected error containing %q, got nil", tc.input, tc.wantErrSub)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("parseKeyVal(%q): error %q does not contain %q", tc.input, err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseKeyVal(%q): unexpected error: %v", tc.input, err)
			}
			if k != tc.wantKey {
				t.Errorf("parseKeyVal(%q): key got %q, want %q", tc.input, k, tc.wantKey)
			}
			if v != tc.wantVal {
				t.Errorf("parseKeyVal(%q): value got %q, want %q", tc.input, v, tc.wantVal)
			}
			if missing != tc.wantMissing {
				t.Errorf("parseKeyVal(%q): missing got %v, want %v", tc.input, missing, tc.wantMissing)
			}
		})
	}
}
