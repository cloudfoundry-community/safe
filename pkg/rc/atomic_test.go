package rc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomicCreates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saferc")

	if err := writeFileAtomic(path, []byte("version: 1\n"), 0600); err != nil {
		t.Fatalf("writeFileAtomic: %s", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %s", err)
	}
	if string(b) != "version: 1\n" {
		t.Errorf("content = %q", b)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %s", err)
	}
	if got := fi.Mode().Perm(); got != 0600 {
		t.Errorf("mode = %04o, want 0600", got)
	}
}

func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saferc")

	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatalf("seed: %s", err)
	}
	if err := writeFileAtomic(path, []byte("new"), 0600); err != nil {
		t.Fatalf("writeFileAtomic: %s", err)
	}

	b, _ := os.ReadFile(path)
	if string(b) != "new" {
		t.Errorf("content = %q, want %q", b, "new")
	}
}

func TestWriteFileAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saferc")

	for range 3 {
		if err := writeFileAtomic(path, []byte("x"), 0600); err != nil {
			t.Fatalf("writeFileAtomic: %s", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %s", err)
	}
	for _, e := range entries {
		if e.Name() != "saferc" {
			t.Errorf("leftover file %q", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("%d entries in dir, want 1", len(entries))
	}
}

// A failed write must leave the previous file exactly as it was: this is the
// credential store, and today's failure mode (truncate first, write maybe) is
// the defect being fixed.
func TestWriteFileAtomicFailureKeepsOriginal(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "saferc")
	if err := os.WriteFile(path, []byte("precious"), 0600); err != nil {
		t.Fatalf("seed: %s", err)
	}

	// An unwritable directory fails temp-file creation -- the earliest and
	// most common failure (unwritable $HOME).
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod: %s", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	err := writeFileAtomic(path, []byte("clobber"), 0600)
	if err == nil {
		t.Fatalf("writeFileAtomic succeeded in an unwritable directory")
	}

	b, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("original after failed write: %s", readErr)
	}
	if string(b) != "precious" {
		t.Errorf("original content = %q, want %q", b, "precious")
	}
}

func TestWriteFileAtomicRejectsMissingDir(t *testing.T) {
	err := writeFileAtomic(filepath.Join(t.TempDir(), "no", "such", "dir", "f"), []byte("x"), 0600)
	if err == nil {
		t.Fatalf("writeFileAtomic succeeded into a missing directory")
	}
	if !strings.Contains(err.Error(), "f") {
		t.Errorf("error %q does not mention the target", err)
	}
}
