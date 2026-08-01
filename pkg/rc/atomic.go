package rc

import (
	"os"
	"path/filepath"

	fmt "github.com/jhunt/go-ansi"
)

// writeFileAtomic replaces the file at path with data in one rename, so a
// reader (or a crash) sees either the previous complete file or the new one,
// never a truncated or half-written mix. The previous file survives every
// failure intact: nothing here ever truncates the target.
//
// The temp file is created in the target's own directory -- rename cannot
// cross filesystems -- and synced before the rename, since these files hold
// root tokens and a short file after a crash is not acceptable. The directory
// itself is not synced: that is not portable, and the worst case it leaves
// open is the rename not surviving a power loss -- a stale config, not a
// corrupt one.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	// os.Rename replaces whatever is at path -- if path is a symlink (a
	// dotfiles-managed ~/.saferc, ~/.vault-token, ~/.svtoken), that replaces
	// the link itself and detaches it, not the file it points at. Resolve to
	// the real file first so the temp file lands next to it and the rename
	// replaces the real file, leaving the link in place. A path that does not
	// exist yet (first write) has nothing to resolve; use it as given.
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}

	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}

	tmp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return fmt.Errorf("could not write %s: %w", path, err)
	}

	// From here on, any failure removes the temp file and leaves the target
	// alone.
	fail := func(what string, err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("could not %s %s: %w", what, path, err)
	}

	// CreateTemp always uses 0600; apply the caller's mode explicitly so the
	// renamed file carries it.
	if err := tmp.Chmod(perm); err != nil {
		return fail("set permissions on", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("write", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("could not close %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("could not replace %s: %w", path, err)
	}
	return nil
}
