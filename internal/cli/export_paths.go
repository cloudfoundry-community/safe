package cli

import (
	"sort"
	"strings"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// dedupeExportPaths sorts the given secret paths and drops any path already
// covered by an earlier one, so export walks each subtree exactly once.
// Callers must pass canonicalized paths (no keys, no versions).
func dedupeExportPaths(paths []string) []string {
	sort.Slice(paths, func(i, j int) bool { return vault.PathLessThan(paths[i], paths[j]) })
	for i := 0; i < len(paths)-1; i++ {
		//No need to get a deeper part of a tree if you're already walking the `((great)*grand)?parent`
		if strings.HasPrefix(strings.Trim(paths[i+1], "/"), strings.Trim(paths[i], "/")) {
			before := paths[:i+1]
			var after []string
			if len(paths)-1 != i+1 {
				after = paths[i+2:]
			}
			paths = append(before, after...)
			i--
		}
	}
	return paths
}
