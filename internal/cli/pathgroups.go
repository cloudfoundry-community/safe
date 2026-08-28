package cli

import (
	"os"

	"github.com/cloudfoundry-community/safe/internal/parallel"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// groupByCanonicalPath buckets targets by the canonical secret path that
// ParsePath derives from pathOf's result -- not the raw argument, which
// some callers only canonicalize on the path:key branch -- so secret//x:a
// and secret/x b, say, land in the same bucket rather than racing each
// other's read-modify-write on the same secret. order lists each canonical
// path in the order it first appeared, which is what later drives notice
// replay; within a bucket, targets keep their argument order.
func groupByCanonicalPath[T any](targets []T, pathOf func(T) string) (order []string, groups map[string][]T) {
	groups = map[string][]T{}
	for _, target := range targets {
		p, _, _ := vault.ParsePath(pathOf(target))
		if _, seen := groups[p]; !seen {
			order = append(order, p)
		}
		groups[p] = append(groups[p], target)
	}
	return order, groups
}

// runPathGroups runs one group of targets per canonical path: distinct
// paths run concurrently, at most limit at a time, while targets sharing a
// path stay sequential within their group, one read-modify-write at a
// time, so a repeated argument never races itself.
//
// run handles a single target; returning an error abandons the rest of
// that target's group and fails the whole fan-out. notice renders a stderr
// line through renderNotice and buffers it with its group. Notices print
// after every group finishes, in the order their paths first appeared on
// the command line -- not completion order.
func runPathGroups[T any](order []string, groups map[string][]T, limit int, run func(target T, notice func(format string, args ...any)) error) error {
	notices := make([][]string, len(order))
	err := parallel.EachLimit(order, limit, func(i int, p string) error {
		notice := func(format string, args ...any) {
			notices[i] = append(notices[i], renderNotice(format, args...))
		}
		for _, target := range groups[p] {
			if err := run(target, notice); err != nil {
				return err
			}
		}
		return nil
	})
	for _, group := range notices {
		for _, n := range group {
			_, _ = os.Stderr.WriteString(n)
		}
	}
	return err
}
