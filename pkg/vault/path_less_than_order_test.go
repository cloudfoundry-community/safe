package vault

// PathLessThan is handed to sort.Slice in three places and to sort.Search in a
// fourth, all of which are entitled to a strict ordering. These tests check
// the properties that entitlement rests on, rather than individual pairs,
// which path_helpers_test.go already covers.

import (
	"math/rand"
	"sort"
	"testing"
)

// orderingSample covers the shapes the comparator distinguishes on: equal
// paths, prefixes, siblings, differing depths, and the leading and trailing
// slashes Canonicalize removes before comparing segments.
var orderingSample = []string{
	"",
	"secret",
	"secret/",
	"/secret",
	"secret/a",
	"secret/a/",
	"/secret/a",
	"secret/ab",
	"secret/a/x",
	"secret/a/y",
	"secret/b",
	"secret/b/x",
	"secret/z",
	"other/a",
}

// A path is never less than itself. sort.Slice with a comparator that says
// otherwise has no defined result.
func TestPathLessThanIsIrreflexive(t *testing.T) {
	for _, p := range orderingSample {
		if PathLessThan(p, p) {
			t.Errorf("PathLessThan(%q, %q) = true, want false", p, p)
		}
	}
}

// Two distinct paths cannot both be less than each other.
func TestPathLessThanIsAsymmetric(t *testing.T) {
	for _, left := range orderingSample {
		for _, right := range orderingSample {
			if PathLessThan(left, right) && PathLessThan(right, left) {
				t.Errorf("PathLessThan reports %q < %q and %q < %q", left, right, right, left)
			}
		}
	}
}

// Incomparability -- neither less than the other -- has to be transitive, or
// the ordering is not one sort can rely on.
func TestPathLessThanHasTransitiveEquivalence(t *testing.T) {
	same := func(a, b string) bool { return !PathLessThan(a, b) && !PathLessThan(b, a) }
	for _, a := range orderingSample {
		for _, b := range orderingSample {
			for _, c := range orderingSample {
				if same(a, b) && same(b, c) && !same(a, c) {
					t.Errorf("%q ~ %q and %q ~ %q but not %q ~ %q", a, b, b, c, a, c)
				}
			}
		}
	}
}

// Ordering is transitive.
func TestPathLessThanIsTransitive(t *testing.T) {
	for _, a := range orderingSample {
		for _, b := range orderingSample {
			for _, c := range orderingSample {
				if PathLessThan(a, b) && PathLessThan(b, c) && !PathLessThan(a, c) {
					t.Errorf("%q < %q < %q but not %q < %q", a, b, c, a, c)
				}
			}
		}
	}
}

// Sorting a list that repeats paths leaves it ordered. Duplicates are what
// reach the comparator in practice: dedupeExportPaths sorts a list it is
// about to collapse, and a tree walk over overlapping roots repeats paths.
func TestSortHandlesRepeatedPaths(t *testing.T) {
	for trial := range 2000 {
		r := rand.New(rand.NewSource(int64(trial)))
		list := make([]string, 2+r.Intn(12))
		for i := range list {
			list[i] = orderingSample[r.Intn(len(orderingSample))]
		}
		sort.Slice(list, func(i, j int) bool { return PathLessThan(list[i], list[j]) })
		for i := 0; i+1 < len(list); i++ {
			if PathLessThan(list[i+1], list[i]) {
				t.Fatalf("trial %d sorted to %v, but %q < %q", trial, list, list[i+1], list[i])
			}
		}
	}
}
