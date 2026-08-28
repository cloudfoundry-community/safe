package cli

// groupByCanonicalPath decides which targets share one sequential
// read-modify-write group and which may run concurrently, so its two
// promises are pinned here directly: targets whose raw arguments spell the
// same secret differently (extra slashes, a :key suffix) land in one group,
// and groups come back in the order their paths first appeared on the
// command line, which is what drives notice replay.

import (
	"reflect"
	"testing"
)

func TestGroupByCanonicalPathCanonicalizes(t *testing.T) {
	args := []string{"secret/b", "secret//x:a", "secret/x", "secret/b:key"}
	order, groups := groupByCanonicalPath(args, func(s string) string { return s })

	wantOrder := []string{"secret/b", "secret/x"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %v, want %v", order, wantOrder)
	}
	if got, want := groups["secret/b"], []string{"secret/b", "secret/b:key"}; !reflect.DeepEqual(got, want) {
		t.Errorf("group secret/b = %v, want %v", got, want)
	}
	if got, want := groups["secret/x"], []string{"secret//x:a", "secret/x"}; !reflect.DeepEqual(got, want) {
		t.Errorf("group secret/x = %v, want %v", got, want)
	}
}

func TestGroupByCanonicalPathKeepsFirstAppearanceOrder(t *testing.T) {
	type target struct{ path, key string }
	targets := []target{
		{"secret/c", "one"},
		{"secret/a", "two"},
		{"secret/c", "three"},
		{"secret/b", "four"},
		{"secret/a", "five"},
	}
	order, groups := groupByCanonicalPath(targets, func(t target) string { return t.path })

	wantOrder := []string{"secret/c", "secret/a", "secret/b"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %v, want %v", order, wantOrder)
	}
	if got := len(groups); got != 3 {
		t.Fatalf("got %d groups, want 3", got)
	}
	// Within a group, targets keep argument order: key one before three,
	// two before five.
	if got, want := groups["secret/c"], []target{{"secret/c", "one"}, {"secret/c", "three"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("group secret/c = %v, want %v", got, want)
	}
	if got, want := groups["secret/a"], []target{{"secret/a", "two"}, {"secret/a", "five"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("group secret/a = %v, want %v", got, want)
	}
}
