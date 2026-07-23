package cli

import (
	"reflect"
	"testing"
)

// dedupeExportPaths must collapse true ancestor/descendant pairs and exact
// duplicates while leaving every other path in place.
func TestDedupeExportPaths_Subsumption(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "child subsumed by parent",
			in:   []string{"secret/bosh/uaa", "secret/bosh/uaa/clients/hm"},
			want: []string{"secret/bosh/uaa"},
		},
		{
			name: "grandchild subsumed by grandparent",
			in:   []string{"secret/bosh", "secret/bosh/uaa/clients/hm"},
			want: []string{"secret/bosh"},
		},
		{
			name: "exact duplicate removed",
			in:   []string{"secret/bosh/nats", "secret/bosh/nats"},
			want: []string{"secret/bosh/nats"},
		},
		{
			name: "unrelated paths preserved and sorted",
			in:   []string{"secret/exodus", "secret/bosh"},
			want: []string{"secret/bosh", "secret/exodus"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := dedupeExportPaths(append([]string{}, tc.in...))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("dedupeExportPaths(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
