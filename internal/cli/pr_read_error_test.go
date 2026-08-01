package cli

// pr() must surface a read error rather than swallowing it and returning an
// empty string. A terminal read failure that reads as "" is indistinguishable
// from an empty value, and in the confirm loop it spins forever.

import (
	"fmt"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("simulated read failure")
}

func TestPrSurfacesReadError(t *testing.T) {
	prompt.SetReader(failingReader{})
	t.Cleanup(func() { prompt.SetReader(nil) })

	if _, err := pr("value", false, true); err == nil {
		t.Fatal("pr must surface a read error, not return an empty string")
	}
}
