package cli

import (
	"testing"
)

// TestCalcDisplayWidth covers the ANSI-escape state machine in table._calcDisplayWidth.
// Inputs span: plain ASCII, single-param SGR (e.g. \033[32m), multi-param SGR
// (e.g. \033[1;32m), reset (\033[0m), and combinations.
func TestCalcDisplayWidth(t *testing.T) {
	t.Parallel()
	tbl := &table{}

	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "empty string",
			input: "",
			want:  0,
		},
		{
			name:  "plain ASCII no escapes",
			input: "hello",
			want:  5,
		},
		{
			name:  "single space",
			input: " ",
			want:  1,
		},
		{
			name:  "plain with spaces",
			input: "hello world",
			want:  11,
		},
		{
			// go-ansi green: \033[32m text \033[0m
			name:  "single SGR escape wrapping text",
			input: "\033[32mgreen\033[0m",
			want:  5,
		},
		{
			// bold: \033[1m
			name:  "bold SGR wrapping text",
			input: "\033[1mbold\033[0m",
			want:  4,
		},
		{
			// multi-param: \033[1;32m (bold + green)
			name:  "multi-param SGR",
			input: "\033[1;32mbold-green\033[0m",
			want:  10,
		},
		{
			// reset only: \033[0m followed by text
			name:  "reset then text",
			input: "\033[0mplain",
			want:  5,
		},
		{
			// escape with no text
			name:  "escape with no visible text",
			input: "\033[32m\033[0m",
			want:  0,
		},
		{
			// text on both sides of an escape
			name:  "text around escape",
			input: "ab\033[32mcd\033[0mef",
			want:  6,
		},
		{
			// longer string typical of table column output
			name:  "multi-word colored",
			input: "\033[33myellow text here\033[0m",
			want:  16,
		},
		{
			// digits in the middle are visible
			name:  "digits are graphic",
			input: "123",
			want:  3,
		},
		{
			// punctuation counts
			name:  "punctuation counts as graphic",
			input: "a:b/c",
			want:  5,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tbl._calcDisplayWidth(tc.input)
			if got != tc.want {
				t.Errorf("_calcDisplayWidth(%q): got %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestCalcDisplayWidth_MultiParamSGR_Extended covers the regex-defined boundary
// of the ANSI state machine with three-param SGR sequences. The state machine
// exits on the first 'm' it encounters, so the middle params must not be
// counted as visible characters.
func TestCalcDisplayWidth_MultiParamSGR_Extended(t *testing.T) {
	t.Parallel()
	tbl := &table{}

	// \033[38;5;200m is a 256-color foreground — three params separated by ';'.
	// The state machine only exits on 'm', so visible chars must be 0 for the escape.
	input := "\033[38;5;200mfoo\033[0m"
	got := tbl._calcDisplayWidth(input)
	if got != 3 {
		t.Errorf("_calcDisplayWidth(%q): got %d, want 3 (only 'foo' is visible)", input, got)
	}
}

// TestTableStripColor verifies _stripColor removes ANSI SGR codes.
func TestTableStripColor(t *testing.T) {
	t.Parallel()
	tbl := &table{}

	cases := []struct {
		input string
		want  string
	}{
		{"\033[32mgreen\033[0m", "green"},
		{"\033[1;32mbold-green\033[0m", "bold-green"},
		{"plain", "plain"},
		{"", ""},
		{"\033[0m\033[1m\033[32m", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := tbl._stripColor(tc.input)
			if got != tc.want {
				t.Errorf("_stripColor(%q): got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestTableGetNumCols verifies _getNumCols returns 0 for an empty table,
// then reflects headers or the first row length.
func TestTableGetNumCols(t *testing.T) {
	t.Parallel()

	t.Run("empty table returns zero", func(t *testing.T) {
		t.Parallel()
		tbl := &table{}
		if got := tbl._getNumCols(); got != 0 {
			t.Errorf("_getNumCols(): got %d, want 0", got)
		}
	})

	t.Run("returns header count when set", func(t *testing.T) {
		t.Parallel()
		tbl := &table{}
		tbl.setHeader("A", "B", "C")
		if got := tbl._getNumCols(); got != 3 {
			t.Errorf("_getNumCols(): got %d, want 3", got)
		}
	})

	t.Run("returns first row width when no headers", func(t *testing.T) {
		t.Parallel()
		tbl := &table{}
		tbl.addRow("x", "y")
		if got := tbl._getNumCols(); got != 2 {
			t.Errorf("_getNumCols(): got %d, want 2", got)
		}
	})
}

// TestTableAssertValidRowWidth verifies that panics occur for zero-col and
// inconsistent-col rows.
func TestTableAssertValidRowWidth_PanicsOnZeroCols(t *testing.T) {
	t.Parallel()
	tbl := &table{}
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for zero-column row, got none")
		}
	}()
	tbl._assertValidRowWidth(0)
}

func TestTableAssertValidRowWidth_PanicsOnMismatch(t *testing.T) {
	t.Parallel()
	tbl := &table{}
	tbl.addRow("a", "b") // establishes 2-column schema
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for column-count mismatch, got none")
		}
	}()
	tbl.addRow("x") // 1 column — should panic
}
