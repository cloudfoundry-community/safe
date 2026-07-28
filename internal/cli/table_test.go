package cli

import (
	"strings"
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

// TestTableAddRowRendersMarkup verifies that go-ansi markup handed to addRow as
// cell content is rendered rather than passed through verbatim.
//
// go-ansi only interprets markup appearing in the format string, and
// ansiColorRegexp only matches already-rendered escape sequences. A cell holding
// an unrendered "@G{...}" template therefore survives _stripColor untouched and
// reaches stdout literally.
//
// Assertions are written to hold whether or not stdout is colorized: the cell's
// display width must equal the visible text, and stripping it must yield the
// visible text exactly.
func TestTableAddRowRendersMarkup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cell string
		want string
	}{
		{name: "green markup", cell: "@G{alive}", want: "alive"},
		{name: "red markup", cell: "@R{destroyed}", want: "destroyed"},
		{name: "yellow markup", cell: "@Y{deleted}", want: "deleted"},
		{name: "plain text is unchanged", cell: "unknown", want: "unknown"},
		{name: "markup surrounded by text", cell: "pre @C{mid} post", want: "pre mid post"},
		{name: "two markup runs in one cell", cell: "@G{a}/@R{b}", want: "a/b"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tbl := &table{}
			tbl.addRow(tc.cell)

			got := tbl.rows[0][0]
			if strings.Contains(got, "@") {
				t.Errorf("addRow(%q): stored %q, which still contains unrendered markup", tc.cell, got)
			}
			if stripped := tbl._stripColor(got); stripped != tc.want {
				t.Errorf("addRow(%q): stripped to %q, want %q", tc.cell, stripped, tc.want)
			}
			if width := tbl._calcDisplayWidth(got); width != len(tc.want) {
				t.Errorf("addRow(%q): display width %d, want %d (column alignment depends on this)",
					tc.cell, width, len(tc.want))
			}
		})
	}
}

// TestTableAddRowPreservesPercent verifies that cell content is not treated as a
// format string. Rendering a cell requires handing it to go-ansi as a format,
// so any '%' it contains must be escaped first or it is consumed as a verb.
func TestTableAddRowPreservesPercent(t *testing.T) {
	t.Parallel()

	cases := []string{
		"100%done",
		"%",
		"%s",
		"%d%%",
		"50% off",
	}

	for _, cell := range cases {
		cell := cell
		t.Run(cell, func(t *testing.T) {
			t.Parallel()
			tbl := &table{}
			tbl.addRow(cell)

			if got := tbl._stripColor(tbl.rows[0][0]); got != cell {
				t.Errorf("addRow(%q): stored %q, want the input preserved verbatim", cell, got)
			}
		})
	}
}

// TestTableAddRowRendersMarkupWithPercent covers the interaction of the two
// fixes above in a single cell.
func TestTableAddRowRendersMarkupWithPercent(t *testing.T) {
	t.Parallel()

	tbl := &table{}
	tbl.addRow("@G{100%done}")

	got := tbl.rows[0][0]
	if strings.Contains(got, "@") {
		t.Errorf("stored %q, which still contains unrendered markup", got)
	}
	if stripped := tbl._stripColor(got); stripped != "100%done" {
		t.Errorf("stripped to %q, want %q", stripped, "100%done")
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
