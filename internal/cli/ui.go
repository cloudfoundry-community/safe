package cli

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
	"github.com/cloudfoundry-community/safe/pkg/vault"
	"github.com/jhunt/go-ansi"
)

var ansiColorRegexp = regexp.MustCompile("\033\\[\\d+(;\\d+)?m")

func parseKeyVal(key string, quiet bool) (string, string, bool, error) {
	if strings.Contains(key, "=") {
		l := strings.SplitN(key, "=", 2)
		if l[1] == "" {
			return l[0], "", false, nil
		}
		if !quiet {
			_, _ = ansi.Fprintf(os.Stderr, "%s: @G{%s}\n", l[0], l[1])
		}
		return l[0], l[1], false, nil
	} else if strings.Contains(key, "@") {
		l := strings.SplitN(key, "@", 2)
		if l[1] == "" {
			return l[0], "", true, fmt.Errorf("no file specified: expecting %s@<filename>", l[0])
		}

		if l[1] == "-" {
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return l[0], "", true, fmt.Errorf("failed to read from standard input: %s", err)
			}
			if !quiet {
				_, _ = ansi.Fprintf(os.Stderr, "%s: <@M{$stdin}\n", l[0])
			}
			return l[0], string(b), false, nil
		}

		b, err := os.ReadFile(l[1]) // #nosec G703 - user intentionally supplies file path via key@file CLI syntax
		if err != nil {
			return l[0], "", true, fmt.Errorf("failed to read contents of %s: %s", l[1], err)
		}
		if !quiet {
			_, _ = ansi.Fprintf(os.Stderr, "%s: <@C{%s}\n", l[0], l[1])
		}
		return l[0], string(b), false, nil
	}
	return key, "", true, nil
}

// expandValueArg resolves the @-prefix conventions for `safe values`
// positional arguments: "@-" reads all of standard input, "@FILE" reads
// FILE, and a "@@" prefix escapes a literal leading '@'. Anything else is
// returned unchanged. File and stdin content is used verbatim (no newline
// trimming), matching what `safe set key@FILE` would have stored. Unlike
// parseKeyVal, nothing is echoed to stderr: the resolved values are search
// targets the user may consider sensitive.
func expandValueArg(arg string) (string, error) {
	switch {
	case arg == "@":
		return "", fmt.Errorf("no file specified: expecting @<filename>")
	case strings.HasPrefix(arg, "@@"):
		return arg[1:], nil
	case arg == "@-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read from standard input: %s", err)
		}
		return string(b), nil
	case strings.HasPrefix(arg, "@"):
		b, err := os.ReadFile(arg[1:]) // #nosec G703 - user intentionally supplies file path via @file CLI syntax
		if err != nil {
			return "", fmt.Errorf("failed to read contents of %s: %s", arg[1:], err)
		}
		return string(b), nil
	}
	return arg, nil
}

// assertWritablePath refuses a path naming a key or a version, using the same
// wording Vault.Write does. The commands that write a whole secret cannot
// honour either, and checking here rather than at the write means the
// complaint arrives before a value is prompted for or key material is
// generated, instead of after the work is thrown away.
func assertWritablePath(path string) error {
	if vault.PathHasKey(path) {
		return fmt.Errorf("cannot write to paths in /path:key notation (%s)", path)
	}
	return assertWritableKeyPath(path)
}

// assertWritableKeyPath refuses a path naming a version, for the commands that
// do accept a key. gen and uuid take one because it names the key they are
// about to create, but a version names a revision that already exists, and
// there is no writing to that, so naming one is a mistake rather than
// something to drop on the floor.
func assertWritableKeyPath(path string) error {
	if vault.PathHasVersion(path) {
		return fmt.Errorf("cannot write to paths in /path^version notation (%s)", path)
	}
	return nil
}

// assertWritablePaths applies assertWritablePath to each path, returning the
// first complaint. Empty paths are skipped, so an unset flag naming an
// optional destination costs nothing.
func assertWritablePaths(paths ...string) error {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := assertWritablePath(path); err != nil {
			return err
		}
	}
	return nil
}

func pr(label string, confirm bool, secure bool) string {
	if !confirm {
		if secure {
			return prompt.Secure("%s: ", label)
		}
		return prompt.Normal("%s: ", label)
	}

	for {
		a := prompt.Secure("%s @Y{[hidden]:} ", label)
		b := prompt.Secure("%s @C{[confirm]:} ", label)

		if a == b && a != "" {
			_, _ = ansi.Fprintf(os.Stderr, "\n")
			return a
		}
		_, _ = ansi.Fprintf(os.Stderr, "\n@Y{oops, try again }(Ctrl-C to cancel)\n\n")
	}
}

type table struct {
	headers []string
	rows    [][]string
}

func (t *table) setHeader(headers ...string) {
	t._assertValidRowWidth(len(headers))
	t.headers = headers
	t._formatHeaders()
}

func (t *table) addRow(cols ...string) {
	t._assertValidRowWidth(len(cols))
	for i := range cols {
		cols[i] = t._renderCell(cols[i])
	}
	t.rows = append(t.rows, cols)
}

func (t *table) print() {
	if t._getNumCols() == 0 {
		return
	}

	colWidths := t._calcColWidths()

	if len(t.headers) > 0 {
		t._printRow(t.headers, colWidths)
	}

	for rowNum := range t.rows {
		t._printRow(t.rows[rowNum], colWidths)
	}
}

func (t *table) _assertValidRowWidth(numCols int) {
	if numCols == 0 {
		panic("Cannot append row with zero columns")
	}

	existingCols := t._getNumCols()
	if existingCols != 0 && numCols != existingCols {
		panic("Number of columns in each row must be consistent")
	}

}

func (t *table) _getNumCols() int {
	if len(t.headers) != 0 {
		return len(t.headers)
	}
	if len(t.rows) != 0 {
		return len(t.rows[0])
	}
	return 0
}

func (t *table) _calcColWidths() []int {
	ret := make([]int, t._getNumCols())
	for i := range ret {
		ret[i] = t._calcColWidth(i)
	}

	return ret
}

func (t *table) _calcColWidth(colNum int) int {
	maxWidth := 0
	if len(t.headers) != 0 {
		maxWidth = t._calcDisplayWidth(t.headers[colNum])
	}

	for rowNum := range t.rows {
		cellWidth := t._calcDisplayWidth(t.rows[rowNum][colNum])
		if cellWidth > maxWidth {
			maxWidth = cellWidth
		}
	}

	return maxWidth
}

func (t *table) _calcDisplayWidth(cell string) int {
	const asciiEscapeStart = '\033'
	const asciiEscapeEnd = 'm'
	count := 0
	state := 0
	for _, c := range cell {
		switch state {
		case 0: //not ascii escape
			if c == asciiEscapeStart {
				state = 1
			} else if unicode.IsGraphic(c) {
				count++
			}

		case 1: //in ascii escape
			if c == asciiEscapeEnd {
				state = 0
			}
		}
	}

	return count
}

func (t *table) _formatHeaders() {
	for colNum := range t.headers {
		t.headers[colNum] = t._sprintf("@M{%s}", t.headers[colNum])
	}
}

func (t *table) _printRow(row []string, widths []int) {
	const colBuffer = 2 //two spaces min between cols
	//print every col except last, inserting buffer spaces
	for colNum := 0; colNum < len(row)-1; colNum++ {
		t._printCell(
			row[colNum],
			widths[colNum]+colBuffer-t._calcDisplayWidth(row[colNum]))
	}

	//no spaces at the end of the last col
	t._printCell(row[len(row)-1], 0)
	_, _ = os.Stdout.Write([]byte{'\n'})
}

func (t *table) _printCell(cell string, spaces int) {
	_, _ = os.Stdout.Write([]byte(cell))

	if spaces == 0 {
		return
	}

	spaceBuf := make([]byte, spaces)
	for idx := range spaces {
		spaceBuf[idx] = ' '
	}

	_, _ = os.Stdout.Write(spaceBuf)
}

// _renderCell interprets go-ansi markup in cell content. go-ansi only renders
// markup found in the format string, so the cell has to be passed as the format
// itself; any '%' it contains is escaped first so it is not consumed as a verb.
func (t *table) _renderCell(cell string) string {
	return t._sprintf(strings.ReplaceAll(cell, "%", "%%"))
}

func (t *table) _sprintf(f string, args ...any) string {
	ret := ansi.Sprintf(f, args...)
	if !ansi.ShouldColorize(os.Stdout) {
		ret = t._stripColor(ret)
	}
	return ret
}

func (t *table) _stripColor(s string) string {
	return ansiColorRegexp.ReplaceAllString(s, "")
}
