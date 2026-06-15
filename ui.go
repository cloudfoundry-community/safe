package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/cloudfoundry-community/safe/prompt"
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
	if !ansi.ShouldColorize(os.Stdout) {
		for i := range cols {
			cols[i] = t._stripColor(cols[i])
		}
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
	for i := 0; i < len(ret); i++ {
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
	for idx := 0; idx < spaces; idx++ {
		spaceBuf[idx] = ' '
	}

	_, _ = os.Stdout.Write(spaceBuf)
}

func (t *table) _sprintf(f string, args ...interface{}) string {
	ret := ansi.Sprintf(f, args...)
	if !ansi.ShouldColorize(os.Stdout) {
		ret = t._stripColor(ret)
	}
	return ret
}

func (t *table) _stripColor(s string) string {
	return ansiColorRegexp.ReplaceAllString(s, "")
}
