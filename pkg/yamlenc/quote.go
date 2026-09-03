// pkg/yamlenc/quote.go
package yamlenc

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/token"
)

// quoter is the ast.Visitor Marshal runs over the encoded tree. The
// library has already double-quoted the strings its own rule catches, and
// those arrive with the quotes baked into the node text, so a value that
// starts with a quote is left alone. Every other plain string that
// needsQuote is switched to the double-quoted style, which the printer
// renders with strconv.Quote: a valid YAML double-quoted scalar that any
// YAML 1.1 or 1.2 reader returns unchanged.
type quoter struct{}

func (q quoter) Visit(n ast.Node) ast.Visitor {
	if s, ok := n.(*ast.StringNode); ok && !strings.HasPrefix(s.Value, `"`) && needsQuote(s.Value) {
		s.Token.Type = token.DoubleQuoteType
	}
	return q
}

// reserved holds the scalars YAML 1.1 and 1.2 resolve to null or bool. The
// lookup is case-insensitive.
var reserved = map[string]bool{
	"": true, "~": true, "null": true,
	"true": true, "false": true,
	"yes": true, "no": true, "on": true, "off": true, "y": true, "n": true,
}

// numeric matches anything a YAML 1.1 or 1.2 core-schema resolver reads as
// an integer or float: binary, octal (both 0o17 and 017), hex, decimal with
// underscores, sexagesimal (1:30), floats with or without an exponent, bare
// exponents (1e3), and .inf and .nan in their three spellings.
var numeric = regexp.MustCompile(`^[-+]?(` +
	`0b[01_]+|0o?[0-7_]+|0x[0-9a-fA-F_]+|[0-9][0-9_]*(:[0-5]?[0-9])*` +
	`|([0-9][0-9_]*)?\.[0-9_]*([eE][-+]?[0-9]+)?` +
	`|[0-9][0-9_]*[eE][-+]?[0-9]+` +
	`|\.(inf|Inf|INF|nan|NaN|NAN)` +
	`)$`)

// timestamp matches the start of a YAML 1.1 timestamp, which is enough to
// force quoting for dates and date-times.
var timestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}`)

// needsQuote reports whether s must be written as a double-quoted scalar to
// come back as the same string from any YAML reader.
//
// Several branches exist because goccy/go-yaml v1.19.2 writes these values
// wrongly on its own: a string starting with "? " is emitted as a plain
// scalar no parser accepts; ".inf" and ".nan" are emitted unquoted and
// read back as floats, and "1e3" is emitted unquoted and reads as a float
// under the YAML 1.2 core schema; carriage returns and tabs inside a plain
// scalar are lost (goccy/go-yaml#781 covers the \r case); and a value that
// is nothing but newlines is emitted as an empty literal block and decodes
// as "" (goccy/go-yaml#872 is the parse-side counterpart). Values ending
// in two or more newlines are also quoted, conservatively, so no reader
// has to honor a keep-chomping indicator. The remaining branches match
// the conservative rules go.yaml.in/yaml/v2 applied, so existing output
// stays plain wherever it was plain before; the leading ":" rule also
// sidesteps goccy/go-yaml#837.
func needsQuote(s string) bool {
	if reserved[strings.ToLower(s)] || numeric.MatchString(s) || timestamp.MatchString(s) {
		return true
	}
	for _, r := range s {
		if r == '\n' {
			continue
		}
		if r < 0x20 || r == 0x7f || unicode.Is(unicode.C, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return true
		}
	}
	if strings.ContainsRune(s, '\n') {
		// Multi-line values become a literal block, which is fine unless
		// the block would be only newlines, start with one, or end in two
		// or more, the shapes goccy's chomping indicator gets wrong.
		return strings.Trim(s, "\n") == "" || strings.HasPrefix(s, "\n") || strings.HasSuffix(s, "\n\n")
	}
	if s != strings.TrimSpace(s) {
		return true
	}
	switch s[0] {
	case ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`':
		return true
	case '-', '?', ':':
		if len(s) == 1 || s[1] == ' ' {
			return true
		}
	}
	return strings.Contains(s, ": ") || strings.Contains(s, " #") ||
		strings.HasSuffix(s, ":") ||
		strings.HasPrefix(s, "---") || strings.HasPrefix(s, "...")
}
