// pkg/yamlenc/yamlenc.go

// Package yamlenc is the one place safe encodes and decodes YAML. Every
// yaml.Marshal or yaml.Unmarshal in the module goes through here so the
// encoder options, and the workarounds for the underlying library, live in
// a single file.
package yamlenc

import (
	"io"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/printer"
)

// Marshal renders v as YAML. The value is encoded with the library's own
// rules first, then the tree is walked and every plain string that
// needsQuote is switched to the double-quoted style; see needsQuote for the
// rule and the upstream issues it works around. Encoding natively and
// editing the tree, rather than registering a CustomMarshaler, keeps
// literal blocks at their correct indentation: a CustomMarshaler's bytes
// are re-parsed as a standalone document, and a nested literal block then
// carries that document's indent on top of its real one.
func Marshal(v any) ([]byte, error) {
	node, err := yaml.NewEncoder(io.Discard).EncodeToNode(v)
	if err != nil {
		return nil, err
	}
	ast.Walk(quoter{}, node)
	var p printer.Printer
	return p.PrintNode(node), nil
}

// Unmarshal decodes data into v with the library defaults: unknown fields
// are ignored, and YAML 1.2 scalar rules apply. Note that the YAML 1.1
// boolean spellings yes, no, on, off, y, and n are strings under 1.2 and
// fail to decode into a bool field.
func Unmarshal(data []byte, v any) error {
	return yaml.Unmarshal(data, v)
}

// ErrorMessage returns the one-line message for a decode error. The
// library's default Error() appends a source excerpt with the offending
// line and its neighbors, which for ~/.saferc can include a token. Callers
// that print parse errors to a terminal use this instead.
func ErrorMessage(err error) string {
	return yaml.FormatError(err, false, false)
}
