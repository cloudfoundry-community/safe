// pkg/yamlenc/order.go
package yamlenc

import (
	"reflect"
	"sort"
	"strings"
	"unicode"

	"github.com/goccy/go-yaml/ast"
)

// reorder walks the encoded tree beside the Go value it was built from and
// sorts every mapping that came from a Go map the way go.yaml.in/yaml/v2
// sorted map keys (see keyLess). goccy sorts map keys as plain strings,
// which moves key10 ahead of key2 and Alpha ahead of _under; the vaults in
// ~/.saferc and the paths and keys in safe get output must keep the old
// order. Struct fields already print in declaration order, so structs are
// only descended into. Any shape the walk does not recognize is left as
// the encoder built it.
func reorder(n ast.Node, v reflect.Value) {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Map:
		m, ok := n.(*ast.MappingNode)
		if !ok || v.Type().Key().Kind() != reflect.String || len(m.Values) != v.Len() {
			return
		}
		// The encoder emitted the entries in plain string order of their
		// keys, so sorting the keys the same way pairs each key with its
		// node without reading the node text.
		keys := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		type entry struct {
			key  string
			node *ast.MappingValueNode
		}
		entries := make([]entry, len(keys))
		for i, k := range keys {
			entries[i] = entry{k, m.Values[i]}
			reorder(m.Values[i].Value, v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key())))
		}
		sort.SliceStable(entries, func(i, j int) bool { return keyLess(entries[i].key, entries[j].key) })
		for i := range entries {
			m.Values[i] = entries[i].node
		}
	case reflect.Struct:
		m, ok := n.(*ast.MappingNode)
		if !ok {
			return
		}
		fields := make(map[string]reflect.Value, v.NumField())
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			fields[name] = v.Field(i)
		}
		for _, mv := range m.Values {
			if fv, ok := fields[keyText(mv.Key)]; ok {
				reorder(mv.Value, fv)
			}
		}
	case reflect.Slice, reflect.Array:
		s, ok := n.(*ast.SequenceNode)
		if !ok || len(s.Values) != v.Len() {
			return
		}
		for i, e := range s.Values {
			reorder(e, v.Index(i))
		}
	}
}

func keyText(k ast.MapKeyNode) string {
	if s, ok := k.(*ast.StringNode); ok {
		return s.Value
	}
	return k.String()
}

// keyLess is the string branch of go.yaml.in/yaml/v2's key sorter, kept
// verbatim so ~/.saferc and safe get output sort as they always have:
// non-letters sort before letters, runs of digits compare by value (with a
// leading zero breaking ties toward the shorter run), and everything else
// compares rune by rune.
func keyLess(a, b string) bool {
	ar, br := []rune(a), []rune(b)
	for i := 0; i < len(ar) && i < len(br); i++ {
		if ar[i] == br[i] {
			continue
		}
		al := unicode.IsLetter(ar[i])
		bl := unicode.IsLetter(br[i])
		if al && bl {
			return ar[i] < br[i]
		}
		if al || bl {
			return bl
		}
		var ai, bi int
		var an, bn int64
		if ar[i] == '0' || br[i] == '0' {
			for j := i - 1; j >= 0 && unicode.IsDigit(ar[j]); j-- {
				if ar[j] != '0' {
					an = 1
					bn = 1
					break
				}
			}
		}
		for ai = i; ai < len(ar) && unicode.IsDigit(ar[ai]); ai++ {
			an = an*10 + int64(ar[ai]-'0')
		}
		for bi = i; bi < len(br) && unicode.IsDigit(br[bi]); bi++ {
			bn = bn*10 + int64(br[bi]-'0')
		}
		if an != bn {
			return an < bn
		}
		if ai != bi {
			return ai < bi
		}
		return ar[i] < br[i]
	}
	return len(ar) < len(br)
}
