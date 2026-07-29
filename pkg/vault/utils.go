package vault

import (
	"regexp"
	"strconv"
	"strings"
)

var canonicalizeSlashRe = regexp.MustCompile("//+")

// lastUnescapedIndex returns the index of the last unescaped occurrence of sep
// in s, or -1 if there is none. It scans left to right, skipping the character
// after every backslash, so that a backslash which is itself escaped is not
// mistaken for one that escapes sep. Index 0 never counts: a separator needs
// something in front of it to separate.
func lastUnescapedIndex(s string, sep byte) int {
	last := -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ //whatever follows is escaped, and cannot be a separator
		case sep:
			if i > 0 {
				last = i
			}
		}
	}
	return last
}

// unescapePathSegment reverses EscapePathSegment. Only the characters that
// EscapePathSegment escapes are unescaped; a backslash in front of anything
// else was never an escape, so both characters are kept. A trailing backslash
// has nothing to escape and is likewise literal, which is what a user gets by
// typing a raw Vault path that ends in one.
func unescapePathSegment(segment string) string {
	if !strings.Contains(segment, `\`) {
		return segment
	}

	var out strings.Builder
	out.Grow(len(segment))
	for i := 0; i < len(segment); i++ {
		if segment[i] == '\\' && i+1 < len(segment) {
			switch segment[i+1] {
			case '\\', ':', '^':
				i++
			}
		}
		out.WriteByte(segment[i])
	}

	return out.String()
}

// ParsePath splits the given path string into its respective secret path
// and contained key parts
func ParsePath(path string) (secret, key string, version uint64) {
	secret = path

	if caret := lastUnescapedIndex(path, '^'); caret >= 0 {
		if v, err := strconv.ParseUint(path[caret+1:], 10, 64); err == nil {
			version = v
			path = path[:caret]
			secret = path
		}
	}

	if colon := lastUnescapedIndex(path, ':'); colon >= 0 {
		key = path[colon+1:]
		secret = path[:colon]
	}

	secret = unescapePathSegment(secret)
	key = unescapePathSegment(key)

	secret = Canonicalize(secret)
	return
}

// EscapePathSegment is the reverse of ParsePath for an output secret or key
// segment; whereas that function unescapes colons and carets, this function
// reescapes them so that they can be run through that function again.
//
// The backslash is escaped first, and for the same reason: a Vault path is an
// arbitrary string, so a name may end in one, and leaving it bare would make
// the separator appended after it look escaped.
func EscapePathSegment(segment string) string {
	segment = strings.ReplaceAll(segment, `\`, `\\`)
	segment = strings.ReplaceAll(segment, ":", `\:`)
	segment = strings.ReplaceAll(segment, "^", `\^`)
	return segment
}

// EncodePath creates a safe-friendly canonical path for the given arguments
func EncodePath(path, key string, version uint64) string {
	path = EscapePathSegment(path)
	if key != "" {
		key = EscapePathSegment(key)
		path += ":" + key
	}

	if version != 0 {
		path += "^" + strconv.FormatUint(version, 10)
	}

	return path
}

// PathHasKey returns true if the given path has a key specified in its syntax.
// False otherwise.
func PathHasKey(path string) bool {
	_, key, _ := ParsePath(path)
	return key != ""
}

// PathHasVersion returns true if the given path has a version specified in its
// syntax.
// False otherwise.
func PathHasVersion(path string) bool {
	_, _, version := ParsePath(path)
	return version != 0
}

func Canonicalize(p string) string {
	p = strings.TrimSuffix(p, "/")
	p = strings.TrimPrefix(p, "/")

	p = canonicalizeSlashRe.ReplaceAllString(p, "/")

	return p
}
