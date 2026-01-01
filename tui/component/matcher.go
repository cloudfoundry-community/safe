package component

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Matcher provides pattern matching for search
type Matcher struct {
	patternType SearchPatternType
	query       string
	regex       *regexp.Regexp
	err         error
}

// NewMatcher creates a matcher for the given pattern
func NewMatcher(query string, patternType SearchPatternType) *Matcher {
	m := &Matcher{
		patternType: patternType,
		query:       query,
	}

	if query == "" {
		return m
	}

	if patternType == SearchPatternRegex {
		// Compile regex, case-insensitive by default
		m.regex, m.err = regexp.Compile("(?i)" + query)
	}
	// For glob, no precompilation needed

	return m
}

// Match checks if the given path matches the pattern
// path format: "secret/database/creds" or "secret/database/creds:password"
func (m *Matcher) Match(path string) (bool, []Range) {
	if m.query == "" {
		return false, nil
	}

	if m.err != nil {
		return false, nil
	}

	if m.patternType == SearchPatternRegex {
		return m.matchRegex(path)
	}
	return m.matchGlob(path)
}

// matchRegex performs regex matching and returns match ranges
func (m *Matcher) matchRegex(path string) (bool, []Range) {
	if m.regex == nil {
		return false, nil
	}

	locs := m.regex.FindAllStringIndex(path, -1)
	if locs == nil {
		return false, nil
	}

	ranges := make([]Range, len(locs))
	for i, loc := range locs {
		ranges[i] = Range{Start: loc[0], End: loc[1]}
	}
	return true, ranges
}

// matchGlob performs glob pattern matching
func (m *Matcher) matchGlob(path string) (bool, []Range) {
	query := m.query

	// Handle ** for recursive matching
	// Convert ** to a regex-like pattern for matching
	if strings.Contains(query, "**") {
		return m.matchDoubleStarGlob(path, query)
	}

	// Try exact match on full path
	if matched, _ := filepath.Match(query, path); matched {
		return true, nil
	}

	// Try matching against the path without key
	pathWithoutKey := path
	keyPart := ""
	if idx := strings.LastIndex(path, ":"); idx >= 0 {
		pathWithoutKey = path[:idx]
		keyPart = path[idx+1:]
	}

	// Match full path without key
	if matched, _ := filepath.Match(query, pathWithoutKey); matched {
		return true, nil
	}

	// Match just the key part
	if keyPart != "" {
		if matched, _ := filepath.Match(query, keyPart); matched {
			return true, nil
		}
	}

	// Match against each path segment
	segments := strings.Split(pathWithoutKey, "/")
	for _, segment := range segments {
		if matched, _ := filepath.Match(query, segment); matched {
			return true, nil
		}
	}

	// Try substring match for simple patterns without wildcards
	if !strings.ContainsAny(query, "*?[]") {
		if strings.Contains(strings.ToLower(path), strings.ToLower(query)) {
			return true, nil
		}
	}

	return false, nil
}

// matchDoubleStarGlob handles ** glob patterns
func (m *Matcher) matchDoubleStarGlob(path, pattern string) (bool, []Range) {
	// Convert ** glob to regex
	// * matches anything except /
	// ** matches anything including /
	regexPattern := regexp.QuoteMeta(pattern)
	regexPattern = strings.ReplaceAll(regexPattern, `\*\*`, `.*`)
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `[^/]*`)
	regexPattern = strings.ReplaceAll(regexPattern, `\?`, `.`)

	// Make it case insensitive and anchor to match full segments
	re, err := regexp.Compile("(?i)" + regexPattern)
	if err != nil {
		return false, nil
	}

	if re.MatchString(path) {
		locs := re.FindAllStringIndex(path, -1)
		if locs != nil {
			ranges := make([]Range, len(locs))
			for i, loc := range locs {
				ranges[i] = Range{Start: loc[0], End: loc[1]}
			}
			return true, ranges
		}
		return true, nil
	}

	return false, nil
}

// Error returns any pattern compilation error
func (m *Matcher) Error() error {
	return m.err
}

// ErrorString returns the error as a string, or empty if no error
func (m *Matcher) ErrorString() string {
	if m.err != nil {
		return m.err.Error()
	}
	return ""
}

// AutoDetectType suggests pattern type based on the query
func AutoDetectType(query string) SearchPatternType {
	// Check for regex-specific characters that are rarely used in globs
	regexIndicators := []string{
		"^",   // Start anchor
		"$",   // End anchor
		"(",   // Group start
		")",   // Group end
		"+",   // One or more
		"|",   // Alternation
		"\\d", // Digit class
		"\\w", // Word class
		"\\s", // Space class
		"\\b", // Word boundary
		"{",   // Quantifier
		"}",   // Quantifier
		"(?",  // Non-capturing group or lookahead
		"[^",  // Negated character class
		".+",  // One or more of any
		".*",  // Zero or more of any (but this is common in globs too)
	}

	for _, indicator := range regexIndicators {
		if strings.Contains(query, indicator) {
			return SearchPatternRegex
		}
	}

	return SearchPatternGlob
}

// MatchNodes finds all matching node indices from a list of paths
func MatchNodes(paths []string, query string, patternType SearchPatternType) ([]int, string) {
	matcher := NewMatcher(query, patternType)
	if err := matcher.Error(); err != nil {
		return nil, matcher.ErrorString()
	}

	if query == "" {
		return nil, ""
	}

	matches := make([]int, 0)
	for i, path := range paths {
		if matched, _ := matcher.Match(path); matched {
			matches = append(matches, i)
		}
	}

	return matches, ""
}

// MatchPaths finds all matching paths from a list of paths
func MatchPaths(paths []string, query string, patternType SearchPatternType) ([]string, string) {
	matcher := NewMatcher(query, patternType)
	if err := matcher.Error(); err != nil {
		return nil, matcher.ErrorString()
	}

	if query == "" {
		return nil, ""
	}

	matches := make([]string, 0)
	for _, path := range paths {
		if matched, _ := matcher.Match(path); matched {
			matches = append(matches, path)
		}
	}

	return matches, ""
}
