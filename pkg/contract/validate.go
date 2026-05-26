package contract

import (
	"path"
	"strings"
)

// MatchAction checks if an action matches a glob pattern according to the v4.0 spec.
//
// Rules:
// 1. Protocol prefixes (http://, https://) are stripped from both pattern and action.
// 2. '*' matches any characters within a single path segment (not across /).
// 3. A trailing '*' extends to cover the rest of the path.
// 4. If there are no wildcards, an exact match is required.
// 5. Hostnames and paths are normalized to prevent relative path traversal bypasses.
func MatchAction(pattern, action string) bool {
	pattern = cleanActionOrPattern(pattern)
	action = cleanActionOrPattern(action)

	// No wildcards -> exact match
	if !strings.Contains(pattern, "*") {
		return pattern == action
	}

	// Split by '/' to analyze segment by segment
	pSegments := strings.Split(pattern, "/")
	aSegments := strings.Split(action, "/")

	hasTrailingWildcard := strings.HasSuffix(pattern, "*")

	if hasTrailingWildcard {
		// E.g. pattern "a/*" (last segment is "*") matches "a" (parent directory)
		if len(aSegments) == len(pSegments)-1 && pSegments[len(pSegments)-1] == "*" {
			for i := 0; i < len(aSegments); i++ {
				if !matchSegment(pSegments[i], aSegments[i]) {
					return false
				}
			}
			return true
		}

		// If it's a trailing wildcard, action must have at least as many segments as pattern
		if len(aSegments) < len(pSegments) {
			return false
		}

		// Match all segments up to the second-to-last segment
		for i := 0; i < len(pSegments)-1; i++ {
			if !matchSegment(pSegments[i], aSegments[i]) {
				return false
			}
		}

		// The last segment of pattern contains the trailing '*'.
		// E.g. "pulls*" or "*".
		lastPatternSeg := pSegments[len(pSegments)-1]
		lastActionSeg := aSegments[len(pSegments)-1]
		matched, err := path.Match(lastPatternSeg, lastActionSeg)
		return err == nil && matched
	}

	// No trailing wildcard -> segments must be exactly equal in number
	if len(pSegments) != len(aSegments) {
		return false
	}

	for i := 0; i < len(pSegments); i++ {
		if !matchSegment(pSegments[i], aSegments[i]) {
			return false
		}
	}

	return true
}

// IsActionAllowed checks if the requested action is permitted by the allow list.
func IsActionAllowed(allowedPatterns []string, action string) bool {
	for _, pattern := range allowedPatterns {
		if MatchAction(pattern, action) {
			return true
		}
	}
	return false
}

func stripProtocol(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return s
}

func cleanActionOrPattern(s string) string {
	s = stripProtocol(s)
	idx := strings.Index(s, "/")
	if idx == -1 {
		return s
	}
	host := s[:idx]
	pathPart := s[idx:]
	cleanedPath := path.Clean(pathPart)
	return host + cleanedPath
}

func matchSegment(patternSeg, actionSeg string) bool {
	matched, err := path.Match(patternSeg, actionSeg)
	return err == nil && matched
}
