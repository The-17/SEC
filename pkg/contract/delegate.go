package contract

import (
	"fmt"
	"strings"
)

// IsPatternSubset checks if a child allow pattern is a strict subset of a parent allow pattern.
func IsPatternSubset(child, parent string) bool {
	childVerb, childPat := splitVerbAndPattern(child)
	parentVerb, parentPat := splitVerbAndPattern(parent)

	// If parent specifies a verb, child must specify the same verb
	if parentVerb != "" {
		if childVerb == "" || childVerb != parentVerb {
			return false
		}
	}

	// Normalise patterns
	childPat = strings.TrimSpace(childPat)
	parentPat = strings.TrimSpace(parentPat)

	// Use a unique placeholder to represent the wildcard character
	// to verify if parent pattern covers the child pattern structure.
	const placeholder = "x_delegation_wildcard_placeholder_x"
	childPatWithPlaceholder := strings.ReplaceAll(childPat, "*", placeholder)

	return MatchAction(parentPat, childPatWithPlaceholder)
}

// ValidateDelegation checks that a child contract is a valid delegation of the parent.
func ValidateDelegation(parent, child SECContract) error {
	// 1. Expiration linkage
	if child.EXP > parent.EXP {
		return fmt.Errorf("delegation error: child expiration (%d) cannot exceed parent expiration (%d)", child.EXP, parent.EXP)
	}

	// 2. Parent JTI linkage
	if child.ParentJTI != parent.JTI {
		return fmt.Errorf("delegation error: child parent_jti (%q) must match parent JTI (%q)", child.ParentJTI, parent.JTI)
	}

	// 3. Max depth enforcement
	if parent.MaxDepth != nil {
		if *parent.MaxDepth <= 0 {
			return fmt.Errorf("delegation error: parent max_depth is 0, no further delegation allowed")
		}
		if child.MaxDepth == nil {
			return fmt.Errorf("delegation error: child must specify max_depth since parent has a depth limit")
		}
		if *child.MaxDepth > *parent.MaxDepth-1 {
			return fmt.Errorf("delegation error: child max_depth (%d) cannot exceed parent max_depth - 1 (%d)", *child.MaxDepth, *parent.MaxDepth-1)
		}
	}

	// 4. Subset enforcement
	for _, childPattern := range child.Allowed {
		matched := false
		for _, parentPattern := range parent.Allowed {
			if IsPatternSubset(childPattern, parentPattern) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("delegation error: child allow pattern %q is not covered by any parent allow pattern", childPattern)
		}
	}

	return nil
}
