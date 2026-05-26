package contract

import (
	"fmt"
	"path"
	"strings"
)

// MatchCapability checks whether a glob pattern matches a dot-separated capability.
// It converts dots to slashes so that Go's path.Match can evaluate the glob properly.
//
// Supported patterns:
//   - Exact match:   "github.issues.read" matches "github.issues.read"
//   - Suffix glob:   "github.*" matches "github.issues" (single segment)
//   - Deep glob:     "github.**" is NOT supported; use multiple patterns
//   - Middle glob:   "github.*.read" matches "github.issues.read"
//   - Prefix glob:   "*.read" matches "issues.read" (single segment)
//   - Universal:     "*" matches any single-segment capability
//
// Note: path.Match treats '*' as matching any sequence of non-separator characters
// within a single path segment. This means "github.*" matches "github.issues" but
// NOT "github.issues.read". For hierarchical wildcard behavior, the caller should
// check if the pattern (minus trailing ".*") is a prefix of the capability.
func MatchCapability(pattern, capability string) bool {
	// Universal wildcard
	if pattern == "*" {
		return true
	}

	// Hierarchical prefix wildcard: "github.*" should match "github.issues.read"
	// This extends beyond path.Match single-segment behavior.
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*")
		if strings.HasPrefix(capability, prefix+".") || capability == prefix {
			return true
		}
	}

	// Standard glob matching via path.Match, converting dots to path separators
	patternPath := strings.ReplaceAll(pattern, ".", "/")
	capPath := strings.ReplaceAll(capability, ".", "/")

	matched, err := path.Match(patternPath, capPath)
	if err != nil {
		return false
	}
	return matched
}

// IsCapabilityAllowed evaluates whether a requested capability is permitted by
// the contract's allow list and deny list. Denies always take precedence.
//
// Evaluation order:
//  1. If the capability matches ANY deny pattern → blocked.
//  2. If the capability matches ANY allow pattern → permitted.
//  3. Otherwise → blocked (default deny).
func IsCapabilityAllowed(caps, denies []string, capability string) bool {
	// Denies take absolute precedence
	for _, deny := range denies {
		if MatchCapability(deny, capability) {
			return false
		}
	}

	// Check allow list
	for _, allow := range caps {
		if MatchCapability(allow, capability) {
			return true
		}
	}

	// Default deny
	return false
}

// ScopeValidator defines the interface for provider-specific resource validation.
// Custom runtimes can implement this to enforce complex resource rules (e.g., AWS
// ARN validation, Kubernetes namespace checks). The default implementation uses
// glob-based prefix matching.
type ScopeValidator interface {
	Validate(scopes map[string][]string, scopeKey string, resource string) error
}

// DefaultScopeValidator implements ScopeValidator with glob-based pattern matching.
// It checks whether the requested resource matches any of the allowed values for
// the given scope key.
type DefaultScopeValidator struct{}

// Validate checks if the resource is permitted under the given scope key.
// If the scope key does not exist in the contract, validation passes (the contract
// does not restrict that resource dimension). If the key exists, at least one of
// the allowed values must match the resource via glob pattern matching.
func (v *DefaultScopeValidator) Validate(scopes map[string][]string, scopeKey string, resource string) error {
	if scopes == nil {
		return nil
	}

	allowedValues, exists := scopes[scopeKey]
	if !exists {
		// Scope key not constrained by this contract
		return nil
	}

	for _, allowed := range allowedValues {
		// Exact match
		if allowed == resource {
			return nil
		}
		// Glob match
		matched, err := path.Match(allowed, resource)
		if err == nil && matched {
			return nil
		}
		// Prefix match (for hierarchical resources like "org/repo")
		if strings.HasSuffix(allowed, "/*") {
			prefix := strings.TrimSuffix(allowed, "/*")
			if strings.HasPrefix(resource, prefix+"/") {
				return nil
			}
		}
	}

	return fmt.Errorf("resource %q is not permitted under scope key %q", resource, scopeKey)
}

// ValidateDelegationBounds verifies that a child contract does not exceed the
// capability boundaries of its parent contract. This enforces the principle of
// least privilege in delegation chains.
//
// Rules:
//  1. Every child capability must be allowed by the parent's capability set.
//  2. All parent denies are inherited (the child cannot remove parent denies).
//  3. The child's expiration must not exceed the parent's expiration.
//  4. The child must reference the parent via ParentJTI.
func ValidateDelegationBounds(parent, child *SECContract) error {
	if !child.Delegated {
		return fmt.Errorf("child contract is not marked as delegated")
	}

	if child.ParentJTI != parent.JTI {
		return fmt.Errorf("child parent_jti %q does not match parent jti %q", child.ParentJTI, parent.JTI)
	}

	// Child expiration must not exceed parent
	if child.EXP > parent.EXP {
		return fmt.Errorf("child expiration (%d) exceeds parent expiration (%d)", child.EXP, parent.EXP)
	}

	// Every child capability must be within the parent's allowed set
	for _, childCap := range child.Capabilities {
		allowed := false
		for _, parentCap := range parent.Capabilities {
			if MatchCapability(parentCap, childCap) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("child capability %q exceeds parent boundaries", childCap)
		}
	}

	// Verify all parent denies are inherited by the child
	for _, parentDeny := range parent.Denies {
		found := false
		for _, childDeny := range child.Denies {
			if childDeny == parentDeny {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("child contract is missing inherited parent deny %q", parentDeny)
		}
	}

	return nil
}
