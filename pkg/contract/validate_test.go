package contract

import (
	"testing"
)

func TestMatchCapability_ExactMatch(t *testing.T) {
	if !MatchCapability("github.issues.read", "github.issues.read") {
		t.Error("expected exact match to succeed")
	}
	if MatchCapability("github.issues.read", "github.issues.write") {
		t.Error("expected different exact strings to fail")
	}
}

func TestMatchCapability_UniversalWildcard(t *testing.T) {
	if !MatchCapability("*", "anything.at.all") {
		t.Error("universal wildcard should match everything")
	}
}

func TestMatchCapability_SuffixWildcard(t *testing.T) {
	// github.* should match all github capabilities at any depth
	if !MatchCapability("github.*", "github.issues") {
		t.Error("suffix wildcard should match single segment")
	}
	if !MatchCapability("github.*", "github.issues.read") {
		t.Error("suffix wildcard should match multi-segment (hierarchical)")
	}
	if MatchCapability("github.*", "slack.messages") {
		t.Error("suffix wildcard should not match different prefix")
	}
}

func TestMatchCapability_MiddleWildcard(t *testing.T) {
	// path.Match treats * as single-segment glob
	if !MatchCapability("github.*.read", "github.issues.read") {
		t.Error("middle wildcard should match single middle segment")
	}
	if MatchCapability("github.*.read", "github.issues.comments.read") {
		t.Error("middle wildcard should not match multiple middle segments in path.Match mode")
	}
}

func TestMatchCapability_PrefixWildcard(t *testing.T) {
	if !MatchCapability("*.read", "github.read") {
		t.Error("prefix wildcard should match single prefix segment")
	}
}

func TestIsCapabilityAllowed_DenyOverridesAllow(t *testing.T) {
	caps := []string{"github.*"}
	denies := []string{"github.repositories.delete"}

	if !IsCapabilityAllowed(caps, denies, "github.issues.read") {
		t.Error("github.issues.read should be allowed")
	}
	if IsCapabilityAllowed(caps, denies, "github.repositories.delete") {
		t.Error("github.repositories.delete should be denied even with github.* allow")
	}
}

func TestIsCapabilityAllowed_DefaultDeny(t *testing.T) {
	caps := []string{"github.issues.read"}
	denies := []string{}

	if IsCapabilityAllowed(caps, denies, "slack.messages.post") {
		t.Error("unmatched capability should be denied by default")
	}
}

func TestDefaultScopeValidator_ExactMatch(t *testing.T) {
	v := &DefaultScopeValidator{}
	scopes := map[string][]string{
		"repositories": {"The-17/agentsecrets"},
	}
	if err := v.Validate(scopes, "repositories", "The-17/agentsecrets"); err != nil {
		t.Errorf("exact scope match should pass: %v", err)
	}
}

func TestDefaultScopeValidator_NoMatch(t *testing.T) {
	v := &DefaultScopeValidator{}
	scopes := map[string][]string{
		"repositories": {"The-17/agentsecrets"},
	}
	if err := v.Validate(scopes, "repositories", "Evil-Org/malware"); err == nil {
		t.Error("non-matching resource should fail scope validation")
	}
}

func TestDefaultScopeValidator_UndefinedScopeKey(t *testing.T) {
	v := &DefaultScopeValidator{}
	scopes := map[string][]string{
		"repositories": {"The-17/agentsecrets"},
	}
	// channels is not constrained — should pass
	if err := v.Validate(scopes, "channels", "general"); err != nil {
		t.Errorf("unconstrained scope key should pass: %v", err)
	}
}

func TestDefaultScopeValidator_PrefixWildcard(t *testing.T) {
	v := &DefaultScopeValidator{}
	scopes := map[string][]string{
		"repositories": {"The-17/*"},
	}
	if err := v.Validate(scopes, "repositories", "The-17/agentsecrets"); err != nil {
		t.Errorf("prefix wildcard scope should pass: %v", err)
	}
	if err := v.Validate(scopes, "repositories", "Evil-Org/malware"); err == nil {
		t.Error("prefix wildcard should not match different org")
	}
}

func TestValidateDelegationBounds_Valid(t *testing.T) {
	parent := &SECContract{
		JTI:          "parent-001",
		EXP:          9999999999,
		Capabilities: []string{"github.*"},
		Denies:       []string{"github.repos.delete"},
	}
	child := &SECContract{
		JTI:          "child-001",
		Delegated:    true,
		ParentJTI:    "parent-001",
		EXP:          9999999998,
		Capabilities: []string{"github.issues.read"},
		Denies:       []string{"github.repos.delete"},
	}
	if err := ValidateDelegationBounds(parent, child); err != nil {
		t.Errorf("valid delegation should pass: %v", err)
	}
}

func TestValidateDelegationBounds_CapabilityEscalation(t *testing.T) {
	parent := &SECContract{
		JTI:          "parent-001",
		EXP:          9999999999,
		Capabilities: []string{"github.issues.read"},
		Denies:       []string{},
	}
	child := &SECContract{
		JTI:          "child-001",
		Delegated:    true,
		ParentJTI:    "parent-001",
		EXP:          9999999998,
		Capabilities: []string{"github.repos.delete"},
		Denies:       []string{},
	}
	if err := ValidateDelegationBounds(parent, child); err == nil {
		t.Error("child with escalated capabilities should fail delegation bounds")
	}
}

func TestValidateDelegationBounds_ExpirationExceeded(t *testing.T) {
	parent := &SECContract{
		JTI:          "parent-001",
		EXP:          1000,
		Capabilities: []string{"github.*"},
		Denies:       []string{},
	}
	child := &SECContract{
		JTI:          "child-001",
		Delegated:    true,
		ParentJTI:    "parent-001",
		EXP:          2000,
		Capabilities: []string{"github.issues.read"},
		Denies:       []string{},
	}
	if err := ValidateDelegationBounds(parent, child); err == nil {
		t.Error("child with expiration exceeding parent should fail")
	}
}

func TestValidateDelegationBounds_MissingInheritedDeny(t *testing.T) {
	parent := &SECContract{
		JTI:          "parent-001",
		EXP:          9999999999,
		Capabilities: []string{"github.*"},
		Denies:       []string{"github.repos.delete"},
	}
	child := &SECContract{
		JTI:          "child-001",
		Delegated:    true,
		ParentJTI:    "parent-001",
		EXP:          9999999998,
		Capabilities: []string{"github.issues.read"},
		Denies:       []string{}, // missing inherited deny
	}
	if err := ValidateDelegationBounds(parent, child); err == nil {
		t.Error("child missing inherited parent deny should fail")
	}
}

func TestSECContract_Validate_ValidContract(t *testing.T) {
	c := &SECContract{
		JTI:          "test-001",
		IAT:          1000,
		EXP:          2000,
		Objective:    "test",
		Capabilities: []string{"github.issues.read"},
		Audience:     []string{"github"},
		ReplayMode:   "reusable",
	}
	if err := c.Validate(); err != nil {
		t.Errorf("valid contract should pass: %v", err)
	}
}

func TestSECContract_Validate_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		c    SECContract
	}{
		{"missing JTI", SECContract{IAT: 1, EXP: 2, Objective: "x", Capabilities: []string{"a"}, Audience: []string{"b"}, ReplayMode: "reusable"}},
		{"missing objective", SECContract{JTI: "x", IAT: 1, EXP: 2, Capabilities: []string{"a"}, Audience: []string{"b"}, ReplayMode: "reusable"}},
		{"missing caps", SECContract{JTI: "x", IAT: 1, EXP: 2, Objective: "x", Audience: []string{"b"}, ReplayMode: "reusable"}},
		{"missing audience", SECContract{JTI: "x", IAT: 1, EXP: 2, Objective: "x", Capabilities: []string{"a"}, ReplayMode: "reusable"}},
		{"missing replay", SECContract{JTI: "x", IAT: 1, EXP: 2, Objective: "x", Capabilities: []string{"a"}, Audience: []string{"b"}}},
		{"exp before iat", SECContract{JTI: "x", IAT: 2, EXP: 1, Objective: "x", Capabilities: []string{"a"}, Audience: []string{"b"}, ReplayMode: "reusable"}},
		{"bounded without max_uses", SECContract{JTI: "x", IAT: 1, EXP: 2, Objective: "x", Capabilities: []string{"a"}, Audience: []string{"b"}, ReplayMode: "bounded"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Validate(); err == nil {
				t.Errorf("expected validation to fail for %s", tt.name)
			}
		})
	}
}
