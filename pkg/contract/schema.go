package contract

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SECContract represents a signed execution contract that defines the capability
// boundaries and lifetime constraints for an autonomous agent.
type SECContract struct {
	JTI       string   `json:"jti"`
	KID       string   `json:"kid,omitempty"`
	IAT       int64    `json:"iat"`
	EXP       int64    `json:"exp"`
	Objective string   `json:"obj"`
	Allowed   []string `json:"allow"`
	ParentJTI string   `json:"parent_jti,omitempty"`
	MaxDepth  *int     `json:"max_depth,omitempty"`
	Signer    string   `json:"signer,omitempty"`
	RunID     string   `json:"run_id,omitempty"`
}

// Validate performs structural validation of the contract fields.
// This checks field-level invariants only (non-empty required fields, UUID format,
// timing sanity). It does not perform cryptographic verification.
func (c *SECContract) Validate() error {
	if c.JTI == "" {
		return fmt.Errorf("jti is required")
	}
	if _, err := uuid.Parse(c.JTI); err != nil {
		return fmt.Errorf("jti must be a valid UUID: %w", err)
	}
	if c.Objective == "" {
		return fmt.Errorf("obj (objective) is required")
	}
	if c.IAT <= 0 {
		return fmt.Errorf("iat (issued at) must be positive")
	}
	if c.EXP <= 0 {
		return fmt.Errorf("exp (expiration) must be positive")
	}
	if c.EXP <= c.IAT {
		return fmt.Errorf("exp must be after iat")
	}
	if len(c.Allowed) == 0 {
		return fmt.Errorf("allow list must contain at least one entry")
	}
	for _, pattern := range c.Allowed {
		if strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("allow list cannot contain empty patterns")
		}
		if err := checkVerbPrefix(pattern); err != nil {
			return err
		}
	}
	if c.ParentJTI != "" {
		if _, err := uuid.Parse(c.ParentJTI); err != nil {
			return fmt.Errorf("parent_jti must be a valid UUID: %w", err)
		}
	}
	if c.MaxDepth != nil && *c.MaxDepth < 0 {
		return fmt.Errorf("max_depth must be non-negative")
	}
	return nil
}

func checkVerbPrefix(pattern string) error {
	idx := strings.Index(pattern, ":")
	if idx == -1 {
		return nil
	}
	if strings.HasPrefix(pattern[idx:], "://") {
		return nil
	}
	prefix := pattern[:idx]
	isAllLetters := true
	for _, r := range prefix {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			isAllLetters = false
			break
		}
	}
	if !isAllLetters || len(prefix) == 0 {
		return nil
	}

	upperPrefix := strings.ToUpper(prefix)
	if upperPrefix == "HTTP" || upperPrefix == "HTTPS" {
		return nil
	}

	if isValidVerb(upperPrefix) {
		return nil
	}

	if idx+1 < len(pattern) && pattern[idx+1] >= '0' && pattern[idx+1] <= '9' {
		return nil
	}

	return fmt.Errorf("invalid HTTP verb prefix %q in pattern %q", prefix, pattern)
}

// IsExpired checks whether the contract has passed its expiration time.
func (c *SECContract) IsExpired() bool {
	return time.Now().Unix() > c.EXP
}
