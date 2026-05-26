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
	}
	return nil
}

// IsExpired checks whether the contract has passed its expiration time.
func (c *SECContract) IsExpired() bool {
	return time.Now().Unix() > c.EXP
}
