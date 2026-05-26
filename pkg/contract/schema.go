package contract

import (
	"fmt"
	"time"
)

// SECContract represents a signed execution contract that defines the capability
// boundaries, resource scopes, and lifetime constraints for an autonomous agent.
type SECContract struct {
	// Contract Identity
	JTI string `json:"jti"`
	KID string `json:"kid,omitempty"`

	// Ephemeral session public key (base64url-encoded Ed25519 public key).
	// Used for delegation: the parent contract declares the session public key
	// that the parent agent will use to sign child contracts. The verifier uses
	// this key to validate child token signatures without needing the root key.
	SessionPubKey string `json:"spk,omitempty"`

	// Timing
	IAT int64 `json:"iat"`
	EXP int64 `json:"exp"`

	// Human-readable intent description
	Objective string `json:"obj"`

	// Capability boundaries
	Capabilities []string `json:"caps"`
	Denies       []string `json:"denies"`

	// Resource constraints (provider-specific)
	Scopes map[string][]string `json:"scopes"`

	// Target verifier identifiers
	Audience []string `json:"aud"`

	// Replay protection
	ReplayMode string `json:"replay"`
	MaxUses    int    `json:"max_uses,omitempty"`

	// Delegation context
	Delegated bool   `json:"delegated,omitempty"`
	ParentJTI string `json:"parent_jti,omitempty"`
}

// Valid replay mode constants.
const (
	ReplayReusable  = "reusable"
	ReplaySingleUse = "single_use"
	ReplayBounded   = "bounded"
)

// Validate performs structural validation of the contract fields.
// This checks field-level invariants only (non-empty required fields, valid
// replay modes, timing sanity). It does not perform cryptographic verification.
func (c *SECContract) Validate() error {
	if c.JTI == "" {
		return fmt.Errorf("jti is required")
	}
	if c.Objective == "" {
		return fmt.Errorf("obj (objective) is required")
	}
	if c.IAT == 0 {
		return fmt.Errorf("iat (issued at) is required")
	}
	if c.EXP == 0 {
		return fmt.Errorf("exp (expiration) is required")
	}
	if c.EXP <= c.IAT {
		return fmt.Errorf("exp must be after iat")
	}
	if len(c.Capabilities) == 0 {
		return fmt.Errorf("caps (capabilities) must contain at least one entry")
	}
	if len(c.Audience) == 0 {
		return fmt.Errorf("aud (audience) must contain at least one entry")
	}

	switch c.ReplayMode {
	case ReplayReusable, ReplaySingleUse, ReplayBounded:
		// valid
	case "":
		return fmt.Errorf("replay mode is required")
	default:
		return fmt.Errorf("invalid replay mode %q: must be one of reusable, single_use, bounded", c.ReplayMode)
	}

	if c.ReplayMode == ReplayBounded && c.MaxUses <= 0 {
		return fmt.Errorf("max_uses must be positive when replay mode is bounded")
	}

	if c.Delegated && c.ParentJTI == "" {
		return fmt.Errorf("parent_jti is required when delegated is true")
	}

	return nil
}

// IsExpired checks whether the contract has passed its expiration time.
func (c *SECContract) IsExpired() bool {
	return time.Now().Unix() > c.EXP
}
