package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"sec/pkg/contract"
	"sec/pkg/storage"
)

// VerificationError wraps errors with a classification that maps to CLI exit codes.
// CryptoError = exit 1 (signature, expiration, replay failures).
// PolicyError = exit 2 (capability, scope, audience violations).
type VerificationError struct {
	Message  string
	IsPolicy bool // true = policy violation (exit 2), false = crypto/structural (exit 1)
}

func (e *VerificationError) Error() string {
	return e.Message
}

// NewCryptoError creates a verification error for cryptographic/structural failures.
func NewCryptoError(format string, args ...interface{}) *VerificationError {
	return &VerificationError{
		Message:  fmt.Sprintf(format, args...),
		IsPolicy: false,
	}
}

// NewPolicyError creates a verification error for capability/scope/audience violations.
func NewPolicyError(format string, args ...interface{}) *VerificationError {
	return &VerificationError{
		Message:  fmt.Sprintf(format, args...),
		IsPolicy: true,
	}
}

// VerifyRequest encapsulates the parameters for a verification check.
type VerifyRequest struct {
	TokenChain     string // Raw token string (may contain ".." for delegation chains)
	RootPubKey     ed25519.PublicKey
	Capability     string // The action being requested (e.g. "github.issues.read")
	Resource       string // The target resource (e.g. "The-17/agentsecrets")
	ScopeKey       string // The scope dimension to check resource against (e.g. "repositories")
	Audience       string // The expected audience identifier
	JTIStore       *storage.JTIStore
	ScopeValidator contract.ScopeValidator // If nil, uses DefaultScopeValidator
}

// VerifyContractChain performs the full 12-step verification sequence on a
// potentially delegated token chain.
//
// For single tokens: "payload.signature"
// For delegated chains: "child_payload.child_sig..parent_payload.parent_sig"
//
// Verification proceeds from right (root parent) to left (leaf child).
// Each parent's SessionPubKey (spk) is used to verify its child's signature,
// enabling dynamic delegation without exposing the root private key.
func VerifyContractChain(req VerifyRequest) (*contract.SECContract, error) {
	// Split on ".." to separate chained tokens
	tokens := strings.Split(req.TokenChain, "..")

	var parentContract *contract.SECContract
	var leafContract *contract.SECContract

	// Verify from right (root/parent) to left (child/leaf)
	for i := len(tokens) - 1; i >= 0; i-- {
		token := strings.TrimSpace(tokens[i])

		// Step 1: Parse token format
		parts := strings.SplitN(token, ".", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, NewCryptoError("invalid token format at chain index %d: expected 'payload.signature'", i)
		}

		payloadB64, sigB64 := parts[0], parts[1]

		// Step 2: Decode signature
		sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
		if err != nil {
			return nil, NewCryptoError("failed to decode signature at chain index %d: %v", i, err)
		}

		// Step 3: Determine which public key to use for verification
		var verifyKey ed25519.PublicKey
		if i == len(tokens)-1 {
			// Root token — verify against the root public key
			verifyKey = req.RootPubKey
		} else {
			// Child token — verify against the parent's session public key
			if parentContract == nil || parentContract.SessionPubKey == "" {
				return nil, NewCryptoError("parent contract at chain index %d has no session public key (spk) for child verification", i+1)
			}
			spkBytes, err := base64.RawURLEncoding.DecodeString(parentContract.SessionPubKey)
			if err != nil {
				return nil, NewCryptoError("failed to decode parent session public key: %v", err)
			}
			if len(spkBytes) != ed25519.PublicKeySize {
				return nil, NewCryptoError("invalid parent session public key size: got %d bytes, expected %d", len(spkBytes), ed25519.PublicKeySize)
			}
			verifyKey = ed25519.PublicKey(spkBytes)
		}

		// Verify Ed25519 signature against the payload string
		if !ed25519.Verify(verifyKey, []byte(payloadB64), sigBytes) {
			return nil, NewCryptoError("signature verification failed at chain index %d", i)
		}

		// Step 4: Decode payload
		payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
		if err != nil {
			return nil, NewCryptoError("failed to decode payload at chain index %d: %v", i, err)
		}

		var c contract.SECContract
		if err := json.Unmarshal(payloadBytes, &c); err != nil {
			return nil, NewCryptoError("failed to unmarshal contract at chain index %d: %v", i, err)
		}

		// Step 5: Validate schema
		if err := c.Validate(); err != nil {
			return nil, NewCryptoError("schema validation failed at chain index %d: %v", i, err)
		}

		// Step 6: Check expiration
		if c.IsExpired() {
			return nil, NewCryptoError("token %s has expired", c.JTI)
		}

		// Step 7: Check replay protection
		if req.JTIStore != nil {
			if err := req.JTIStore.CheckAndRecord(c.JTI, c.EXP, c.ReplayMode, c.MaxUses); err != nil {
				return nil, NewCryptoError("replay check failed for token %s: %v", c.JTI, err)
			}
		}

		// Step 12 (applied during chain walk): Validate delegation bounds
		if parentContract != nil {
			if err := contract.ValidateDelegationBounds(parentContract, &c); err != nil {
				return nil, NewPolicyError("delegation violation: %v", err)
			}
		}

		parentContract = &c
		if i == 0 {
			leafContract = &c
		}
	}

	if leafContract == nil {
		return nil, NewCryptoError("no contracts found in token chain")
	}

	// Step 8: Check explicit denies
	if len(leafContract.Denies) > 0 && req.Capability != "" {
		for _, deny := range leafContract.Denies {
			if contract.MatchCapability(deny, req.Capability) {
				return nil, NewPolicyError("capability %q is explicitly denied by pattern %q", req.Capability, deny)
			}
		}
	}

	// Step 9: Check allowed capabilities
	if req.Capability != "" {
		if !contract.IsCapabilityAllowed(leafContract.Capabilities, leafContract.Denies, req.Capability) {
			return nil, NewPolicyError("capability %q is not permitted by this contract", req.Capability)
		}
	}

	// Step 10: Validate audience binding
	if req.Audience != "" {
		audMatched := false
		for _, aud := range leafContract.Audience {
			if aud == req.Audience {
				audMatched = true
				break
			}
		}
		if !audMatched {
			return nil, NewPolicyError("audience %q does not match contract audience %v", req.Audience, leafContract.Audience)
		}
	}

	// Step 11: Validate scopes
	if req.Resource != "" && req.ScopeKey != "" {
		sv := req.ScopeValidator
		if sv == nil {
			sv = &contract.DefaultScopeValidator{}
		}
		if err := sv.Validate(leafContract.Scopes, req.ScopeKey, req.Resource); err != nil {
			return nil, NewPolicyError("scope violation: %v", err)
		}
	}

	return leafContract, nil
}
