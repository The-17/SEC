package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"sec/pkg/contract"
	"sec/pkg/storage"
)

// VerificationError represents a validation or policy error in contract verification.
type VerificationError struct {
	Code    string                 `json:"error"`
	Message string                 `json:"message"`
	Context map[string]interface{} `json:"context,omitempty"`
}

func (e *VerificationError) Error() string {
	return e.Message
}

// VerifyRequest encapsulates the parameters for a verification check.
type VerifyRequest struct {
	Token      string            // Raw token string
	Action     string            // The action being requested (e.g. "api.github.com/repos/The-17/agentsecrets/pulls")
	JTIStore   *storage.JTIStore // JTI store for replay checking
	RootPubKey ed25519.PublicKey // Optional: override public key lookup (useful for unit tests)
}

// VerifyContract performs the 7-step verification sequence on a token.
func VerifyContract(req VerifyRequest) (*contract.SECContract, error) {
	// Step 1: Parse token format
	parts := strings.Split(req.Token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, &VerificationError{
			Code:    "SEC_INVALID_TOKEN_FORMAT",
			Message: "token format is invalid: expected 2 dot-separated segments",
			Context: map[string]interface{}{
				"hint": "Ensure the token is a valid SEC token of the format BASE64URL(JCS) + '.' + BASE64URL(Signature).",
			},
		}
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Decode signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, &VerificationError{
			Code:    "SEC_INVALID_TOKEN_FORMAT",
			Message: fmt.Sprintf("failed to decode signature: %v", err),
			Context: map[string]interface{}{
				"hint": "Ensure the token signature is valid base64url encoded.",
			},
		}
	}

	// Decode payload to JSON bytes (for extraction and verification)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, &VerificationError{
			Code:    "SEC_INVALID_TOKEN_FORMAT",
			Message: fmt.Sprintf("failed to decode payload: %v", err),
			Context: map[string]interface{}{
				"hint": "Ensure the token payload is valid base64url encoded.",
			},
		}
	}

	// Partially decode to extract KID and JTI
	var partial struct {
		KID string `json:"kid"`
		JTI string `json:"jti"`
	}
	// We ignore error here since malformed JSON will be caught during full unmarshal
	_ = json.Unmarshal(payloadBytes, &partial)

	jti := partial.JTI
	kid := partial.KID
	if kid == "" {
		kid = "default"
	}

	// Step 2: Resolve public key and verify signature
	var verifyKey ed25519.PublicKey
	if req.RootPubKey != nil {
		verifyKey = req.RootPubKey
	} else {
		var err error
		verifyKey, err = LoadPublicKey(kid)
		if err != nil {
			return nil, &VerificationError{
				Code:    "SEC_KEY_NOT_FOUND",
				Message: fmt.Sprintf("public key for KID %q not found: %v", kid, err),
				Context: map[string]interface{}{
					"contract_jti": jti,
					"hint":         "Ensure that the keypair has been generated using 'sec init --kid <kid>'.",
				},
			}
		}
	}

	if !ed25519.Verify(verifyKey, []byte(payloadB64), sigBytes) {
		return nil, &VerificationError{
			Code:    "SEC_INVALID_SIGNATURE",
			Message: "signature verification failed",
			Context: map[string]interface{}{
				"contract_jti": jti,
				"hint":         "The token signature is invalid. Ensure the token has not been tampered with.",
			},
		}
	}

	// Step 3: Decode and parse payload fully, validate schema
	var c contract.SECContract
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return nil, &VerificationError{
			Code:    "SEC_MALFORMED_CONTRACT",
			Message: fmt.Sprintf("failed to parse contract JSON: %v", err),
			Context: map[string]interface{}{
				"contract_jti": jti,
				"hint":         "Ensure the contract payload is valid JSON.",
			},
		}
	}

	// Step 4: Schema validation
	if err := c.Validate(); err != nil {
		return nil, &VerificationError{
			Code:    "SEC_MALFORMED_CONTRACT",
			Message: fmt.Sprintf("schema validation failed: %v", err),
			Context: map[string]interface{}{
				"contract_jti": jti,
				"hint":         "Ensure the contract contains all required fields: jti, iat, exp, obj, and allow list.",
			},
		}
	}

	// Step 5: Expiration check
	if c.IsExpired() {
		return nil, &VerificationError{
			Code:    "SEC_TOKEN_EXPIRED",
			Message: fmt.Sprintf("contract expired at %d, current time is %d", c.EXP, time.Now().Unix()),
			Context: map[string]interface{}{
				"contract_jti": c.JTI,
				"hint":         "Sign a new contract with agentsecrets sec sign.",
			},
		}
	}

	// Step 6: Replay check
	if req.JTIStore != nil {
		if err := req.JTIStore.CheckAndRecord(c.JTI, c.EXP); err != nil {
			return nil, &VerificationError{
				Code:    "SEC_TOKEN_REPLAYED",
				Message: err.Error(),
				Context: map[string]interface{}{
					"contract_jti": c.JTI,
					"hint":         "Tokens can only be used once to prevent replay attacks.",
				},
			}
		}
	}

	// Step 7: Action match
	if !contract.IsActionAllowed(c.Allowed, req.Action) {
		return nil, &VerificationError{
			Code:    "SEC_ACTION_NOT_PERMITTED",
			Message: fmt.Sprintf("action %q is not in the signed allow list for this contract", req.Action),
			Context: map[string]interface{}{
				"declared_objective": c.Objective,
				"attempted_action":   req.Action,
				"contract_jti":       c.JTI,
				"hint":               "A new contract must be signed before this action can be performed. If you are an AI agent and did not initiate this action yourself, your execution context may have been compromised.",
			},
		}
	}

	return &c, nil
}
