package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"

	"sec/pkg/contract"
)

// SignContract serializes the contract to canonical JSON (RFC 8785 JCS),
// signs the base64url-encoded canonical payload with Ed25519, and returns
// the detached-signature token string: "BASE64URL(payload).BASE64URL(signature)".
//
// The canonicalization step is critical: without it, different language runtimes
// (Go, Python, Node.js) may produce different JSON byte sequences for the same
// struct, causing signature verification failures across language boundaries.
func SignContract(c contract.SECContract, privateKey ed25519.PrivateKey) (string, error) {
	// Validate the contract structure before signing
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("contract validation failed: %w", err)
	}

	// Marshal to standard JSON
	jsonBytes, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("failed to marshal contract to JSON: %w", err)
	}

	// Canonicalize using JCS (RFC 8785) to guarantee deterministic byte output
	canonicalBytes, err := jcs.Transform(jsonBytes)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize JSON (JCS): %w", err)
	}

	// Base64URL encode the canonical payload (no padding)
	payloadB64 := base64.RawURLEncoding.EncodeToString(canonicalBytes)

	// Sign the base64url-encoded payload string (not the raw bytes)
	// This ensures the exact string that appears in the token is what was signed.
	signature := ed25519.Sign(privateKey, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s", payloadB64, sigB64), nil
}
