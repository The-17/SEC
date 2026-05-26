package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"sec/pkg/config"
	"sec/pkg/contract"
	seccrypto "sec/pkg/crypto"
	"sec/pkg/storage"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	exitSuccess     = 0
	exitCryptoError = 1
	exitPolicyError = 2
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(exitCryptoError)
	}

	switch os.Args[1] {
	case "init":
		os.Exit(runInit(os.Args[2:]))
	case "sign":
		os.Exit(runSign(os.Args[2:]))
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "revoke":
		os.Exit(runRevoke(os.Args[2:]))
	case "delegate":
		os.Exit(runDelegate(os.Args[2:]))
	case "status":
		os.Exit(runStatus(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Printf("sec version %s, commit %s, built at %s\n", version, commit, date)
		os.Exit(exitSuccess)
	case "help", "--help", "-h":
		printUsage()
		os.Exit(exitSuccess)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(exitCryptoError)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `SEC (Signed Execution Contracts) — Cryptographic Capability Boundaries

Usage:
  sec init    [--kid <key_id>]        Generate Ed25519 signing keypair
  sec sign    [flags]                 Sign a new execution contract
  sec verify  [flags]                 Verify a contract token
  sec revoke  [flags]                 Revoke a signed execution contract
  sec delegate [flags]                Delegate a child contract from a parent
  sec status                          Show diagnostic status of SEC
  sec version                         Show build version info of SEC

Run 'sec <command> --help' for command-specific flags.
`)
}

// --- INIT COMMAND ---

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	kid := fs.String("kid", "default", "Key identifier for the generated keypair")

	if err := fs.Parse(args); err != nil {
		return exitCryptoError
	}

	if err := seccrypto.GenerateKeyPair(*kid); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitCryptoError
	}

	fmt.Fprintf(os.Stderr, "Keypair generated: ~/.sec/keys/%s.key and ~/.sec/keys/%s.pub\n", *kid, *kid)
	return exitSuccess
}

// --- SIGN COMMAND ---

func runSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	objective := fs.String("objective", "", "Human-readable objective (required)")
	allow := fs.String("allow", "", "Comma-separated allowed action patterns (required)")
	ttl := fs.String("ttl", "10m", "Token time-to-live (e.g. 10m, 1h, 24h)")
	kid := fs.String("kid", "default", "Key ID to use for signing")
	outFile := fs.String("out", "", "Write token to file instead of stdout")
	signer := fs.String("signer", "", "Identifier of the signing orchestrator")
	runID := fs.String("run-id", "", "Correlation ID for the execution session")

	if err := fs.Parse(args); err != nil {
		return exitCryptoError
	}

	// Validate required flags
	if *objective == "" {
		fmt.Fprintf(os.Stderr, "error: --objective is required\n")
		return exitCryptoError
	}
	if *allow == "" {
		fmt.Fprintf(os.Stderr, "error: --allow is required\n")
		return exitCryptoError
	}

	// Parse TTL duration
	duration, err := time.ParseDuration(*ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --ttl value %q: %v\n", *ttl, err)
		return exitCryptoError
	}

	now := time.Now()

	// Parse capabilities
	caps := splitAndTrim(*allow)

	// Build the contract
	c := contract.SECContract{
		JTI:       uuid.New().String(),
		KID:       *kid,
		IAT:       now.Unix(),
		EXP:       now.Add(duration).Unix(),
		Objective: *objective,
		Allowed:   caps,
		Signer:    *signer,
		RunID:     *runID,
	}

	// Load the private key
	privateKey, err := seccrypto.LoadPrivateKey(*kid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "hint: run 'sec init --kid %s' to generate a keypair\n", *kid)
		return exitCryptoError
	}

	// Sign the contract
	token, err := seccrypto.SignContract(c, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitCryptoError
	}

	// Output
	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(token), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to write token to %s: %v\n", *outFile, err)
			return exitCryptoError
		}
		fmt.Fprintf(os.Stderr, "Token written to %s\n", *outFile)
	} else {
		fmt.Print(token)
	}

	return exitSuccess
}

// --- VERIFY COMMAND ---

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	tokenStr := fs.String("token", "", "Raw token string")
	tokenFile := fs.String("token-file", "", "Path to token file")
	action := fs.String("action", "", "Required action to check against the allow list")

	if err := fs.Parse(args); err != nil {
		return exitCryptoError
	}

	// Load token from string or file
	token := *tokenStr
	if token == "" && *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to read token file: %v\n", err)
			return exitCryptoError
		}
		token = strings.TrimSpace(string(data))
	}
	if token == "" {
		fmt.Fprintf(os.Stderr, "error: --token or --token-file is required\n")
		return exitCryptoError
	}

	if *action == "" {
		fmt.Fprintf(os.Stderr, "error: --action is required\n")
		return exitCryptoError
	}

	// Open JTI store
	jtiStore, err := storage.OpenJTIStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open replay store: %v\n", err)
		return exitCryptoError
	}
	defer jtiStore.Close()

	// Run verification
	verified, err := seccrypto.VerifyContract(seccrypto.VerifyRequest{
		Token:    token,
		Action:   *action,
		JTIStore: jtiStore,
	})
	if err != nil {
		return handleVerifyError(err)
	}

	// Success — output the verified contract as JSON to stdout
	output, _ := json.MarshalIndent(verified, "", "  ")
	fmt.Println(string(output))
	return exitSuccess
}

// handleVerifyError maps verification errors to appropriate exit codes and
// outputs structured JSON error payloads to stderr.
func handleVerifyError(err error) int {
	var code string = "SEC_MALFORMED_CONTRACT"
	var message string = err.Error()
	var context map[string]interface{}
	exitCode := exitCryptoError

	if ve, ok := err.(*seccrypto.VerificationError); ok {
		code = ve.Code
		message = ve.Message
		context = ve.Context
		if ve.Code == "SEC_ACTION_NOT_PERMITTED" {
			exitCode = exitPolicyError
		}
	}

	payload := map[string]interface{}{
		"error":   code,
		"message": message,
	}
	if context != nil {
		payload["context"] = context
	}
	output, _ := json.Marshal(payload)
	fmt.Fprintln(os.Stderr, string(output))

	return exitCode
}

// --- STATUS COMMAND ---

func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return exitCryptoError
	}

	keysDir, err := config.GetKeysDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to resolve keys directory: %v\n", err)
		return exitCryptoError
	}

	dbPath, err := config.GetDBPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to resolve JTI database path: %v\n", err)
		return exitCryptoError
	}

	// Check if default key pair is generated
	defaultKeyExists := false
	defaultPubExists := false
	if _, err := os.Stat(filepath.Join(keysDir, "default.key")); err == nil {
		defaultKeyExists = true
	}
	if _, err := os.Stat(filepath.Join(keysDir, "default.pub")); err == nil {
		defaultPubExists = true
	}

	initialized := "No"
	if defaultKeyExists && defaultPubExists {
		initialized = "Yes"
	}

	// Count JTI records
	jtiCount := 0
	jtiStore, err := storage.OpenJTIStore()
	if err == nil {
		defer jtiStore.Close()
		if count, err := jtiStore.GetRecordCount(); err == nil {
			jtiCount = count
		}
	}

	fmt.Printf("SEC Status:\n")
	fmt.Printf("  Initialized:   %s\n", initialized)
	fmt.Printf("  Keys Location: %s\n", keysDir)
	fmt.Printf("  Replay Store:  %s\n", dbPath)
	fmt.Printf("  Active JTIs:   %d\n", jtiCount)

	return exitSuccess
}

// splitAndTrim splits a comma-separated string and trims whitespace from each element.
// Returns nil for empty input.
func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// --- REVOKE COMMAND ---

func runRevoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	jtiFlag := fs.String("jti", "", "JTI UUID to revoke")
	tokenFile := fs.String("token-file", "", "Path to token file to extract JTI from")

	if err := fs.Parse(args); err != nil {
		return exitCryptoError
	}

	if (*jtiFlag == "" && *tokenFile == "") || (*jtiFlag != "" && *tokenFile != "") {
		fmt.Fprintf(os.Stderr, "error: must specify either --jti or --token-file, but not both\n")
		return exitCryptoError
	}

	var jti string
	var exp int64

	if *jtiFlag != "" {
		jti = *jtiFlag
		if _, err := uuid.Parse(jti); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid JTI UUID: %v\n", err)
			return exitCryptoError
		}
		// Generous default expiration for manual JTI revocation: 24h
		exp = time.Now().Add(24 * time.Hour).Unix()
	} else {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to read token file: %v\n", err)
			return exitCryptoError
		}
		token := strings.TrimSpace(string(data))
		parts := strings.Split(token, ".")
		if len(parts) != 2 || parts[0] == "" {
			fmt.Fprintf(os.Stderr, "error: invalid token format\n")
			return exitCryptoError
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to decode token payload: %v\n", err)
			return exitCryptoError
		}
		var parsed struct {
			JTI string `json:"jti"`
			EXP int64  `json:"exp"`
		}
		if err := json.Unmarshal(payloadBytes, &parsed); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to parse contract payload JSON: %v\n", err)
			return exitCryptoError
		}
		jti = parsed.JTI
		exp = parsed.EXP
		if jti == "" {
			fmt.Fprintf(os.Stderr, "error: token payload does not contain jti\n")
			return exitCryptoError
		}
		if exp <= 0 {
			exp = time.Now().Add(24 * time.Hour).Unix()
		}
	}

	jtiStore, err := storage.OpenJTIStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open replay store: %v\n", err)
		return exitCryptoError
	}
	defer jtiStore.Close()

	if err := jtiStore.Revoke(jti, exp); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to revoke contract: %v\n", err)
		return exitCryptoError
	}

	fmt.Fprintf(os.Stderr, "Contract %s successfully revoked\n", jti)
	return exitSuccess
}

// --- DELEGATE COMMAND ---

func runDelegate(args []string) int {
	fs := flag.NewFlagSet("delegate", flag.ContinueOnError)
	parentFile := fs.String("parent", "", "Path to parent token file (required)")
	objective := fs.String("objective", "", "Human-readable objective (required)")
	allow := fs.String("allow", "", "Comma-separated allowed action patterns (required)")
	ttl := fs.String("ttl", "", "Child token time-to-live (e.g. 5m). Defaults to parent remaining time")
	kid := fs.String("kid", "", "Key ID to use for signing (defaults to parent's KID)")
	maxDepth := fs.Int("max-depth", -1, "Optional maximum delegation depth for the child contract")
	outFile := fs.String("out", "", "Write child token to file instead of stdout")

	if err := fs.Parse(args); err != nil {
		return exitCryptoError
	}

	if *parentFile == "" {
		fmt.Fprintf(os.Stderr, "error: --parent is required\n")
		return exitCryptoError
	}
	if *objective == "" {
		fmt.Fprintf(os.Stderr, "error: --objective is required\n")
		return exitCryptoError
	}
	if *allow == "" {
		fmt.Fprintf(os.Stderr, "error: --allow is required\n")
		return exitCryptoError
	}

	// 1. Read and verify parent token
	parentBytes, err := os.ReadFile(*parentFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to read parent token: %v\n", err)
		return exitCryptoError
	}
	parentToken := strings.TrimSpace(string(parentBytes))

	parent, err := readAndVerifyParentToken(parentToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid parent token: %v\n", err)
		return exitCryptoError
	}

	// 2. Determine signing key
	signingKid := *kid
	if signingKid == "" {
		signingKid = parent.KID
		if signingKid == "" {
			signingKid = "default"
		}
	}

	// 3. Determine child expiration
	now := time.Now()
	var childExp int64
	if *ttl != "" {
		duration, err := time.ParseDuration(*ttl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid --ttl value %q: %v\n", *ttl, err)
			return exitCryptoError
		}
		childExp = now.Add(duration).Unix()
		// Clamp to parent expiration if it exceeds it
		if childExp > parent.EXP {
			childExp = parent.EXP
		}
	} else {
		// Default to parent expiration
		childExp = parent.EXP
	}

	// 4. Build child contract
	caps := splitAndTrim(*allow)
	child := contract.SECContract{
		JTI:       uuid.New().String(),
		KID:       signingKid,
		IAT:       now.Unix(),
		EXP:       childExp,
		Objective: *objective,
		Allowed:   caps,
		ParentJTI: parent.JTI,
	}

	// Set child max depth
	if *maxDepth >= 0 {
		depthVal := *maxDepth
		child.MaxDepth = &depthVal
	} else if parent.MaxDepth != nil {
		childDepth := *parent.MaxDepth - 1
		child.MaxDepth = &childDepth
	}

	// 5. Validate delegation constraints
	if err := contract.ValidateDelegation(*parent, child); err != nil {
		fmt.Fprintf(os.Stderr, "error: delegation validation failed: %v\n", err)
		return exitCryptoError
	}

	// 6. Sign child contract
	privateKey, err := seccrypto.LoadPrivateKey(signingKid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitCryptoError
	}

	token, err := seccrypto.SignContract(child, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to sign child contract: %v\n", err)
		return exitCryptoError
	}

	// 7. Output
	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(token), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to write token to %s: %v\n", *outFile, err)
			return exitCryptoError
		}
		fmt.Fprintf(os.Stderr, "Child token written to %s\n", *outFile)
	} else {
		fmt.Print(token)
	}

	return exitSuccess
}

func readAndVerifyParentToken(token string) (*contract.SECContract, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid token format: expected 2 dot-separated segments")
	}

	payloadB64, sigB64 := parts[0], parts[1]

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var partial struct {
		KID string `json:"kid"`
	}
	_ = json.Unmarshal(payloadBytes, &partial)

	kid := partial.KID
	if kid == "" {
		kid = "default"
	}

	verifyKey, err := seccrypto.LoadPublicKey(kid)
	if err != nil {
		return nil, fmt.Errorf("public key for KID %q not found: %w", kid, err)
	}

	if !ed25519.Verify(verifyKey, []byte(payloadB64), sigBytes) {
		return nil, fmt.Errorf("signature verification failed")
	}

	var c contract.SECContract
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return nil, fmt.Errorf("failed to parse contract JSON: %w", err)
	}

	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("schema validation failed: %w", err)
	}

	if c.IsExpired() {
		return nil, fmt.Errorf("contract is expired")
	}

	return &c, nil
}
