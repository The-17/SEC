package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"sec/pkg/contract"
	seccrypto "sec/pkg/crypto"
	"sec/pkg/storage"
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
	allow := fs.String("allow", "", "Comma-separated allowed capabilities (required)")
	deny := fs.String("deny", "", "Comma-separated denied capabilities")
	scope := fs.String("scope", "", "Comma-separated scope assignments (e.g. repositories=The-17/agentsecrets)")
	audience := fs.String("audience", "", "Comma-separated audience identifiers (required)")
	ttl := fs.String("ttl", "10m", "Token time-to-live (e.g. 10m, 1h, 24h)")
	kid := fs.String("kid", "default", "Key ID to use for signing")
	replay := fs.String("replay", "reusable", "Replay mode: reusable, single_use, or bounded")
	maxUses := fs.Int("max-uses", 0, "Max uses for bounded replay mode")
	outFile := fs.String("out", "", "Write token to file instead of stdout")
	spk := fs.String("spk", "", "Session public key (base64url-encoded Ed25519 public key) for delegation")
	delegated := fs.Bool("delegated", false, "Mark contract as delegated")
	parentJTI := fs.String("parent-jti", "", "Parent contract JTI (required if delegated)")

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
	if *audience == "" {
		fmt.Fprintf(os.Stderr, "error: --audience is required\n")
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
	denies := splitAndTrim(*deny)
	auds := splitAndTrim(*audience)

	// Parse scopes
	scopes := make(map[string][]string)
	if *scope != "" {
		for _, assignment := range splitAndTrim(*scope) {
			parts := strings.SplitN(assignment, "=", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "error: invalid scope format %q (expected key=value)\n", assignment)
				return exitCryptoError
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			scopes[key] = append(scopes[key], val)
		}
	}

	// Build the contract
	c := contract.SECContract{
		JTI:           uuid.New().String(),
		KID:           *kid,
		SessionPubKey: *spk,
		IAT:           now.Unix(),
		EXP:           now.Add(duration).Unix(),
		Objective:     *objective,
		Capabilities:  caps,
		Denies:        denies,
		Scopes:        scopes,
		Audience:      auds,
		ReplayMode:    *replay,
		MaxUses:       *maxUses,
		Delegated:     *delegated,
		ParentJTI:     *parentJTI,
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
	capability := fs.String("capability", "", "Required capability to check")
	resource := fs.String("resource", "", "Target resource")
	scopeKey := fs.String("scope-key", "repositories", "Scope dimension key for resource validation")
	audience := fs.String("audience", "", "Expected audience")

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

	// Determine the KID from the root token in the chain to load the correct public key.
	// The root token is the rightmost in a delegation chain.
	rootKID, err := extractRootKID(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitCryptoError
	}
	if rootKID == "" {
		rootKID = "default"
	}

	// Load public key
	pubKey, err := seccrypto.LoadPublicKey(rootKID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
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
	verified, err := seccrypto.VerifyContractChain(seccrypto.VerifyRequest{
		TokenChain: token,
		RootPubKey: pubKey,
		Capability: *capability,
		Resource:   *resource,
		ScopeKey:   *scopeKey,
		Audience:   *audience,
		JTIStore:   jtiStore,
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
	exitCode := exitCryptoError
	errorType := "sec_crypto_error"

	if ve, ok := err.(*seccrypto.VerificationError); ok {
		if ve.IsPolicy {
			exitCode = exitPolicyError
			errorType = "sec_policy_violation"
		}
	}

	payload := map[string]string{
		"error":   errorType,
		"message": err.Error(),
	}
	output, _ := json.Marshal(payload)
	fmt.Fprintln(os.Stderr, string(output))

	return exitCode
}

// extractRootKID extracts the KID from the root (rightmost) token in a chain
// by decoding its payload without verifying the signature.
func extractRootKID(tokenChain string) (string, error) {
	tokens := strings.Split(tokenChain, "..")
	rootToken := strings.TrimSpace(tokens[len(tokens)-1])

	parts := strings.SplitN(rootToken, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid root token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode root token payload: %v", err)
	}

	var partial struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(payloadBytes, &partial); err != nil {
		return "", fmt.Errorf("failed to parse root token KID: %v", err)
	}

	return partial.KID, nil
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
