package main

import (
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
