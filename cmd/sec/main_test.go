package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sec/pkg/contract"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Create temporary directory for building the binary
	tmpDir, err := os.MkdirTemp("", "sec-test-build-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "sec")

	// Compile the CLI binary
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build binary: %v\nOutput:\n%s\n", err, string(output))
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// runSec runs the compiled sec binary with custom environment (HOME env variable override).
func runSec(homeDir string, args ...string) (string, string, int, error) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(os.Environ(), "HOME="+homeDir)
	
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			return stdout.String(), stderr.String(), -1, err
		}
	}

	return stdout.String(), stderr.String(), exitCode, nil
}

func getRawPublicKeyB64(homeDir, kid string) (string, error) {
	pubPath := filepath.Join(homeDir, ".sec", "keys", kid+".pub")
	pemBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", fmt.Errorf("invalid public key PEM block")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	pubKey, ok := pubKeyInterface.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("key is not ed25519 public key")
	}

	return base64.RawURLEncoding.EncodeToString(pubKey), nil
}

func TestCLI_EndToEnd(t *testing.T) {
	// Create ephemeral home dir for this test
	tempHome, err := os.MkdirTemp("", "sec-test-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// 1. Initialize environment (sec init)
	stdout, stderr, exitCode, err := runSec(tempHome, "init")
	if err != nil {
		t.Fatalf("init command failed: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d. stderr: %s", exitCode, stderr)
	}

	// Verify key files were created
	defaultKeyPath := filepath.Join(tempHome, ".sec", "keys", "default.key")
	defaultPubPath := filepath.Join(tempHome, ".sec", "keys", "default.pub")
	if _, err := os.Stat(defaultKeyPath); os.IsNotExist(err) {
		t.Fatalf("expected private key file to exist at %s", defaultKeyPath)
	}
	if _, err := os.Stat(defaultPubPath); os.IsNotExist(err) {
		t.Fatalf("expected public key file to exist at %s", defaultPubPath)
	}

	// 2. Initialize a separate keypair for delegation (sec init --kid session)
	_, _, exitCode, err = runSec(tempHome, "init", "--kid", "session")
	if err != nil || exitCode != 0 {
		t.Fatalf("init --kid session failed: %v, exitCode=%d", err, exitCode)
	}
	sessionPubB64, err := getRawPublicKeyB64(tempHome, "session")
	if err != nil {
		t.Fatalf("failed to load session public key bytes: %v", err)
	}

	// 3. Sign a root contract with default key, including session public key spk
	stdout, stderr, exitCode, err = runSec(tempHome, "sign",
		"--objective", "root task",
		"--allow", "github.issues.read,github.issues.write",
		"--deny", "github.issues.delete",
		"--scope", "repositories=The-17/agentsecrets",
		"--audience", "github",
		"--ttl", "5m",
		"--spk", sessionPubB64,
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}

	rootToken := strings.TrimSpace(stdout)
	if rootToken == "" {
		t.Fatal("expected non-empty token from sign command")
	}

	// Decode root contract to get its JTI for delegation
	parts := strings.Split(rootToken, ".")
	if len(parts) != 2 {
		t.Fatalf("invalid token format: %q", rootToken)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode root payload: %v", err)
	}
	var rootContract contract.SECContract
	if err := json.Unmarshal(payloadBytes, &rootContract); err != nil {
		t.Fatalf("failed to unmarshal root contract: %v", err)
	}
	rootJTI := rootContract.JTI

	// 4. Verify root token directly
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", rootToken,
		"--capability", "github.issues.read",
		"--resource", "The-17/agentsecrets",
		"--audience", "github",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("verify root failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}

	// 5. Verify root token failure (unauthorized capability)
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", rootToken,
		"--capability", "github.issues.delete",
		"--resource", "The-17/agentsecrets",
		"--audience", "github",
	)
	if err != nil {
		t.Fatalf("verify root capability error: %v", err)
	}
	if exitCode != 2 {
		t.Fatalf("expected policy violation exit code 2, got %d. stderr=%s", exitCode, stderr)
	}
	var errPayload map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &errPayload); err != nil {
		t.Fatalf("expected JSON error response on stderr, got: %s. error: %v", stderr, err)
	}
	if errPayload["error"] != "sec_policy_violation" {
		t.Errorf("expected error type 'sec_policy_violation', got %q", errPayload["error"])
	}

	// 6. Sign child contract using the session key, marked as delegated, pointing to rootJTI
	stdout, stderr, exitCode, err = runSec(tempHome, "sign",
		"--kid", "session",
		"--objective", "child delegation task",
		"--allow", "github.issues.read",
		"--deny", "github.issues.delete",
		"--audience", "github",
		"--ttl", "2m",
		"--delegated",
		"--parent-jti", rootJTI,
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign child failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}
	childToken := strings.TrimSpace(stdout)

	// Build the token chain: child_token..root_token
	tokenChain := fmt.Sprintf("%s..%s", childToken, rootToken)

	// 7. Verify the delegation chain successfully
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", tokenChain,
		"--capability", "github.issues.read",
		"--resource", "The-17/agentsecrets",
		"--audience", "github",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("verify delegation chain failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}
	
	var verifiedContract contract.SECContract
	if err := json.Unmarshal([]byte(stdout), &verifiedContract); err != nil {
		t.Fatalf("expected verified contract on stdout: %v, stdout=%s", err, stdout)
	}
	if verifiedContract.Objective != "child delegation task" {
		t.Errorf("expected leaf objective, got %q", verifiedContract.Objective)
	}

	// 8. Verify the delegation chain escalation failure (child attempts github.issues.write which is in root but child only allows read)
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", tokenChain,
		"--capability", "github.issues.write",
		"--resource", "The-17/agentsecrets",
		"--audience", "github",
	)
	if err != nil {
		t.Fatalf("verify delegation chain error: %v", err)
	}
	if exitCode != 2 {
		t.Fatalf("expected policy violation exit code 2, got %d. stderr=%s", exitCode, stderr)
	}

	// 9. Verify invalid signature on token chain
	tamperedChain := tokenChain + "extraBytes"
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", tamperedChain,
		"--capability", "github.issues.read",
		"--resource", "The-17/agentsecrets",
		"--audience", "github",
	)
	if err != nil {
		t.Fatalf("verify tampered chain error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected crypto error exit code 1, got %d. stderr=%s", exitCode, stderr)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &errPayload); err != nil {
		t.Fatalf("expected JSON error response on stderr, got: %s. error: %v", stderr, err)
	}
	if errPayload["error"] != "sec_crypto_error" {
		t.Errorf("expected error type 'sec_crypto_error', got %q", errPayload["error"])
	}

	// 10. Test token-file verification
	tokenFile := filepath.Join(tempHome, "chain.token")
	if err := os.WriteFile(tokenFile, []byte(tokenChain), 0600); err != nil {
		t.Fatalf("failed to write chain token to file: %v", err)
	}
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token-file", tokenFile,
		"--capability", "github.issues.read",
		"--resource", "The-17/agentsecrets",
		"--audience", "github",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("verify token-file failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}

	// 11. Test replay protection of single_use token using E2E cli verification
	// First, sign a single_use token
	stdout, stderr, exitCode, err = runSec(tempHome, "sign",
		"--objective", "single use test",
		"--allow", "github.issues.read",
		"--audience", "github",
		"--replay", "single_use",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign single_use failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}
	singleUseToken := strings.TrimSpace(stdout)

	// Verify first time: success
	_, _, exitCode, err = runSec(tempHome, "verify",
		"--token", singleUseToken,
		"--capability", "github.issues.read",
		"--audience", "github",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("first verify of single_use token failed: %v, exitCode=%d", err, exitCode)
	}

	// Verify second time: fails with crypto error (replay rejection)
	_, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", singleUseToken,
		"--capability", "github.issues.read",
		"--audience", "github",
	)
	if err != nil {
		t.Fatalf("second verify error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected replay rejection exit code 1 (crypto error), got %d. stderr=%s", exitCode, stderr)
	}
	if !strings.Contains(stderr, "replay rejected") {
		t.Errorf("expected error message to contain 'replay rejected', got: %s", stderr)
	}
}

func TestCLI_SignOutFile(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// Initialize
	_, _, exitCode, err := runSec(tempHome, "init")
	if err != nil || exitCode != 0 {
		t.Fatalf("init failed: %v, exitCode=%d", err, exitCode)
	}

	tokenFile := filepath.Join(tempHome, "signed.token")

	// Sign with --out
	stdout, stderr, exitCode, err := runSec(tempHome, "sign",
		"--objective", "out file test",
		"--allow", "github.issues.read",
		"--audience", "github",
		"--out", tokenFile,
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign with --out failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}

	// Verify token was written to file
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		t.Fatalf("expected token file to exist at %s", tokenFile)
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if !strings.Contains(token, ".") {
		t.Fatalf("invalid token format in file: %s", token)
	}
	if stdout != "" {
		t.Fatalf("expected stdout to be empty when --out is specified, got %q", stdout)
	}
}

func TestCLI_MissingRequiredFlags(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// Sign with missing allow
	_, stderr, exitCode, err := runSec(tempHome, "sign",
		"--objective", "missing allow test",
		"--audience", "github",
	)
	if err != nil {
		t.Fatalf("sign command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for missing required flags, got %d", exitCode)
	}
	if !strings.Contains(stderr, "allow is required") {
		t.Errorf("expected stderr to contain 'allow is required', got %q", stderr)
	}

	// Sign with missing objective
	_, stderr, exitCode, err = runSec(tempHome, "sign",
		"--allow", "github.issues.read",
		"--audience", "github",
	)
	if err != nil {
		t.Fatalf("sign command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for missing required flags, got %d", exitCode)
	}
	if !strings.Contains(stderr, "objective is required") {
		t.Errorf("expected stderr to contain 'objective is required', got %q", stderr)
	}

	// Sign with missing audience
	_, stderr, exitCode, err = runSec(tempHome, "sign",
		"--objective", "missing aud test",
		"--allow", "github.issues.read",
	)
	if err != nil {
		t.Fatalf("sign command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for missing required flags, got %d", exitCode)
	}
	if !strings.Contains(stderr, "audience is required") {
		t.Errorf("expected stderr to contain 'audience is required', got %q", stderr)
	}
}

func TestCLI_InvalidExpiry(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// Initialize
	_, _, exitCode, err := runSec(tempHome, "init")
	if err != nil || exitCode != 0 {
		t.Fatalf("init failed: %v", err)
	}

	// Sign with invalid ttl
	_, stderr, exitCode, err := runSec(tempHome, "sign",
		"--objective", "expiry test",
		"--allow", "github.issues.read",
		"--audience", "github",
		"--ttl", "invalid-ttl",
	)
	if err != nil {
		t.Fatalf("sign command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for invalid ttl, got %d", exitCode)
	}
	if !strings.Contains(stderr, "invalid --ttl value") {
		t.Errorf("expected stderr to contain 'invalid --ttl value', got %q", stderr)
	}

	// Sign with short TTL token
	stdout, _, exitCode, err := runSec(tempHome, "sign",
		"--objective", "expired token test",
		"--allow", "github.issues.read",
		"--audience", "github",
		"--ttl", "1s",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign with short ttl failed: %v, exitCode=%d", err, exitCode)
	}
	expiredToken := strings.TrimSpace(stdout)

	// Sleep 1.5s to let the token expire
	time.Sleep(1500 * time.Millisecond)

	// Verify expired token
	_, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", expiredToken,
		"--capability", "github.issues.read",
		"--audience", "github",
	)
	if err != nil {
		t.Fatalf("verify command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected crypto error exit code 1 for expired token, got %d", exitCode)
	}
	if !strings.Contains(stderr, "has expired") {
		t.Errorf("expected stderr to contain 'has expired', got %q", stderr)
	}
}
