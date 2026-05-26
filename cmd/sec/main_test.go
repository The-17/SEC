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

	// 2. Sign a valid contract
	stdout, stderr, exitCode, err = runSec(tempHome, "sign",
		"--objective", "summarise open pulls",
		"--allow", "api.github.com/repos/The-17/agentsecrets/pulls*",
		"--ttl", "5m",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}

	token := strings.TrimSpace(stdout)
	if token == "" {
		t.Fatal("expected non-empty token from sign command")
	}

	// 3. Verify token successfully
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", token,
		"--action", "api.github.com/repos/The-17/agentsecrets/pulls/42",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("verify failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}

	var verifiedContract contract.SECContract
	if err := json.Unmarshal([]byte(stdout), &verifiedContract); err != nil {
		t.Fatalf("failed to parse verified contract JSON output: %v", err)
	}
	if verifiedContract.Objective != "summarise open pulls" {
		t.Errorf("expected objective 'summarise open pulls', got %q", verifiedContract.Objective)
	}

	// 4. Verify policy violation (unauthorized action)
	// We need a fresh token because the first one has already been marked as used (replayed)
	stdout, stderr, exitCode, err = runSec(tempHome, "sign",
		"--objective", "summarise open pulls",
		"--allow", "api.github.com/repos/The-17/agentsecrets/pulls*",
		"--ttl", "5m",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign second token failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}
	token2 := strings.TrimSpace(stdout)

	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", token2,
		"--action", "api.stripe.com/v1/transfers",
	)
	if err != nil {
		t.Fatalf("verify command error: %v", err)
	}
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 (policy violation), got %d. stderr=%s", exitCode, stderr)
	}

	var errPayload map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &errPayload); err != nil {
		t.Fatalf("expected JSON error response on stderr, got: %s. error: %v", stderr, err)
	}
	if errPayload["error"] != "SEC_ACTION_NOT_PERMITTED" {
		t.Errorf("expected error code SEC_ACTION_NOT_PERMITTED, got %q", errPayload["error"])
	}

	// 5. Verify replay protection (first verification records the JTI, second verification on same store should fail)
	// Note: runSec above verified the token once. Since we run in the same homeDir environment,
	// the JTI store persists in tempHome/.sec/jti.db.
	// So doing a new verify command on the same token should fail!
	stdout, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", token,
		"--action", "api.github.com/repos/The-17/agentsecrets/pulls/42",
	)
	if err != nil {
		t.Fatalf("verify command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 (replay rejected), got %d. stderr=%s", exitCode, stderr)
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &errPayload); err != nil {
		t.Fatalf("expected JSON error response on stderr, got: %s", stderr)
	}
	if errPayload["error"] != "SEC_TOKEN_REPLAYED" {
		t.Errorf("expected error type SEC_TOKEN_REPLAYED, got %q", errPayload["error"])
	}

	// 6. Test CLI status subcommand
	stdout, stderr, exitCode, err = runSec(tempHome, "status")
	if err != nil || exitCode != 0 {
		t.Fatalf("status command failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}
	if !strings.Contains(stdout, "Initialized:   Yes") {
		t.Errorf("expected status output to show Initialized: Yes, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Active JTIs:   2") {
		t.Errorf("expected status output to show Active JTIs: 2, got:\n%s", stdout)
	}
}

func TestCLI_SignOutFile(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	_, _, exitCode, err := runSec(tempHome, "init")
	if err != nil || exitCode != 0 {
		t.Fatalf("init failed: %v, exitCode=%d", err, exitCode)
	}

	tokenFile := filepath.Join(tempHome, "signed.token")

	stdout, stderr, exitCode, err := runSec(tempHome, "sign",
		"--objective", "out file test",
		"--allow", "api.github.com/repos/*",
		"--out", tokenFile,
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign with --out failed: %v, exitCode=%d, stderr=%s", err, exitCode, stderr)
	}

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
		"--allow", "api.github.com/repos/*",
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
}

func TestCLI_InvalidExpiry(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	_, _, exitCode, err := runSec(tempHome, "init")
	if err != nil || exitCode != 0 {
		t.Fatalf("init failed: %v", err)
	}

	// Sign with invalid ttl
	_, stderr, exitCode, err := runSec(tempHome, "sign",
		"--objective", "expiry test",
		"--allow", "api.github.com/repos/*",
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
		"--allow", "api.github.com/repos/*",
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
		"--action", "api.github.com/repos/The-17/agentsecrets",
	)
	if err != nil {
		t.Fatalf("verify command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for expired token, got %d", exitCode)
	}

	var errPayload map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &errPayload); err != nil {
		t.Fatalf("expected JSON error response on stderr, got: %s", stderr)
	}
	if errPayload["error"] != "SEC_TOKEN_EXPIRED" {
		t.Errorf("expected error type SEC_TOKEN_EXPIRED, got %q", errPayload["error"])
	}
}

func TestCLI_Revoke(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-revoke-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// 1. Initialize environment
	_, _, exitCode, err := runSec(tempHome, "init")
	if err != nil || exitCode != 0 {
		t.Fatalf("init failed: %v", err)
	}

	// 2. Sign a token
	stdout, _, exitCode, err := runSec(tempHome, "sign",
		"--objective", "revoke test",
		"--allow", "api.github.com/repos/*",
		"--ttl", "5m",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign failed: %v", err)
	}
	token := strings.TrimSpace(stdout)

	// Write token to file for revoke command
	tokenPath := filepath.Join(tempHome, "token.sec")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	// 3. Revoke using token-file
	_, stderr, exitCode, err := runSec(tempHome, "revoke", "--token-file", tokenPath)
	if err != nil || exitCode != 0 {
		t.Fatalf("revoke failed: %v, stderr=%s", err, stderr)
	}

	// 4. Verify should fail with SEC_TOKEN_REPLAYED
	_, stderr, exitCode, err = runSec(tempHome, "verify",
		"--token", token,
		"--action", "api.github.com/repos/The-17/agentsecrets",
	)
	if err != nil {
		t.Fatalf("verify command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 after revocation, got %d", exitCode)
	}
	var errPayload map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &errPayload); err != nil {
		t.Fatalf("expected JSON error response on stderr, got: %s", stderr)
	}
	if errPayload["error"] != "SEC_TOKEN_REPLAYED" {
		t.Errorf("expected error type SEC_TOKEN_REPLAYED, got %q", errPayload["error"])
	}

	// 5. Test revoking by raw JTI
	parts := strings.Split(token, ".")
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var parsed struct {
		JTI string `json:"jti"`
	}
	_ = json.Unmarshal(payloadBytes, &parsed)
	jti := parsed.JTI

	// Re-verify the error message of revoke with invalid JTI UUID
	_, _, exitCode, err = runSec(tempHome, "revoke", "--jti", "invalid-jti-uuid")
	if err != nil || exitCode != 1 {
		t.Fatalf("expected revoke to fail with invalid uuid, got exitCode=%d", exitCode)
	}

	// Revoke by raw JTI (idempotent, should succeed)
	_, _, exitCode, err = runSec(tempHome, "revoke", "--jti", jti)
	if err != nil || exitCode != 0 {
		t.Fatalf("revoke by JTI failed: %v", err)
	}
}

func TestCLI_Delegate(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-delegate-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// 1. Initialize environment
	_, _, exitCode, err := runSec(tempHome, "init")
	if err != nil || exitCode != 0 {
		t.Fatalf("init failed: %v", err)
	}

	// 2. Sign parent token
	stdout, _, exitCode, err := runSec(tempHome, "sign",
		"--objective", "parent contract",
		"--allow", "GET:api.github.com/repos/*,POST:api.github.com/issues/*",
		"--ttl", "10m",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign parent failed: %v", err)
	}
	parentToken := strings.TrimSpace(stdout)

	parentPath := filepath.Join(tempHome, "parent.sec")
	if err := os.WriteFile(parentPath, []byte(parentToken), 0600); err != nil {
		t.Fatalf("failed to write parent token: %v", err)
	}

	// 3. Delegate child token with valid subset
	stdout, _, exitCode, err = runSec(tempHome, "delegate",
		"--parent", parentPath,
		"--objective", "child contract",
		"--allow", "GET:api.github.com/repos/The-17/agentsecrets/pulls*",
		"--ttl", "5m",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("delegate failed: %v, stdout=%s", err, stdout)
	}
	childToken := strings.TrimSpace(stdout)

	// Verify child token works
	stdout, _, exitCode, err = runSec(tempHome, "verify",
		"--token", childToken,
		"--action", "GET:api.github.com/repos/The-17/agentsecrets/pulls/12",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("verify child token failed: %v, exitCode=%d, stdout=%s", err, exitCode, stdout)
	}

	// 4. Try delegating invalid subset (escalation to POST)
	_, stderr, exitCode, err := runSec(tempHome, "delegate",
		"--parent", parentPath,
		"--objective", "child contract",
		"--allow", "POST:api.github.com/repos/The-17/agentsecrets/pulls*",
		"--ttl", "5m",
	)
	if err != nil {
		t.Fatalf("delegate command error: %v", err)
	}
	if exitCode != 1 {
		t.Fatalf("expected delegation to fail, got exitCode=%d", exitCode)
	}
	if !strings.Contains(stderr, "delegation error") {
		t.Errorf("expected error to contain 'delegation error', got %q", stderr)
	}
}

func TestCLI_Provenance(t *testing.T) {
	tempHome, err := os.MkdirTemp("", "sec-test-home-provenance-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// 1. Initialize environment
	_, _, exitCode, err := runSec(tempHome, "init")
	if err != nil || exitCode != 0 {
		t.Fatalf("init failed: %v", err)
	}

	// 2. Sign token with provenance flags
	stdout, _, exitCode, err := runSec(tempHome, "sign",
		"--objective", "provenance test",
		"--allow", "api.github.com/repos/*",
		"--signer", "my-orchestrator",
		"--run-id", "my-run-1234",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("sign failed: %v", err)
	}
	token := strings.TrimSpace(stdout)

	// 3. Verify and verify provenance fields in verified JSON
	stdout, _, exitCode, err = runSec(tempHome, "verify",
		"--token", token,
		"--action", "api.github.com/repos/The-17/agentsecrets",
	)
	if err != nil || exitCode != 0 {
		t.Fatalf("verify failed: %v", err)
	}

	var verified struct {
		Signer string `json:"signer"`
		RunID  string `json:"run_id"`
	}
	if err := json.Unmarshal([]byte(stdout), &verified); err != nil {
		t.Fatalf("failed to parse verified output JSON: %v, stdout=%s", err, stdout)
	}

	if verified.Signer != "my-orchestrator" {
		t.Errorf("expected signer to be 'my-orchestrator', got %q", verified.Signer)
	}
	if verified.RunID != "my-run-1234" {
		t.Errorf("expected run_id to be 'my-run-1234', got %q", verified.RunID)
	}
}
