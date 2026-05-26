package crypto

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sec/pkg/contract"
	"sec/pkg/storage"
)

// setupTestKeys generates an ephemeral keypair for testing
func setupTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate test keys: %v", err)
	}
	return pub, priv
}

func makeTestContract(overrides ...func(*contract.SECContract)) contract.SECContract {
	c := contract.SECContract{
		JTI:       "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
		KID:       "default",
		IAT:       time.Now().Unix(),
		EXP:       time.Now().Add(10 * time.Minute).Unix(),
		Objective: "unit test",
		Allowed:   []string{"api.github.com/repos/The-17/agentsecrets/pulls*"},
	}
	for _, o := range overrides {
		o(&c)
	}
	return c
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	verified, err := VerifyContract(VerifyRequest{
		Token:      token,
		Action:     "api.github.com/repos/The-17/agentsecrets/pulls/42",
		RootPubKey: pub,
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	if verified.JTI != c.JTI {
		t.Errorf("JTI mismatch: got %q, want %q", verified.JTI, c.JTI)
	}
	if verified.Objective != c.Objective {
		t.Errorf("Objective mismatch: got %q, want %q", verified.Objective, c.Objective)
	}
}

func TestVerify_UnauthorizedAction(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = VerifyContract(VerifyRequest{
		Token:      token,
		Action:     "api.stripe.com/v1/transfers",
		RootPubKey: pub,
	})
	if err == nil {
		t.Fatal("expected verification to fail for unauthorized action")
	}

	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected VerificationError, got %T", err)
	}
	if ve.Code != "SEC_ACTION_NOT_PERMITTED" {
		t.Errorf("expected error code SEC_ACTION_NOT_PERMITTED, got %q", ve.Code)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract(func(c *contract.SECContract) {
		c.IAT = time.Now().Add(-2 * time.Hour).Unix()
		c.EXP = time.Now().Add(-1 * time.Hour).Unix()
	})

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = VerifyContract(VerifyRequest{
		Token:      token,
		Action:     "api.github.com/repos/The-17/agentsecrets/pulls/42",
		RootPubKey: pub,
	})
	if err == nil {
		t.Fatal("expected verification to fail for expired token")
	}

	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected VerificationError, got %T", err)
	}
	if ve.Code != "SEC_TOKEN_EXPIRED" {
		t.Errorf("expected error code SEC_TOKEN_EXPIRED, got %q", ve.Code)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper with the last few characters of the signature to ensure bits change
	tampered := token[:len(token)-5] + "XXXXX"

	_, err = VerifyContract(VerifyRequest{
		Token:      tampered,
		Action:     "api.github.com/repos/The-17/agentsecrets/pulls/42",
		RootPubKey: pub,
	})
	if err == nil {
		t.Fatal("expected verification to fail for tampered signature")
	}

	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected VerificationError, got %T", err)
	}
	if ve.Code != "SEC_INVALID_SIGNATURE" {
		t.Errorf("expected error code SEC_INVALID_SIGNATURE, got %q", ve.Code)
	}
}

func TestVerify_ReplayProtection(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Set up a temp SQLite database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "jti_test.db")
	os.Setenv("SEC_DB_PATH_OVERRIDE", dbPath)
	defer os.Unsetenv("SEC_DB_PATH_OVERRIDE")

	store, err := storage.OpenJTIStore()
	if err != nil {
		t.Fatalf("failed to open JTI store: %v", err)
	}
	defer store.Close()

	// First verify: success
	_, err = VerifyContract(VerifyRequest{
		Token:      token,
		Action:     "api.github.com/repos/The-17/agentsecrets/pulls/42",
		RootPubKey: pub,
		JTIStore:   store,
	})
	if err != nil {
		t.Fatalf("first verification failed: %v", err)
	}

	// Second verify: failure (replay)
	_, err = VerifyContract(VerifyRequest{
		Token:      token,
		Action:     "api.github.com/repos/The-17/agentsecrets/pulls/42",
		RootPubKey: pub,
		JTIStore:   store,
	})
	if err == nil {
		t.Fatal("expected second verification to fail due to replay protection")
	}

	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected VerificationError, got %T", err)
	}
	if ve.Code != "SEC_TOKEN_REPLAYED" {
		t.Errorf("expected error code SEC_TOKEN_REPLAYED, got %q", ve.Code)
	}
}

func TestValidateKID(t *testing.T) {
	tests := []struct {
		kid     string
		wantErr bool
	}{
		{"default", false},
		{"session-key-1", false},
		{"key_2", false},
		{"", true},
		{"../default", true},
		{"/etc/passwd", true},
		{"default.key", true},
		{"default!", true},
	}

	for _, tt := range tests {
		err := ValidateKID(tt.kid)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateKID(%q) error = %v, wantErr = %v", tt.kid, err, tt.wantErr)
		}
	}
}
