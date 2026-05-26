package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sec/pkg/contract"
	"sec/pkg/storage"
)

// setupTestKeys generates an ephemeral keypair for testing without touching ~/.sec/
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
		JTI:          "test-jti-001",
		IAT:          time.Now().Unix(),
		EXP:          time.Now().Add(10 * time.Minute).Unix(),
		Objective:    "unit test",
		Capabilities: []string{"github.issues.read", "github.pull_requests.comment"},
		Denies:       []string{"github.repositories.delete"},
		Scopes:       map[string][]string{"repositories": {"The-17/agentsecrets"}},
		Audience:     []string{"github"},
		ReplayMode:   "reusable",
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

	verified, err := VerifyContractChain(VerifyRequest{
		TokenChain: token,
		RootPubKey: pub,
		Capability: "github.issues.read",
		Resource:   "The-17/agentsecrets",
		ScopeKey:   "repositories",
		Audience:   "github",
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

func TestVerify_DeniedCapability(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: token,
		RootPubKey: pub,
		Capability: "github.repositories.delete",
		Audience:   "github",
	})
	if err == nil {
		t.Fatal("expected verification to fail for denied capability")
	}

	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected VerificationError, got %T", err)
	}
	if !ve.IsPolicy {
		t.Error("denied capability should be a policy error (exit code 2)")
	}
}

func TestVerify_UnauthorizedCapability(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: token,
		RootPubKey: pub,
		Capability: "stripe.charges.create",
		Audience:   "github",
	})
	if err == nil {
		t.Fatal("expected verification to fail for unauthorized capability")
	}
}

func TestVerify_WrongAudience(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: token,
		RootPubKey: pub,
		Capability: "github.issues.read",
		Audience:   "slack",
	})
	if err == nil {
		t.Fatal("expected verification to fail for wrong audience")
	}

	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected VerificationError, got %T", err)
	}
	if !ve.IsPolicy {
		t.Error("audience mismatch should be a policy error")
	}
}

func TestVerify_ScopeMismatch(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: token,
		RootPubKey: pub,
		Capability: "github.issues.read",
		Resource:   "Evil-Org/malware",
		ScopeKey:   "repositories",
		Audience:   "github",
	})
	if err == nil {
		t.Fatal("expected verification to fail for scope mismatch")
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

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: token,
		RootPubKey: pub,
	})
	if err == nil {
		t.Fatal("expected verification to fail for expired token")
	}

	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected VerificationError, got %T", err)
	}
	if ve.IsPolicy {
		t.Error("expired token should be a crypto error (exit code 1), not policy")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	pub, priv := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper with the last character of the signature
	tampered := token[:len(token)-1] + "X"

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: tampered,
		RootPubKey: pub,
	})
	if err == nil {
		t.Fatal("expected verification to fail for tampered signature")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv := setupTestKeys(t)
	otherPub, _ := setupTestKeys(t)
	c := makeTestContract()

	token, err := SignContract(c, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: token,
		RootPubKey: otherPub,
	})
	if err == nil {
		t.Fatal("expected verification to fail with wrong public key")
	}
}

func TestVerify_DelegationChain(t *testing.T) {
	// Root keypair (used to sign the parent contract)
	rootPub, rootPriv := setupTestKeys(t)

	// Session keypair (parent declares spk, uses session priv to sign child)
	sessionPub, sessionPriv := setupTestKeys(t)
	sessionPubB64 := base64.RawURLEncoding.EncodeToString(sessionPub)

	parentContract := makeTestContract(func(c *contract.SECContract) {
		c.JTI = "parent-001"
		c.Capabilities = []string{"github.*"}
		c.Denies = []string{"github.repos.delete"}
		c.SessionPubKey = sessionPubB64
	})

	parentToken, err := SignContract(parentContract, rootPriv)
	if err != nil {
		t.Fatalf("failed to sign parent: %v", err)
	}

	childContract := contract.SECContract{
		JTI:          "child-001",
		IAT:          time.Now().Unix(),
		EXP:          time.Now().Add(5 * time.Minute).Unix(),
		Objective:    "read issues only",
		Capabilities: []string{"github.issues.read"},
		Denies:       []string{"github.repos.delete"},
		Scopes:       map[string][]string{"repositories": {"The-17/agentsecrets"}},
		Audience:     []string{"github"},
		ReplayMode:   "reusable",
		Delegated:    true,
		ParentJTI:    "parent-001",
	}

	childToken, err := SignContract(childContract, sessionPriv)
	if err != nil {
		t.Fatalf("failed to sign child: %v", err)
	}

	chain := BuildDelegatedToken(childToken, parentToken)

	verified, err := VerifyContractChain(VerifyRequest{
		TokenChain: chain,
		RootPubKey: rootPub,
		Capability: "github.issues.read",
		Resource:   "The-17/agentsecrets",
		ScopeKey:   "repositories",
		Audience:   "github",
	})
	if err != nil {
		t.Fatalf("delegation chain verification failed: %v", err)
	}
	if verified.JTI != "child-001" {
		t.Errorf("expected leaf contract JTI child-001, got %s", verified.JTI)
	}
}

func TestVerify_DelegationChain_Escalation(t *testing.T) {
	rootPub, rootPriv := setupTestKeys(t)
	sessionPub, sessionPriv := setupTestKeys(t)
	sessionPubB64 := base64.RawURLEncoding.EncodeToString(sessionPub)

	parentContract := makeTestContract(func(c *contract.SECContract) {
		c.JTI = "parent-001"
		c.Capabilities = []string{"github.issues.read"}
		c.Denies = []string{}
		c.SessionPubKey = sessionPubB64
	})

	parentToken, err := SignContract(parentContract, rootPriv)
	if err != nil {
		t.Fatalf("failed to sign parent: %v", err)
	}

	// Child tries to escalate beyond parent
	childContract := contract.SECContract{
		JTI:          "child-001",
		IAT:          time.Now().Unix(),
		EXP:          time.Now().Add(5 * time.Minute).Unix(),
		Objective:    "evil escalation",
		Capabilities: []string{"github.repos.delete"},
		Denies:       []string{},
		Scopes:       map[string][]string{},
		Audience:     []string{"github"},
		ReplayMode:   "reusable",
		Delegated:    true,
		ParentJTI:    "parent-001",
	}

	childToken, err := SignContract(childContract, sessionPriv)
	if err != nil {
		t.Fatalf("failed to sign child: %v", err)
	}

	chain := BuildDelegatedToken(childToken, parentToken)

	_, err = VerifyContractChain(VerifyRequest{
		TokenChain: chain,
		RootPubKey: rootPub,
		Capability: "github.repos.delete",
		Audience:   "github",
	})
	if err == nil {
		t.Fatal("expected escalation attempt to fail")
	}
}

func TestReplay_SingleUse(t *testing.T) {
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

	jti := "single-use-test-001"
	exp := time.Now().Add(10 * time.Minute).Unix()

	// First use should succeed
	if err := store.CheckAndRecord(jti, exp, "single_use", 0); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}

	// Second use should fail
	if err := store.CheckAndRecord(jti, exp, "single_use", 0); err == nil {
		t.Fatal("second use of single_use token should fail")
	}
}

func TestReplay_Bounded(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "jti_test.db")
	os.Setenv("SEC_DB_PATH_OVERRIDE", dbPath)
	defer os.Unsetenv("SEC_DB_PATH_OVERRIDE")

	store, err := storage.OpenJTIStore()
	if err != nil {
		t.Fatalf("failed to open JTI store: %v", err)
	}
	defer store.Close()

	jti := "bounded-test-001"
	exp := time.Now().Add(10 * time.Minute).Unix()
	maxUses := 3

	// Uses 1-3 should succeed
	for i := 1; i <= maxUses; i++ {
		if err := store.CheckAndRecord(jti, exp, "bounded", maxUses); err != nil {
			t.Fatalf("use %d/%d should succeed: %v", i, maxUses, err)
		}
	}

	// Use 4 should fail
	if err := store.CheckAndRecord(jti, exp, "bounded", maxUses); err == nil {
		t.Fatal("exceeding max_uses should fail")
	}
}

func TestReplay_Reusable(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "jti_test.db")
	os.Setenv("SEC_DB_PATH_OVERRIDE", dbPath)
	defer os.Unsetenv("SEC_DB_PATH_OVERRIDE")

	store, err := storage.OpenJTIStore()
	if err != nil {
		t.Fatalf("failed to open JTI store: %v", err)
	}
	defer store.Close()

	jti := "reusable-test-001"
	exp := time.Now().Add(10 * time.Minute).Unix()

	// Should succeed indefinitely
	for i := 0; i < 100; i++ {
		if err := store.CheckAndRecord(jti, exp, "reusable", 0); err != nil {
			t.Fatalf("reusable token should always succeed: %v", err)
		}
	}
}
