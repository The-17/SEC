package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sec/pkg/config"
)

// ValidateKID checks if a key ID is safe to use as a file name,
// preventing path traversal attacks (e.g. "../default").
func ValidateKID(kid string) error {
	if kid == "" {
		return fmt.Errorf("KID cannot be empty")
	}
	for _, r := range kid {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("invalid KID %q: must contain only alphanumeric characters, underscores, or dashes", kid)
		}
	}
	return nil
}

// GenerateKeyPair generates an Ed25519 keypair and writes it to ~/.sec/keys/<kid>.key and <kid>.pub.
func GenerateKeyPair(kid string) error {
	if err := ValidateKID(kid); err != nil {
		return err
	}

	// 1. Generate Ed25519 key pair in memory
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	keysDir, err := config.GetKeysDir()
	if err != nil {
		return fmt.Errorf("failed to get keys directory: %w", err)
	}

	// 2. Create the directory with 0700 (Owner-only Read/Write/Execute)
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// 3. Encode the private key to PKCS#8 PEM format
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	privPEM := pem.EncodeToMemory(privBlock)

	// 4. Encode the public key to PKIX PEM format
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	pubPEM := pem.EncodeToMemory(pubBlock)

	// 5. Write files with strict OS-level permissions
	privPath := filepath.Join(keysDir, kid+".key")
	pubPath := filepath.Join(keysDir, kid+".pub")

	// 0600 = Owner read/write only
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// 0644 = Owner read/write, public read
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// LoadPrivateKey loads and decodes an Ed25519 private key from ~/.sec/keys/<kid>.key.
func LoadPrivateKey(kid string) (ed25519.PrivateKey, error) {
	if err := ValidateKID(kid); err != nil {
		return nil, err
	}

	keysDir, err := config.GetKeysDir()
	if err != nil {
		return nil, err
	}
	privPath := filepath.Join(keysDir, kid+".key")

	pemBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block for private key")
	}

	privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Type assertion: converting interface{} to ed25519.PrivateKey
	privKey, ok := privKeyInterface.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 private key")
	}

	return privKey, nil
}

// LoadPublicKey loads and decodes an Ed25519 public key from ~/.sec/keys/<kid>.pub.
func LoadPublicKey(kid string) (ed25519.PublicKey, error) {
	if err := ValidateKID(kid); err != nil {
		return nil, err
	}

	keysDir, err := config.GetKeysDir()
	if err != nil {
		return nil, err
	}
	pubPath := filepath.Join(keysDir, kid+".pub")

	pemBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block for public key")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Type assertion: converting interface{} to ed25519.PublicKey
	pubKey, ok := pubKeyInterface.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 public key")
	}

	return pubKey, nil
}
