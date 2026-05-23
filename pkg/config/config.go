package config

import (
	"os"
	"path/filepath"
)

// GetSECConfigDir returns the path to ~/.sec directory.
// Exported functions must be capitalized to be visible outside this package.
func GetSECConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".sec"), nil
}

// GetKeysDir returns the path to ~/.sec/keys directory.
func GetKeysDir() (string, error) {
	configDir, err := GetSECConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "keys"), nil
}

// GetDBPath returns the path to ~/.sec/jti.db SQLite database file.
func GetDBPath() (string, error) {
	configDir, err := GetSECConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "jti.db"), nil
}
