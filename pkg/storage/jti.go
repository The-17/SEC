package storage

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	_ "github.com/glebarez/go-sqlite"

	"sec/pkg/config"
)

// JTIStore manages replay protection state using a local SQLite database.
// It tracks token usage to prevent reuse of signed contracts.
type JTIStore struct {
	db          *sql.DB
	cleanupOnce sync.Once
}

// OpenJTIStore opens (or creates) the SQLite JTI database at ~/.sec/jti.db
// and configures it for concurrent access patterns.
func OpenJTIStore() (*JTIStore, error) {
	// Allow path override for testing (avoids touching ~/.sec/)
	dbPath := os.Getenv("SEC_DB_PATH_OVERRIDE")
	if dbPath == "" {
		var err error
		dbPath, err = config.GetDBPath()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve JTI database path: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JTI database: %w", err)
	}

	// Configure SQLite for concurrent access
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", pragma, err)
		}
	}

	// Create the schema conforming to Spec v4.0
	schema := `
	CREATE TABLE IF NOT EXISTS used_jtis (
		jti  TEXT PRIMARY KEY,
		exp  INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_exp ON used_jtis(exp);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize JTI schema: %w", err)
	}

	store := &JTIStore{db: db}

	// Schedule async cleanup of expired records (runs once per store lifetime)
	store.cleanupOnce.Do(func() {
		go store.cleanupExpired()
	})

	return store, nil
}

// CheckAndRecord validates and records a token's JTI.
// Returns an error if the JTI has been seen before (replay protection).
func (s *JTIStore) CheckAndRecord(jti string, exp int64) error {
	// Use a transaction for atomicity under concurrent access
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var existingJTI string
	err = tx.QueryRow("SELECT jti FROM used_jtis WHERE jti = ?", jti).Scan(&existingJTI)

	if err == sql.ErrNoRows {
		// First use — insert the record
		_, err = tx.Exec("INSERT INTO used_jtis (jti, exp) VALUES (?, ?)", jti, exp)
		if err != nil {
			return fmt.Errorf("failed to record JTI: %w", err)
		}
		return tx.Commit()
	}
	if err != nil {
		return fmt.Errorf("failed to query JTI: %w", err)
	}

	// JTI exists — replay detected
	return fmt.Errorf("replay rejected: token %s has already been used", jti)
}

// Revoke proactively records a JTI as used/revoked.
// If the JTI is already recorded, it does nothing and returns nil.
func (s *JTIStore) Revoke(jti string, exp int64) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO used_jtis (jti, exp) VALUES (?, ?)", jti, exp)
	if err != nil {
		return fmt.Errorf("failed to revoke JTI: %w", err)
	}
	return nil
}

// cleanupExpired removes expired JTI records from the database.
// This runs asynchronously in a goroutine to avoid blocking the verification path.
func (s *JTIStore) cleanupExpired() {
	now := time.Now().Unix()
	_, _ = s.db.Exec("DELETE FROM used_jtis WHERE exp < ?", now)
}

// Close releases the database connection.
func (s *JTIStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetRecordCount returns the total number of records in the JTI store.
func (s *JTIStore) GetRecordCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM used_jtis").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count JTI records: %w", err)
	}
	return count, nil
}
