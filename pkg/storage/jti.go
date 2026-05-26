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
// It tracks token usage for single_use and bounded replay modes.
//
// Concurrency safety:
//   - WAL (Write-Ahead Logging) mode enables concurrent readers with a single writer.
//   - busy_timeout prevents SQLITE_BUSY errors under parallel verification loads.
//   - Expired record cleanup runs asynchronously to keep the hot path fast.
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

	// Create the schema
	schema := `
	CREATE TABLE IF NOT EXISTS used_jtis (
		jti  TEXT PRIMARY KEY,
		exp  INTEGER NOT NULL,
		uses INTEGER NOT NULL DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_used_jtis_exp ON used_jtis(exp);
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

// CheckAndRecord validates and records a token's JTI based on its replay mode.
//
// Behavior by mode:
//   - "reusable":   Always passes (no tracking needed).
//   - "single_use": Fails if the JTI has been seen before. Records it on first use.
//   - "bounded":    Fails if usage count has reached max_uses. Increments counter.
func (s *JTIStore) CheckAndRecord(jti string, exp int64, mode string, maxUses int) error {
	if mode == "reusable" {
		return nil
	}

	// Use a transaction for atomicity under concurrent access
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	var uses int
	err = tx.QueryRow("SELECT uses FROM used_jtis WHERE jti = ?", jti).Scan(&uses)

	if err == sql.ErrNoRows {
		// First use — insert the record
		_, err = tx.Exec("INSERT INTO used_jtis (jti, exp, uses) VALUES (?, ?, 1)", jti, exp)
		if err != nil {
			return fmt.Errorf("failed to record JTI: %w", err)
		}
		return tx.Commit()
	}
	if err != nil {
		return fmt.Errorf("failed to query JTI: %w", err)
	}

	// JTI exists — evaluate based on mode
	switch mode {
	case "single_use":
		return fmt.Errorf("replay rejected: token %s has already been used (single_use)", jti)

	case "bounded":
		if uses >= maxUses {
			return fmt.Errorf("replay rejected: token %s has reached max uses (%d/%d)", jti, uses, maxUses)
		}
		_, err = tx.Exec("UPDATE used_jtis SET uses = uses + 1 WHERE jti = ?", jti)
		if err != nil {
			return fmt.Errorf("failed to increment JTI usage: %w", err)
		}
		return tx.Commit()

	default:
		return fmt.Errorf("unknown replay mode %q for existing JTI", mode)
	}
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
