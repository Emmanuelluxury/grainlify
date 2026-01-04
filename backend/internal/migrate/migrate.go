package migrate

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/jagadeesh/grainlify/backend/migrations"
)

func Up(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("db pool is nil")
	}

	slog.Info("loading embedded migration files")
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		slog.Error("failed to load embedded migrations",
			"error", err,
			"error_type", fmt.Sprintf("%T", err),
		)
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	slog.Info("embedded migrations loaded")

	slog.Info("opening database connection for migrations")
	sqlDB := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer sqlDB.Close()

	// Set lock_timeout BEFORE creating the postgres driver
	// The driver uses pg_advisory_lock which needs the timeout set on the connection first
	// Increase timeout to 60s to handle concurrent deployments better
	slog.Info("setting lock timeout for migration connection", "timeout", "60s")
	_, err = sqlDB.ExecContext(ctx, "SET lock_timeout = '60s'")
	if err != nil {
		slog.Warn("failed to set lock_timeout, continuing anyway",
			"error", err,
		)
	}

	slog.Info("creating postgres migration driver")
	// Configure postgres driver with lock timeout to handle concurrent migrations
	db, err := postgres.WithInstance(sqlDB, &postgres.Config{
		MigrationsTable:       "schema_migrations",
		DatabaseName:          "",
		SchemaName:            "",
		StatementTimeout:      0,
		MultiStatementEnabled: false,
	})
	if err != nil {
		slog.Error("failed to create postgres migration driver",
			"error", err,
			"error_type", fmt.Sprintf("%T", err),
		)
		return fmt.Errorf("create postgres migration driver: %w", err)
	}

	slog.Info("creating migrator instance")
	m, err := migrate.NewWithInstance("iofs", src, "postgres", db)
	if err != nil {
		slog.Error("failed to create migrator",
			"error", err,
			"error_type", fmt.Sprintf("%T", err),
		)
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() {
		slog.Info("closing migrator")
		_, _ = m.Close()
	}()

	// Check current version before migrating
	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		slog.Warn("could not get current migration version",
			"error", err,
		)
	} else {
		slog.Info("current migration version",
			"version", version,
			"dirty", dirty,
		)
	}

	// migrate.Up() is not context-aware; we still accept ctx for future evolutions.
	_ = ctx

	slog.Info("running database migrations")
	
	// Try to run migrations with retry logic for lock timeouts
	// This handles cases where multiple instances start simultaneously in deployments
	maxRetries := 5
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			// Exponential backoff: 2s, 4s, 8s, 16s
			waitTime := time.Duration(1<<uint(attempt-2)) * 2 * time.Second
			slog.Info("retrying migration after lock timeout",
				"attempt", attempt,
				"max_retries", maxRetries,
				"wait_time", waitTime,
			)
			time.Sleep(waitTime)
			
			// Reset lock_timeout for retry attempts
			_, err := sqlDB.ExecContext(ctx, "SET lock_timeout = '60s'")
			if err != nil {
				slog.Warn("failed to reset lock_timeout on retry",
					"error", err,
				)
			}
		}
		
		err := m.Up()
		if err == nil || err == migrate.ErrNoChange {
			lastErr = err
			break
		}
		
		// Check if it's a lock timeout error (SQLSTATE 55P03)
		errStr := err.Error()
		isLockError := contains(errStr, "timeout") || 
			contains(errStr, "lock") || 
			contains(errStr, "can't acquire") ||
			contains(errStr, "55P03") ||
			contains(errStr, "lock timeout")
		
		if attempt < maxRetries && isLockError {
			slog.Warn("migration lock timeout, will retry",
				"attempt", attempt,
				"max_retries", maxRetries,
				"error", err,
			)
			lastErr = err
			continue
		}
		
		// For other errors or final attempt, return immediately
		lastErr = err
		break
	}
	
	if lastErr != nil && lastErr != migrate.ErrNoChange {
		slog.Error("migration failed after retries",
			"error", lastErr,
			"error_type", fmt.Sprintf("%T", lastErr),
		)
		return lastErr
	}
	
	err = lastErr

	if err == migrate.ErrNoChange {
		slog.Info("migrations up to date, no changes needed")
	} else {
		// Get version after migration
		newVersion, _, verErr := m.Version()
		if verErr == nil {
			slog.Info("migrations completed successfully",
				"new_version", newVersion,
			)
		} else {
			slog.Info("migrations completed successfully")
		}
	}

	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}


