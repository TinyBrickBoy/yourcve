// Package db opens the PostgreSQL pool and runs the migrations (goose for the
// app schema, rivermigrate for the River job tables).
package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if cfg.MaxConns < 20 {
		cfg.MaxConns = 20
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations. Migrations are expand only, so an
// older binary keeps working against a newer schema during rolling updates.
func Migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	sqldb := stdlib.OpenDBFromPool(pool)
	defer sqldb.Close()

	// serialize concurrent starts
	if _, err := sqldb.ExecContext(ctx, `SELECT pg_advisory_lock(7347001)`); err != nil {
		return err
	}
	defer sqldb.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7347001)`) //nolint:errcheck

	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := gooseUp(ctx, sqldb); err != nil {
		return fmt.Errorf("goose: %w", err)
	}

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return err
	}
	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return fmt.Errorf("river migrate: %w", err)
	}
	if len(res.Versions) > 0 {
		log.Info("river migrations applied", "count", len(res.Versions))
	}
	return nil
}

func gooseUp(ctx context.Context, db *sql.DB) error {
	return goose.UpContext(ctx, db, "migrations")
}
