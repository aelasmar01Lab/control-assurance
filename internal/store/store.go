// Package store is the application's PostgreSQL access.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/pack"
)

// Store reads and writes the application database.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to the database at databaseURL.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// Read every timestamp in UTC, so that exported history is the same
	// bytes whatever time zone the machine is in.
	cfg.AfterConnect = func(_ context.Context, conn *pgx.Conn) error {
		conn.TypeMap().RegisterType(&pgtype.Type{
			Name: "timestamptz", OID: pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC},
		})
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// inTx runs fn in a transaction, committing if it returns nil.
func (s *Store) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ImportPack writes a framework version and its requirements. Importing the
// same pack again is a no-op; importing different content under an existing
// key and version is an error, because framework rows never change.
func (s *Store) ImportPack(ctx context.Context, p *pack.Pack) (imported bool, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		f := p.Framework
		var existing string
		err := tx.QueryRow(ctx,
			`SELECT content_sha256 FROM framework_versions WHERE key = $1 AND version = $2`,
			f.Key, f.Version).Scan(&existing)
		switch {
		case err == nil && existing == p.ContentSHA256:
			return nil
		case err == nil:
			return fmt.Errorf("%s %s is already imported with different content (%s); a changed pack needs a new version",
				f.Key, f.Version, existing)
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}

		var id int64
		err = tx.QueryRow(ctx, `
			INSERT INTO framework_versions
				(key, title, version, license, source_repository, source_commit,
				 source_path, source_retrieved, source_sha256, content_sha256)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::date, $9, $10)
			RETURNING id`,
			f.Key, f.Title, f.Version, f.License, f.Source.Repository, f.Source.Commit,
			f.Source.Path, f.Source.Retrieved, f.Source.SHA256, p.ContentSHA256).Scan(&id)
		if err != nil {
			return err
		}
		for i, r := range p.Requirements {
			_, err := tx.Exec(ctx, `
				INSERT INTO requirements (framework_version_id, identifier, group_title, title, body, position)
				VALUES ($1, $2, $3, $4, $5, $6)`,
				id, r.ID, r.Group, r.Title, r.Text, i+1)
			if err != nil {
				return err
			}
		}
		imported = true
		return nil
	})
	return imported, err
}

// UpsertResource records an in-scope resource and returns its id.
func (s *Store) UpsertResource(ctx context.Context, provider, kind, externalID, decidedBy string, at time.Time) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO resources (provider, kind, external_id, scope, decided_by, created_at)
		VALUES ($1, $2, $3, 'in_scope', $4, $5)
		ON CONFLICT (provider, kind, external_id) DO UPDATE SET provider = EXCLUDED.provider
		RETURNING id`,
		provider, kind, externalID, decidedBy, at).Scan(&id)
	return id, err
}

// SyncCheckVersion records a check version the first time it is used, and
// refuses to continue if a recorded version no longer matches the code.
func (s *Store) SyncCheckVersion(ctx context.Context, c check.Check) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO check_versions (key, version, observation_kind, assertion, establishes, does_not_establish)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (key, version) DO NOTHING`,
		c.Key, c.Version, c.ObservationKind, c.Assertion, c.Establishes, c.DoesNotEstablish)
	if err != nil {
		return err
	}
	var kind, assertion, establishes, doesNot string
	err = s.pool.QueryRow(ctx, `
		SELECT observation_kind, assertion, establishes, does_not_establish
		FROM check_versions WHERE key = $1 AND version = $2`,
		c.Key, c.Version).Scan(&kind, &assertion, &establishes, &doesNot)
	if err != nil {
		return err
	}
	if kind != c.ObservationKind || assertion != c.Assertion || establishes != c.Establishes || doesNot != c.DoesNotEstablish {
		return fmt.Errorf("check %s version %s differs from the version already recorded; changing a check means a new version",
			c.Key, c.Version)
	}
	return nil
}

// PendingObservation is an observation a check version has not yet evaluated.
type PendingObservation struct {
	ID            int64
	ResourceID    int64
	PayloadSHA256 string
	// AsOf is the source's own timestamp when it gave one, otherwise the
	// time of collection.
	AsOf time.Time
}

// PendingObservations returns the observations of c's kind that c has not
// evaluated, oldest first.
func (s *Store) PendingObservations(ctx context.Context, c check.Check) ([]PendingObservation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT o.id, o.resource_id, o.payload_sha256, COALESCE(o.source_timestamp, o.collected_at)
		FROM observations o
		WHERE o.kind = $3
		  AND NOT EXISTS (
			SELECT 1 FROM evaluations e
			WHERE e.observation_id = o.id AND e.check_key = $1 AND e.check_version = $2)
		ORDER BY o.id`,
		c.Key, c.Version, c.ObservationKind)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[PendingObservation])
}

// FindingChange says what recording an evaluation did to findings.
type FindingChange string

// The possible finding changes.
const (
	FindingUnchanged FindingChange = ""
	FindingOpened    FindingChange = "opened"
	FindingClosed    FindingChange = "closed"
)

// RecordEvaluation stores one evaluation and applies its effect on findings:
// a fail opens a finding if none is open, a pass closes the open one, and
// not_evaluated changes nothing.
//
// Findings only move when the observation is newer than any this check has
// already evaluated for the resource, so replaying history under a new check
// version adds evaluations without rewriting what happened.
func (s *Store) RecordEvaluation(ctx context.Context, o PendingObservation, c check.Check, result check.Result, explanation string, at time.Time) (evaluationID int64, change FindingChange, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var newestEvaluated int64
		err := tx.QueryRow(ctx, `
			SELECT COALESCE(max(e.observation_id), 0)
			FROM evaluations e JOIN observations ob ON ob.id = e.observation_id
			WHERE e.check_key = $1 AND ob.resource_id = $2`,
			c.Key, o.ResourceID).Scan(&newestEvaluated)
		if err != nil {
			return err
		}

		err = tx.QueryRow(ctx, `
			INSERT INTO evaluations (observation_id, check_key, check_version, result, explanation, evaluated_at)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			o.ID, c.Key, c.Version, string(result), explanation, at).Scan(&evaluationID)
		if err != nil {
			return err
		}
		if o.ID <= newestEvaluated {
			return nil
		}

		switch result {
		case check.Fail:
			tag, err := tx.Exec(ctx, `
				INSERT INTO findings (check_key, resource_id, opening_evaluation_id, opened_at)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (check_key, resource_id) WHERE closing_evaluation_id IS NULL DO NOTHING`,
				c.Key, o.ResourceID, evaluationID, at)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				change = FindingOpened
			}
		case check.Pass:
			tag, err := tx.Exec(ctx, `
				UPDATE findings SET closing_evaluation_id = $3, closed_at = $4
				WHERE check_key = $1 AND resource_id = $2 AND closing_evaluation_id IS NULL`,
				c.Key, o.ResourceID, evaluationID, at)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				change = FindingClosed
			}
		}
		return nil
	})
	return evaluationID, change, err
}
