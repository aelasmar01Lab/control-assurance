package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Resource is something a check can be about.
type Resource struct {
	ID         int64
	Provider   string
	Kind       string
	ExternalID string
}

// InScopeResources returns every in-scope resource.
func (s *Store) InScopeResources(ctx context.Context) ([]Resource, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, kind, external_id FROM resources
		WHERE scope = 'in_scope' ORDER BY provider, external_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Resource])
}

// NewRun describes a collection attempt to queue.
type NewRun struct {
	Integration string
	Kind        string
	ResourceID  int64
	// Cause is manual or schedule. Retries are queued by FailRun.
	Cause    string
	RunAfter time.Time
}

// EnqueueRun queues a collection attempt and returns its id. A job has at
// most one unfinished attempt: when one already exists nothing is added,
// queued is false and the existing attempt's id is returned. A manual
// request also brings a waiting retry forward to now. actorID, when not
// zero, is written to the decision log for a newly queued attempt.
func (s *Store) EnqueueRun(ctx context.Context, actorID int64, n NewRun, now time.Time) (id int64, queued bool, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO collection_runs (integration, kind, resource_id, outcome, cause, queued_at, run_after)
			VALUES ($1, $2, $3, 'queued', $4, $5, $6)
			ON CONFLICT (kind, resource_id) WHERE outcome IN ('queued', 'running') DO NOTHING
			RETURNING id`,
			n.Integration, n.Kind, n.ResourceID, n.Cause, now, n.RunAfter).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			if n.Cause == "manual" {
				if _, err := tx.Exec(ctx, `
					UPDATE collection_runs SET run_after = $3
					WHERE kind = $1 AND resource_id = $2 AND outcome = 'queued' AND run_after > $3`,
					n.Kind, n.ResourceID, now); err != nil {
					return err
				}
			}
			return tx.QueryRow(ctx, `
				SELECT id FROM collection_runs
				WHERE kind = $1 AND resource_id = $2 AND outcome IN ('queued', 'running')`,
				n.Kind, n.ResourceID).Scan(&id)
		}
		if err != nil {
			return err
		}
		queued = true
		if actorID != 0 {
			return logTx(ctx, tx, actorID, "collection.queued", "collection_run", id, n.Kind+" ("+n.Cause+")", now)
		}
		return nil
	})
	return id, queued, err
}

// ClaimedRun is a queued attempt a worker has taken.
type ClaimedRun struct {
	ID          int64
	Integration string
	Kind        string
	ResourceID  int64
	Attempt     int
	Target      string // the resource's external id
}

// ClaimRun takes the oldest due attempt of one of the given kinds and marks
// it running, with a lease. Rows another worker is claiming are skipped, so
// two workers never take the same attempt. It returns nil when nothing is due.
func (s *Store) ClaimRun(ctx context.Context, kinds []string, now, leaseUntil time.Time) (*ClaimedRun, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE collection_runs c
		SET outcome = 'running', started_at = $2, lease_expires_at = $3
		FROM resources r
		WHERE r.id = c.resource_id AND c.id = (
			SELECT id FROM collection_runs
			WHERE outcome = 'queued' AND run_after <= $2 AND kind = ANY($1)
			ORDER BY run_after, id
			FOR UPDATE SKIP LOCKED
			LIMIT 1)
		RETURNING c.id, c.integration, c.kind, c.resource_id, c.attempt, r.external_id`,
		kinds, now, leaseUntil)
	if err != nil {
		return nil, err
	}
	run, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[ClaimedRun])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return run, err
}

// ErrRunNotRunning means the run was finished by someone else, for example
// after its lease expired.
var ErrRunNotRunning = errors.New("run is not running")

// FailRun marks a running attempt as failed with an error class. A failed
// attempt has no observation, so it cannot change any result. When retryAt
// is set, the next attempt is queued for that time in the same transaction
// and its id is returned.
func (s *Store) FailRun(ctx context.Context, runID int64, finishedAt time.Time, errorClass, detail string, retryAt *time.Time) (retryID int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE collection_runs
			SET outcome = 'failed', finished_at = $2, error_class = $3, error_detail = $4
			WHERE id = $1 AND outcome = 'running'`,
			runID, finishedAt, errorClass, detail)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("run %d: %w", runID, ErrRunNotRunning)
		}
		if retryAt == nil {
			return nil
		}
		return tx.QueryRow(ctx, `
			INSERT INTO collection_runs (integration, kind, resource_id, outcome, cause, queued_at, run_after, attempt, retry_of)
			SELECT integration, kind, resource_id, 'queued', 'retry', $2, $3, attempt + 1, id
			FROM collection_runs WHERE id = $1
			RETURNING id`,
			runID, finishedAt, *retryAt).Scan(&retryID)
	})
	return retryID, err
}

// NewObservation is what a successful run saw.
type NewObservation struct {
	ResourceID  int64
	Kind        string
	CollectedAt time.Time
	// SourceTimestamp is when the source says the data was produced, when
	// that differs from the time of collection.
	SourceTimestamp   *time.Time
	PayloadSHA256     string
	PayloadSize       int64
	PayloadMediaType  string
	PayloadStorageRef string
	NormalizerVersion string
}

// CompleteRun marks a running attempt as succeeded and records its
// observation, together.
func (s *Store) CompleteRun(ctx context.Context, runID int64, finishedAt time.Time, inventoryComplete bool, o NewObservation) (observationID int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		// Many observations may share one payload row.
		_, err := tx.Exec(ctx, `
			INSERT INTO evidence_payloads (sha256, size_bytes, media_type, storage_ref)
			VALUES ($1, $2, $3, $4) ON CONFLICT (sha256) DO NOTHING`,
			o.PayloadSHA256, o.PayloadSize, o.PayloadMediaType, o.PayloadStorageRef)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO observations (run_id, resource_id, kind, collected_at, source_timestamp, payload_sha256, normalizer_version)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			runID, o.ResourceID, o.Kind, o.CollectedAt, o.SourceTimestamp, o.PayloadSHA256, o.NormalizerVersion).Scan(&observationID)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			UPDATE collection_runs
			SET outcome = 'succeeded', finished_at = $2, inventory_complete = $3
			WHERE id = $1 AND outcome = 'running'`,
			runID, finishedAt, inventoryComplete)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("run %d: %w", runID, ErrRunNotRunning)
		}
		return nil
	})
	return observationID, err
}

// ExpiredRun is a running attempt whose lease has passed.
type ExpiredRun struct {
	ID      int64
	Attempt int
}

// ExpiredRuns returns the running attempts whose lease has passed: their
// worker stopped without finishing them.
func (s *Store) ExpiredRuns(ctx context.Context, now time.Time) ([]ExpiredRun, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, attempt FROM collection_runs
		WHERE outcome = 'running' AND COALESCE(lease_expires_at, started_at) < $1
		ORDER BY id`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ExpiredRun])
}

// LastQueued returns, for each job that has ever been queued, when its
// newest attempt was queued. The key is kind then resource id.
func (s *Store) LastQueued(ctx context.Context) (map[string]map[int64]time.Time, error) {
	rows, err := s.pool.Query(ctx, `SELECT kind, resource_id, max(queued_at) FROM collection_runs GROUP BY kind, resource_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[int64]time.Time{}
	for rows.Next() {
		var kind string
		var resourceID int64
		var at time.Time
		if err := rows.Scan(&kind, &resourceID, &at); err != nil {
			return nil, err
		}
		if out[kind] == nil {
			out[kind] = map[int64]time.Time{}
		}
		out[kind][resourceID] = at
	}
	return out, rows.Err()
}

// RunRow is one collection attempt.
type RunRow struct {
	ID                int64
	Integration       string
	Kind              string
	Resource          string
	Cause             string
	Attempt           int
	RetryOf           *int64
	QueuedAt          time.Time
	RunAfter          time.Time
	StartedAt         *time.Time
	FinishedAt        *time.Time
	Outcome           string
	ErrorClass        string
	ErrorDetail       string
	InventoryComplete bool
}

const runColumns = `
	c.id, c.integration, c.kind, r.external_id, c.cause, c.attempt, c.retry_of, c.queued_at, c.run_after,
	c.started_at, c.finished_at, c.outcome, c.error_class, c.error_detail, c.inventory_complete
	FROM collection_runs c JOIN resources r ON r.id = c.resource_id`

// Runs returns the most recent collection attempts, newest first.
func (s *Store) Runs(ctx context.Context, limit int) ([]RunRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT`+runColumns+` ORDER BY c.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RunRow])
}

// RunByID returns one collection attempt.
func (s *Store) RunByID(ctx context.Context, id int64) (RunRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT`+runColumns+` WHERE c.id = $1`, id)
	if err != nil {
		return RunRow{}, err
	}
	run, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[RunRow])
	return run, notFound(err)
}

// JobHealth summarises the attempts of one job: one kind of evidence
// collected from one resource.
type JobHealth struct {
	Provider string
	Resource string
	Kind     string
	// Last is the newest finished attempt.
	LastID          *int64
	LastOutcome     *string
	LastErrorClass  *string
	LastErrorDetail *string
	LastFinishedAt  *time.Time
	LastAttempt     *int
	// LastSuccessAt is when evidence was last collected, and
	// LastSuccessComplete whether that listing was read to the end.
	LastSuccessAt       *time.Time
	LastSuccessComplete *bool
	// FailuresSinceSuccess counts failed attempts since the last success.
	FailuresSinceSuccess int
	// Pending is the unfinished attempt, if there is one.
	PendingID       *int64
	PendingOutcome  *string
	PendingRunAfter *time.Time
	PendingAttempt  *int
	PendingCause    *string
}

// JobsHealth returns the health of every job that has been attempted.
func (s *Store) JobsHealth(ctx context.Context) ([]JobHealth, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.provider, r.external_id, j.kind,
		       last.id, last.outcome, last.error_class, last.error_detail, last.finished_at, last.attempt,
		       ok.finished_at, ok.inventory_complete,
		       (SELECT count(*) FROM collection_runs f
		        WHERE f.kind = j.kind AND f.resource_id = j.resource_id
		          AND f.outcome = 'failed' AND f.id > COALESCE(ok.id, 0)),
		       pend.id, pend.outcome, pend.run_after, pend.attempt, pend.cause
		FROM (SELECT DISTINCT kind, resource_id FROM collection_runs) j
		JOIN resources r ON r.id = j.resource_id
		LEFT JOIN LATERAL (
			SELECT * FROM collection_runs c
			WHERE c.kind = j.kind AND c.resource_id = j.resource_id AND c.outcome IN ('succeeded', 'failed')
			ORDER BY c.id DESC LIMIT 1) last ON true
		LEFT JOIN LATERAL (
			SELECT * FROM collection_runs c
			WHERE c.kind = j.kind AND c.resource_id = j.resource_id AND c.outcome = 'succeeded'
			ORDER BY c.id DESC LIMIT 1) ok ON true
		LEFT JOIN LATERAL (
			SELECT * FROM collection_runs c
			WHERE c.kind = j.kind AND c.resource_id = j.resource_id AND c.outcome IN ('queued', 'running')
			LIMIT 1) pend ON true
		ORDER BY r.provider, r.external_id, j.kind`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[JobHealth])
}

// ScopeRow is a resource and the scope decision made about it.
type ScopeRow struct {
	Provider    string
	Kind        string
	ExternalID  string
	Scope       string
	ScopeReason string
	DecidedBy   string
	CreatedAt   time.Time
}

// ResourcesBefore returns every resource registered before the given time.
func (s *Store) ResourcesBefore(ctx context.Context, before time.Time) ([]ScopeRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, kind, external_id, scope, scope_reason, decided_by, created_at
		FROM resources WHERE created_at < $1 ORDER BY provider, kind, external_id`, before)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ScopeRow])
}
